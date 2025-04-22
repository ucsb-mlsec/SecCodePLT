from __future__ import annotations

import logging
import math
import os
from pathlib import Path
import datasets
import hydra
from dotenv import load_dotenv
from omegaconf import OmegaConf, DictConfig, ListConfig
import orjson
from tqdm import tqdm
from functools import partial
from dataclasses import dataclass
from typing import Any

from virtue_code_eval import METRIC_REGISTRY, TASK_REGISTRY, METRICS_WITH_ARGUMENTS
from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.generate_failure_cases import generate_failure_cases
from virtue_code_eval.generate_table import generate_table
from virtue_code_eval.project_env import PACKAGE_ROOT
from virtue_code_eval.models.default_model import TogetherModel, AsyncTogetherModel

datasets.utils.logging.set_verbosity_warning()
datasets.utils.disable_progress_bars()

logger = logging.getLogger(__name__)


def cfg_to_container(cfg: Any):
    # A wrapper to avoid NoneType error
    if cfg is None:
        return None
    else:
        return OmegaConf.to_container(cfg, resolve=True)


@dataclass
class EvaluatorState:
    task: Task | None = None
    task_cfg: DictConfig | None = None
    model: AsyncTogetherModel | None = None
    model_cfg: DictConfig | None = None
    data: list[DataPoint] | None = None


class Evaluator:
    def __init__(self, cfg: DictConfig):
        self.cfg = cfg
        self.out_dir = Path(cfg.out_dir)
        self.curr_state = EvaluatorState()

        self.save_every = cfg.get("save_every")
        self.rerun_eval = cfg.get("rerun_eval", False)

    def _get_and_init_model_out_dir(self, model_name: str) -> Path:
        # rename to avoid invalid filenames
        model_name = model_name.replace("/", "__")
        model_out_dir = self.out_dir / "model_results" / model_name
        if not model_out_dir.exists():
            model_out_dir.mkdir(parents=True)
        return model_out_dir

    def _save_task_results(
        self, task_name: str, results: list[DataPoint], save_dir: Path
    ):
        # rename to avoid invalid filenames
        task_name = task_name.replace("/", "__")
        results_path = save_dir / f"{task_name}.json"
        with open(results_path, "wb") as f:
            f.write(orjson.dumps(results, option=orjson.OPT_INDENT_2, default=str))
        logger.info(f"Task {task_name} results saved to {results_path}")

    def _load_task_results(self, task_name: str, save_dir: Path) -> list[DataPoint]:
        task_name = task_name.replace("/", "__")
        results_path = save_dir / f"{task_name}.json"
        if not results_path.exists():
            return []
        with open(results_path, "rb") as f:
            raw_results = orjson.loads(f.read())
        results = []
        for raw_result in raw_results:
            data = DataPoint(**raw_result)
            results.append(data)
        logger.info(
            f"Task {task_name} results loaded from {results_path}: {len(results)}"
        )
        return results

    def _run_model(self, model_chat_fn: callable, data: DataPoint):
        # need to support multi-cycle generation
        # need to support n_sample>1
        # TODO: how to handle failure of model
        response = model_chat_fn(data.messages)
        if response is None:
            return
        post_response = data.task.postprocess_generation(response, data)
        data.raw_response = response
        data.response = post_response

    def _async_run_model(self, model_chat_fn: callable, data: list[DataPoint]):
        # need to support multi-cycle generation
        # need to support n_sample>1
        # TODO: how to handle failure of model
        responses = model_chat_fn([data_point.messages for data_point in data])
        for response, data_point in zip(responses, data):
            if response is None:
                continue
            post_response = data_point.task.postprocess_generation(response, data_point)
            data_point.raw_response = response
            data_point.response = post_response

    def _init_metric_functions(self, metric_cfgs: list[str | dict]):
        metric_functions = {}
        for metric_cfg in metric_cfgs:
            if isinstance(metric_cfg, str):
                if metric_cfg in METRICS_WITH_ARGUMENTS:
                    raise ValueError(
                        f"Metric {metric_cfg} is a customized metric and you need to pass arguments."
                    )
                metric_functions[metric_cfg] = METRIC_REGISTRY[metric_cfg]
            else:
                metric_name = metric_cfg["metric_name"]
                config = metric_cfg.get("config", {})
                if metric_name in METRICS_WITH_ARGUMENTS:
                    metric_functions[metric_name] = METRIC_REGISTRY[metric_name](
                        **config
                    )
                else:
                    metric_functions[metric_name] = METRIC_REGISTRY[metric_name]
        return metric_functions

    def _init_task(self, task_cfg: DictConfig) -> Task:
        metric_functions = self._init_metric_functions(task_cfg.metrics)
        extra_kwargs = {}
        if "extra_kwargs" in task_cfg:
            extra_kwargs = OmegaConf.to_container(task_cfg.extra_kwargs, resolve=True)
        task = TASK_REGISTRY[task_cfg.task_name](
            subtasks=task_cfg.get("subtasks"),
            metric_functions=metric_functions,
            num_data=task_cfg.get("num_data"),
            shuffle_data=task_cfg.get("shuffle_data", False),
            batch_size=self.cfg.get("batch_size", 1),
            fewshot_num=task_cfg.get("fewshot_num"),
            **extra_kwargs,
        )
        return task

    def async_evaluate_task(
        self, task_cfg: DictConfig, model: AsyncTogetherModel, results_out_dir: Path
    ):
        # init task
        results_for_task = self._load_task_results(task_cfg.task_name, results_out_dir)
        cnt_unsaved_results = 0
        existing_ids: set = {res.id_ for res in results_for_task}
        existing_id_to_result = {res.id_: res for res in results_for_task}
        save_task_fn = partial(
            self._save_task_results,
            task_name=task_cfg.task_name,
            save_dir=results_out_dir,
        )

        metric_functions = self._init_metric_functions(task_cfg.metrics)

        batch_size = self.cfg.get("batch_size", 1)

        task: Task = TASK_REGISTRY[task_cfg.task_name](
            subtasks=task_cfg.get("subtasks"),
            metric_functions=metric_functions,
            num_data=task_cfg.get("num_data"),
            shuffle_data=task_cfg.get("shuffle_data", False),
            batch_size=batch_size,
            fewshot_num=task_cfg.get("fewshot_num"),
            **OmegaConf.to_container(task_cfg.extra_kwargs, resolve=True)
            if "extra_kwargs" in task_cfg
            else {},
        )
        # filter out existing data points
        if not self.rerun_eval:
            task.filter_existing_ids(existing_ids)
        # update state
        self.curr_state.task = task
        self.curr_state.task_cfg = task_cfg

        # support batch queries now
        total = math.ceil(len(task) / batch_size)
        data_failed = []
        for data in tqdm(
            task.batch_iter(),
            desc=f"Evaluating model [{self.curr_state.model_cfg.model_name}], task [{task_cfg.task_name}]",
            total=total,
            ncols=150,
        ):
            self.curr_state.data = data
            data_to_generate = []
            data_succeeded = []
            for data_point in data:
                if data_point.id_ in existing_id_to_result:
                    res = existing_id_to_result[data_point.id_]
                    res.raw_data = data_point.raw_data
                    res.task = data_point.task
                    data_succeeded.append(res)
                else:
                    data_to_generate.append(data_point)
            # generate
            self._async_run_model(model, data_to_generate)
            for data_point in data_to_generate:
                if data_point.response is None:
                    logger.warning(
                        f"Model query failed for data point {data_point.id_}, skip this data point."
                    )
                    data_failed.append(data_point)
                else:
                    data_succeeded.append(data_point)

            # evaluate
            for data_point in data_succeeded:
                task.evaluate(data_point)
                # ignore raw_data to save space
                data_point.raw_data = None
                if data_point.id_ not in existing_ids:
                    results_for_task.append(data_point)
            # record
            cnt_unsaved_results += len(data_succeeded)
            if self.save_every and cnt_unsaved_results >= self.save_every:
                cnt_unsaved_results = 0
                save_task_fn(results=results_for_task)
        logger.info(
            f"Saving {len(results_for_task)} results for task {task_cfg.task_name}"
        )
        save_task_fn(results=results_for_task)

        if data_failed:
            logger.info(f"Failed to query model for {len(data_failed)} data points.")

        # clear state
        self.curr_state.data = None
        self.curr_state.task = None
        self.curr_state.task_cfg = None

        return results_for_task

    def evaluate_task(
        self, task_cfg: DictConfig, model: TogetherModel, results_out_dir: Path
    ):
        # warning for batch size
        if task_cfg.get("batch_size", 1) > 1:
            logger.warning("Batch size > 1 is not supported for synchronous model.")
        # init task
        results_for_task = self._load_task_results(task_cfg.task_name, results_out_dir)
        existing_ids = {data.id_ for data in results_for_task}
        save_task_fn = partial(
            self._save_task_results,
            task_name=task_cfg.task_name,
            save_dir=results_out_dir,
        )

        metric_functions = self._init_metric_functions(task_cfg.metrics)

        task: Task = TASK_REGISTRY[task_cfg.task_name](
            subtasks=task_cfg.get("subtasks", None),
            metric_functions=metric_functions,
            num_data=task_cfg.get("num_data"),
            shuffle_data=task_cfg.get("shuffle_data", False),
            fewshot_num=task_cfg.get("fewshot_num"),
        )

        # update state
        self.curr_state.task = task
        self.curr_state.task_cfg = task_cfg

        # run for each data point
        # TODO: batch queries
        for data in tqdm(
            task,
            desc=f"{self.curr_state.model_cfg.model_name}: {task_cfg.task_name}",
        ):
            if data.id_ in existing_ids:
                logger.debug(f"Skip data point {data.id_}, already evaluated.")
                continue

            self.curr_state.data = data

            # generate
            self._run_model(model, data)
            if data.response is None:
                logger.warning(
                    f"Model query failed for data point {data.id_}, skip this data point."
                )
                continue
            # evaluate
            task.evaluate(data)
            # record
            # ignore raw_data to save space
            data.raw_data = None
            results_for_task.append(data)
            if self.save_every and len(results_for_task) % self.save_every == 0:
                save_task_fn(results=results_for_task)
        save_task_fn(results=results_for_task)

        # clear state
        self.curr_state.data = None
        self.curr_state.task = None
        self.curr_state.task_cfg = None

        return results_for_task

    def evaluate_model(self, model_cfg: DictConfig):
        # init model
        model = AsyncTogetherModel(
            model_cfg.model_name,
            chat_config=cfg_to_container(model_cfg.get("chat_config")),
            client_config=cfg_to_container(model_cfg.get("client_config")),
        )
        model_out_dir = self._get_and_init_model_out_dir(model_cfg.model_name)
        results_for_model = {}

        self.curr_state.model = model
        self.curr_state.model_cfg = model_cfg

        if isinstance(self.cfg.tasks, ListConfig):
            logger.warning("Old config format detected, please update to new format.")
            task_cfg_iter = self.cfg.tasks
        else:
            task_cfg_iter = self.cfg.tasks.values()
        for task_cfg in task_cfg_iter:
            if not task_cfg.enabled:
                continue
            results_for_task = self.async_evaluate_task(
                task_cfg, model, model_out_dir
            )
            results_for_model[task_cfg.task_name] = results_for_task

        self.curr_state.model = None
        self.curr_state.model_cfg = None

        return results_for_model

    def evaluate(self):
        results = {}
        if isinstance(self.cfg.models, ListConfig):
            logger.warning("Old config format detected, please update to new format.")
            model_cfg_iter = self.cfg.models
        else:
            model_cfg_iter = self.cfg.models.values()
        for model_cfg in model_cfg_iter:
            if not model_cfg.enabled:
                continue
            results_for_model = self.evaluate_model(model_cfg)
            results[model_cfg.model_name] = results_for_model

        # save results
        with open(self.out_dir / "results.json", "wb") as f:
            f.write(orjson.dumps(results, option=orjson.OPT_INDENT_2, default=str))
        logger.info(f"Evaluation finish! Results saved to {self.out_dir}")

    def summary(self):
        generate_table(self.out_dir, self.out_dir / "results.json")
        generate_failure_cases(self.out_dir, self.out_dir / "results.json")


@hydra.main(
    version_base="1.3", config_path=str(PACKAGE_ROOT / "config"), config_name="evaluate"
)
def main(cfg: DictConfig):
    # use dotenv to load environment variables
    load_dotenv()
    # print config
    logger.info(OmegaConf.to_yaml(cfg, resolve=True))
    logger.info(os.getcwd())

    evaluator = Evaluator(cfg)
    evaluator.evaluate()
    evaluator.summary()


if __name__ == "__main__":
    main()
