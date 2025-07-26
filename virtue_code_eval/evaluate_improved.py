from __future__ import annotations

import asyncio
import logging
import math
import os
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from typing import Any, Iterator, Union

import datasets
import hydra
import orjson
from dotenv import load_dotenv
from omegaconf import DictConfig, ListConfig, OmegaConf
from tqdm import tqdm

from virtue_code_eval import METRIC_REGISTRY, METRICS_WITH_ARGUMENTS, TASK_REGISTRY
from virtue_code_eval.code_tasks.base_task import DataPoint, Task
from virtue_code_eval.generate_failure_cases import generate_failure_cases
from virtue_code_eval.generate_table import generate_table
from virtue_code_eval.models.default_model import AsyncTogetherModel, TogetherModel
from virtue_code_eval.project_env import PACKAGE_ROOT

datasets.utils.logging.set_verbosity_warning()
datasets.utils.disable_progress_bars()

logger = logging.getLogger(__name__)


def cfg_to_container(cfg: Any):
    """A wrapper to avoid NoneType error"""
    if cfg is None:
        return None
    return OmegaConf.to_container(cfg, resolve=True)


@dataclass
class EvaluatorState:
    task: Task | None = None
    task_cfg: DictConfig | None = None
    model: Union[AsyncTogetherModel, TogetherModel] | None = None
    model_cfg: DictConfig | None = None
    data: Union[DataPoint, list[DataPoint]] | None = None


class Evaluator:
    def __init__(self, cfg: DictConfig):
        self.cfg = cfg
        self.out_dir = Path(cfg.out_dir)
        self.curr_state = EvaluatorState()
        self.save_every = cfg.get("save_every")
        self.rerun_eval = cfg.get("rerun_eval", False)

    def _get_and_init_model_out_dir(self, model_name: str) -> Path:
        """Get model output directory with safe filename"""
        model_name = model_name.replace("/", "__")
        model_out_dir = self.out_dir / "model_results" / model_name
        model_out_dir.mkdir(parents=True, exist_ok=True)
        return model_out_dir

    def _save_task_results(self, task_name: str, results: list[DataPoint], save_dir: Path):
        """Save task results to file"""
        task_name = task_name.replace("/", "__")
        results_path = save_dir / f"{task_name}.json"
        with open(results_path, "wb") as f:
            f.write(orjson.dumps(results, option=orjson.OPT_INDENT_2, default=str))
        logger.info(f"Task {task_name} results saved to {results_path}")

    def _load_task_results(self, task_name: str, save_dir: Path) -> list[DataPoint]:
        """Load existing task results"""
        task_name = task_name.replace("/", "__")
        results_path = save_dir / f"{task_name}.json"
        if not results_path.exists():
            return []
        
        with open(results_path, "rb") as f:
            raw_results = orjson.loads(f.read())
        
        results = [DataPoint(**raw_result) for raw_result in raw_results]
        logger.info(f"Task {task_name} results loaded from {results_path}: {len(results)}")
        return results

    def _init_metric_functions(self, metric_cfgs: list[str | dict]) -> dict:
        """Initialize metric functions from config"""
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
                    metric_functions[metric_name] = METRIC_REGISTRY[metric_name](**config)
                else:
                    metric_functions[metric_name] = METRIC_REGISTRY[metric_name]
        return metric_functions

    def _init_task(self, task_cfg: DictConfig) -> Task:
        """Initialize task from config"""
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

    def _get_config_iter(self, config_section: Union[DictConfig, ListConfig], config_name: str) -> Iterator:
        """Unified config iteration logic"""
        if isinstance(config_section, ListConfig):
            logger.warning(f"Old config format detected for {config_name}, please update to new format.")
            return config_section
        return config_section.values()

    @contextmanager
    def _state_context(self, **kwargs):
        """Context manager for state management"""
        old_state = {}
        for key, value in kwargs.items():
            old_state[key] = getattr(self.curr_state, key)
            setattr(self.curr_state, key, value)
        try:
            yield
        finally:
            for key, value in old_state.items():
                setattr(self.curr_state, key, value)

    async def _process_batch_async(self, model: AsyncTogetherModel, data_batch: list[DataPoint]) -> tuple[list[DataPoint], list[DataPoint]]:
        """Process a batch of data points asynchronously"""
        # Generate responses
        try:
            responses = await model([dp.messages for dp in data_batch])
            
            succeeded = []
            failed = []
            
            for response, data_point in zip(responses, data_batch):
                if response is None:
                    logger.warning(f"Model query failed for data point {data_point.id_}")
                    failed.append(data_point)
                    continue
                
                try:
                    post_response = data_point.task.postprocess_generation(response, data_point)
                    data_point.raw_response = response
                    data_point.response = post_response
                    succeeded.append(data_point)
                except Exception as e:
                    logger.error(f"Error processing response for {data_point.id_}: {e}")
                    failed.append(data_point)
            
            # Evaluate successful results
            if succeeded:
                await asyncio.gather(*[data_point.task.evaluate(data_point) for data_point in succeeded])
            
            return succeeded, failed
            
        except Exception as e:
            logger.error(f"Batch generation failed: {e}")
            return [], data_batch

    def _process_single_sync(self, model: TogetherModel, data_point: DataPoint) -> bool:
        """Process a single data point synchronously"""
        try:
            response = model(data_point.messages)
            if response is None:
                logger.warning(f"Model query failed for data point {data_point.id_}")
                return False
            
            post_response = data_point.task.postprocess_generation(response, data_point)
            data_point.raw_response = response
            data_point.response = post_response
            data_point.task.evaluate(data_point)
            return True
            
        except Exception as e:
            logger.error(f"Error processing data point {data_point.id_}: {e}")
            return False

    async def async_evaluate_task(
        self, task_cfg: DictConfig, model: AsyncTogetherModel, results_out_dir: Path
    ) -> list[DataPoint]:
        """Asynchronous task evaluation"""
        # Load existing results
        results_for_task = self._load_task_results(task_cfg.task_name, results_out_dir)
        existing_ids = {res.id_ for res in results_for_task}
        existing_id_to_result = {res.id_: res for res in results_for_task}
        
        save_task_fn = partial(
            self._save_task_results,
            task_name=task_cfg.task_name,
            save_dir=results_out_dir,
        )
        
        # Initialize task
        task = self._init_task(task_cfg)
        
        # Filter out existing data points
        if not self.rerun_eval:
            task.filter_existing_ids(existing_ids)
        
        # Update state
        with self._state_context(task=task, task_cfg=task_cfg):
            batch_size = self.cfg.get("batch_size", 1)
            total = math.ceil(len(task) / batch_size)
            cnt_unsaved_results = 0
            data_failed = []
            
            for data_batch in tqdm(
                task.batch_iter(),
                desc=f"Evaluating model [{self.curr_state.model_cfg.model_name}], task [{task_cfg.task_name}]",
                total=total,
                ncols=150,
            ):
                self.curr_state.data = data_batch
                
                # Separate existing and new data points
                data_to_generate = []
                data_succeeded = []
                
                for data_point in data_batch:
                    if data_point.id_ in existing_id_to_result:
                        res = existing_id_to_result[data_point.id_]
                        res.raw_data = data_point.raw_data
                        res.task = data_point.task
                        data_succeeded.append(res)
                    else:
                        data_to_generate.append(data_point)
                
                # Process new data points
                if data_to_generate:
                    succeeded, failed = await self._process_batch_async(model, data_to_generate)
                    data_succeeded.extend(succeeded)
                    data_failed.extend(failed)
                
                # Record results
                for data_point in data_succeeded:
                    data_point.raw_data = None  # Save space
                    if data_point.id_ not in existing_ids:
                        results_for_task.append(data_point)
                
                # Save periodically
                cnt_unsaved_results += len(data_succeeded)
                if self.save_every and cnt_unsaved_results >= self.save_every:
                    cnt_unsaved_results = 0
                    save_task_fn(results=results_for_task)
            
            # Final save
            logger.info(f"Saving {len(results_for_task)} results for task {task_cfg.task_name}")
            save_task_fn(results=results_for_task)
            
            if data_failed:
                logger.info(f"Failed to query model for {len(data_failed)} data points.")
        
        return results_for_task

    def evaluate_task(
        self, task_cfg: DictConfig, model: TogetherModel, results_out_dir: Path
    ) -> list[DataPoint]:
        """Synchronous task evaluation"""
        if self.cfg.get("batch_size", 1) > 1:
            logger.warning("Batch size > 1 is not supported for synchronous model.")
        
        # Load existing results
        results_for_task = self._load_task_results(task_cfg.task_name, results_out_dir)
        existing_ids = {data.id_ for data in results_for_task}
        
        save_task_fn = partial(
            self._save_task_results,
            task_name=task_cfg.task_name,
            save_dir=results_out_dir,
        )
        
        # Initialize task
        task = self._init_task(task_cfg)
        
        # Update state
        with self._state_context(task=task, task_cfg=task_cfg):
            cnt_unsaved_results = 0
            
            for data in tqdm(
                task,
                desc=f"{self.curr_state.model_cfg.model_name}: {task_cfg.task_name}",
            ):
                if data.id_ in existing_ids and not self.rerun_eval:
                    logger.debug(f"Skip data point {data.id_}, already evaluated.")
                    continue
                
                self.curr_state.data = data
                
                # Process data point
                if self._process_single_sync(model, data):
                    data.raw_data = None  # Save space
                    results_for_task.append(data)
                    cnt_unsaved_results += 1
                    
                    # Save periodically
                    if self.save_every and cnt_unsaved_results >= self.save_every:
                        cnt_unsaved_results = 0
                        save_task_fn(results=results_for_task)
            
            # Final save
            save_task_fn(results=results_for_task)
        
        return results_for_task

    async def evaluate_model(self, model_cfg: DictConfig) -> dict:
        """Evaluate a single model on all tasks"""
        # Initialize model
        model = AsyncTogetherModel(
            model_cfg.model_name,
            chat_config=cfg_to_container(model_cfg.get("chat_config")),
            client_config=cfg_to_container(model_cfg.get("client_config")),
        )
        model_out_dir = self._get_and_init_model_out_dir(model_cfg.model_name)
        results_for_model = {}
        
        with self._state_context(model=model, model_cfg=model_cfg):
            task_cfg_iter = self._get_config_iter(self.cfg.tasks, "tasks")
            
            for task_cfg in task_cfg_iter:
                if not task_cfg.enabled:
                    continue
                results_for_task = await self.async_evaluate_task(
                    task_cfg, model, model_out_dir
                )
                results_for_model[task_cfg.task_name] = results_for_task
        
        return results_for_model

    async def evaluate(self):
        """Main evaluation entry point"""
        results = {}
        model_cfg_iter = self._get_config_iter(self.cfg.models, "models")
        
        for model_cfg in model_cfg_iter:
            if not model_cfg.enabled:
                continue
            results_for_model = await self.evaluate_model(model_cfg)
            results[model_cfg.model_name] = results_for_model
        
        # Save results
        with open(self.out_dir / "results.json", "wb") as f:
            f.write(orjson.dumps(results, option=orjson.OPT_INDENT_2, default=str))
        logger.info(f"Evaluation finish! Results saved to {self.out_dir}")

    def summary(self):
        """Generate summary tables and failure cases"""
        generate_table(self.out_dir, self.out_dir / "results.json")
        generate_failure_cases(self.out_dir, self.out_dir / "results.json")


@hydra.main(
    version_base="1.3", config_path=str(PACKAGE_ROOT / "config"), config_name="evaluate"
)
def main(cfg: DictConfig):
    load_dotenv()
    logger.info(OmegaConf.to_yaml(cfg, resolve=True))
    logger.info(os.getcwd())
    
    evaluator = Evaluator(cfg)
    asyncio.run(evaluator.evaluate())
    evaluator.summary()


if __name__ == "__main__":
    main()