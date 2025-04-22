from __future__ import annotations

import logging
from pprint import pformat
from datasets import load_dataset as hf_load_dataset
import json

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.apps_metric.compute import (
    compute_apps_tests_impl,
)

logger = logging.getLogger(__name__)


class GeneralAPPS(Task):
    TASK_FULL_NAME = "capability/generation/difficulty"
    AVAIL_METRICS = ["unittest", "bleu"]
    AVAIL_SUBTASKS = {"difficulty": ["introductory", "interview", "competition"]}
    HF_DATASET_PATH = "codeparrot/apps"

    def __init__(
        self,
        subtasks: dict[str, list[str]],
        metric_functions: dict[str, callable],
        num_data: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
        fewshot_num: int | None = None,
    ):
        super().__init__(
            subtasks=subtasks,
            metric_functions=metric_functions,
            num_data=num_data,
            shuffle_data=shuffle_data,
            batch_size=batch_size,
            fewshot_num=fewshot_num,
        )

        logger.info(f"Evaluating {len(self.dataset)} samples")
        logger.debug(f"One example data:\n{pformat(self.dataset[0])}")

    def get_dataset(self):
        dataset = hf_load_dataset(self.HF_DATASET_PATH, split="test")
        return dataset

    def get_prompt(self, doc):
        """Generate prompts for APPS
        Finetuning setup: prompt=question  with some starter code and function name if they exist.
        We also specify the type of the prompt, i.e. whether it is call-based or standard input-based.
        """
        starter_code = None if len(doc["starter_code"]) == 0 else doc["starter_code"]
        try:
            input_outpout = json.loads(doc["input_output"])
            fn_name = (
                None if not input_outpout.get("fn_name") else input_outpout["fn_name"]
            )
        except ValueError:
            fn_name = None
        prompt = "\nQUESTION:\n"
        prompt += doc["question"]
        if starter_code:
            prompt += starter_code
        if not fn_name:
            call_format = "\nUse Standard Input format"
            prompt += call_format
        else:
            call_format = "\nUse Call-Based format"
            prompt += call_format
        prompt = prompt.split("ANSWER:", 1)[0]
        prompt += "\nANSWER:\n"
        prompt += "```python\n"
        return prompt

    def get_reference(self, doc):
        """Builds the reference solution for the doc (sample from the test dataset)."""
        if not doc["solutions"]:
            return doc["solutions"]
        return json.loads(doc["solutions"])[0]

    def get_reference_model_output(self, doc) -> str:
        reference = self.get_reference(doc)
        return reference + "\n```"

    def get_id(self, doc):
        return doc["problem_id"]

    def postprocess_generation(self, generation, prompt):
        """Defines the postprocessing for a LM generation.
        :param generation: str
            code generation from LM
        :param idx: int
            index of doc in the dataset to which the generation belongs
            (not used for APPS)
        """
        try:
            generation = generation.split("\nANSWER:", 1)[1]
        except IndexError:
            # happens when prompts were very long and got truncated
            pass
        try:
            generation = generation.split("```python\n", 1)[1]
            generation = generation.split("\n```", 1)[0]
        except IndexError:
            # happens when prompts were very long and got truncated
            pass
        # remove ```
        generation = generation.replace("```", "")
        return generation

    @staticmethod
    def compute_unittest_impl(data: DataPoint):
        return int(
            compute_apps_tests_impl(
                response=data.response,
                sample=data.raw_data,
            )
            == 1.0
        )
