from __future__ import annotations

from datasets import load_dataset as hf_load_dataset
from datasets import concatenate_datasets
import logging
from pprint import pformat
import json
from typing import Literal

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.safim_unittest import compute_safim_tests_impl

from .prompt_utils import (
    extract_code_from_chat_model,
    truncate_for_fewshot,
    truncate_line_until_block,
    truncate_control,
    truncate_api_call,
    add_instruct_with_fewshot,
    get_infilling_parts,
)

logger = logging.getLogger(__name__)


class GeneralSAFIM(Task):
    TASK_FULL_NAME = "capability/completion/FIM"
    AVAIL_METRICS = ["unittest"]
    AVAIL_SUBTASKS = {
        "completion_type": [
            "api",
            "block",
            "control",
            "block_v2",
        ],  # NOTE: "api" has no unittest
        "lang": ["cpp", "csharp", "java", "python"],
    }
    HF_DATASET_PATH = "gonglinyuan/safim"

    def __init__(
        self,
        subtasks: dict[str, list[str]],
        metric_functions: dict[str, callable],
        num_data: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
        fewshot_num: int | None = None,
        prompt_mode: Literal["1S", "SPM"] = "1S",
    ):
        """
        prompt_mode: The mode of the prompt, definitions are from the SAFIM repo:
        - infilling: Prefix-Suffix-Middle (PSM)
        - reverse_infilling: Suffix-Prefix-Middle (SPM)
        - left_to_right: Left-to-Right (L2R)
        - prefix_feeding: Instructed Prefix Feeding (IPF)
        - fewshot: One-Shot (1S)
        """
        assert prompt_mode in ["1S", "SPM"], f"Unsupported prompt mode: {prompt_mode}"
        self.prompt_mode = prompt_mode
        if fewshot_num:
            raise ValueError(
                "Few-shot learning is not supported for this task, SAFIM currently requires 1-shot to format the output correctly."
            )
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
        all_datasets = []
        name_map = {"block_v2": "block"}
        for name in self.AVAIL_SUBTASKS["completion_type"]:
            dataset = hf_load_dataset(self.HF_DATASET_PATH, name=name, split="test")
            # filter by language
            dataset = dataset.filter(lambda x: x["lang"] in self.AVAIL_SUBTASKS["lang"])
            # add a field for the task name
            dataset = dataset.map(
                lambda x: {"completion_type": name_map.get(name, name)}
            )
            all_datasets.append(dataset)

        dataset = concatenate_datasets(all_datasets)
        dataset = dataset.map(lambda x: {"unit_tests": json.loads(x["unit_tests"])})
        return dataset

    def get_id(self, doc):
        return doc["task_id"]

    def get_prompt(self, sample):
        if self.prompt_mode == "1S":
            return add_instruct_with_fewshot(sample, sample["completion_type"])
        
        if self.prompt_mode == "SPM":
            prefix, suffix = get_infilling_parts(sample)
            return f"{suffix}\n\n{prefix}"
            
        return sample["prompt"]

    def get_reference(self, doc):
        return self.get_solution(doc)

    def get_reference_model_output(self, doc):
        solution = self.get_solution(doc)
        return solution

    def get_solution(self, doc):
        return doc["ground_truth"]

    def postprocess_generation(self, generation, data: DataPoint):
        generation = extract_code_from_chat_model(
            generation, data.raw_data["lang"], data.raw_data["completion_type"]
        )
        generation = truncate_for_fewshot(generation)

        if data.subtask["completion_type"] in ["block", "block_v2"]:
            generation = truncate_line_until_block(data.raw_data, generation)
        elif data.subtask["completion_type"] == "control":
            generation = truncate_control(data.raw_data, generation)
        elif data.subtask["completion_type"] == "api":
            generation = truncate_api_call(generation)
        return generation

    @staticmethod
    def compute_unittest_impl(data: DataPoint):
        return int(
            compute_safim_tests_impl(
                response=data.response,
                sample=data.raw_data,
            )
            == 1.0
        )
