from __future__ import annotations

from pprint import pformat
from datasets import load_dataset as hf_load_dataset
import logging

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.ds1000_metric.unittest import (
    compute_ds1000_unittest_impl,
)

logger = logging.getLogger(__name__)


class GeneralDS1000(Task):
    TASK_FULL_NAME = "capability/completion/library"
    AVAIL_METRICS = ["unittest"]
    AVAIL_SUBTASKS = {
        "lib": [
            "Matplotlib",
            "Numpy",
            "Pandas",
            "Pytorch",
            "Scipy",
            "Sklearn",
            "Tensorflow",
        ]
    }
    HF_DATASET_PATH = "xlangai/DS-1000"
    # original system prompt
    # SYSTEM_PROMPT = (
    #     "Write a short code following the given format and indentation. Place the executable code between <code> "
    #     "and </code> tags, without any other non-executable things."
    # )
    SYSTEM_PROMPT = "Write a short code to solve the problem continued from the prompt, right after the last <code> tag. Do not include existing code and any other non-executable things. Please stop with </code> or # SOLUTION END."

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
        dataset = dataset.map(lambda x: {"lib": x["metadata"]["library"]})
        return dataset

    def get_prompt(self, doc):
        """
        Builds the prompt for the LM to generate from.
        :param doc: dict[str: str]
            sample from the test dataset
        :return: str | dict[str: str]
        """
        return doc["prompt"]

    def get_system_prompt(self, doc) -> str | None:
        return self.SYSTEM_PROMPT

    def get_reference(self, doc):
        """
        Builds the reference solution for the doc (sample from the test dataset).
        :param doc: dict[str: str]
            sample from the test dataset
        :return: str
        """
        return doc["reference_code"]

    def get_id(self, doc):
        return doc["metadata"]["problem_id"]

    def postprocess_generation(self, generation, reference):
        """
        Defines the postprocessing for a LM generation.
        :param generation: str
            code generation from LM
        :param idx: int (if needed)
            index of doc in the dataset to which the generation belongs
        :return: str
        """
        stop_words = ["</code>", "# SOLUTION END"]
        code = generation
        for stop_word in stop_words:
            code = code.split(stop_word)[0]

        code = code.split("</code>")[0]
        code = code.replace("```python", "")
        code = code.split("```")[0]
        code = code.split("\nEND SOLUTION")[0]
        code = code.replace("<code>", "")

        return code

    @staticmethod
    def compute_unittest_impl(data: DataPoint):
        return compute_ds1000_unittest_impl(
            data.response,
            data.raw_data,
        )
