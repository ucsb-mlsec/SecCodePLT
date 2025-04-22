from __future__ import annotations

import logging
from pprint import pformat

from datasets import load_dataset as hf_load_dataset

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.execution.live_code_bench.output_generation import (
    check_testcase_output,
)

logger = logging.getLogger(__name__)


def make_direct_output_prompt(code, inputs):
    return f"""You are given a Python function and an assertion containing an input to the function. Complete the assertion with a literal (no unsimplified expressions, no function calls) containing the output when executing the provided code on the given input, even if the function is incorrect or incomplete. Do NOT output any extra information. Provide the full assertion with the correct output in [ANSWER] and [/ANSWER] tags, following the examples.

[PYTHON]
def f(n):
    return n
assert f(17) == ??
[/PYTHON]
[ANSWER]
assert f(17) == 17
[/ANSWER]

[PYTHON]
def f(s):
    return s + "a"
assert f("x9j") == ??
[/PYTHON]
[ANSWER]
assert f("x9j") == "x9ja"
[/ANSWER]

[PYTHON]
{code}
assert f({inputs}) == ??
[/PYTHON]
[ANSWER]
"""


class GeneralCruxOuputGeneration(Task):
    TASK_FULL_NAME = "capability/generation/cruxeval/output_generation"
    AVAIL_METRICS = ["inout_prediction"]
    AVAIL_SUBTASKS = {}
    HF_DATASET_PATH = "cruxeval-org/cruxeval"

    def __init__(
        self,
        subtasks: dict[str, list[str]],
        metric_functions: dict[str, callable],
        num_data: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
        fewshot_num: int | None = None,
    ):
        assert fewshot_num is None, "This task has its own fewshot implementation."
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
        return make_direct_output_prompt(doc["code"], doc["input"])

    def get_reference(self, doc):
        """Builds the reference solution for the doc (sample from the test dataset)."""
        return doc["output"]

    def get_id(self, doc):
        return doc["id"]

    def postprocess_generation(self, response, data: DataPoint):
        """Defines the postprocessing for a LM generation.
        :param response: str
            code generation from LM
        :param data: DataPoint
            index of doc in the dataset to which the generation belongs
            (not used for APPS)
        """
        # extract the code block from the response
        import re

        # if [ANSWER] and [/ANSWER] both exist
        pattern = re.compile(r"\[ANSWER](.*?)\[/ANSWER]", re.DOTALL)
        code_blocks = pattern.findall(response)
        if len(code_blocks) > 0:
            response = "\n".join(code_blocks)
        else:
            # check if only [/ANSWER] exists
            pattern = re.compile(r"(.*?)\[/ANSWER]", re.DOTALL)
            code_blocks = pattern.findall(response)
            if len(code_blocks) > 0:
                response = "\n".join(code_blocks)
            else:
                # check if only [ANSWER] exists
                pattern = re.compile(r"\[ANSWER](.*?)", re.DOTALL)
                code_blocks = pattern.findall(response)
                if len(code_blocks) > 0:
                    response = "\n".join(code_blocks)
        return response.strip()

    @staticmethod
    def compute_inout_prediction_impl(data: DataPoint) -> float:
        idx_results = []
        extracted_generation_list = [data.response]
        for extracted_generation in extracted_generation_list:
            global_result = check_testcase_output(extracted_generation, data.reference)
            idx_results.append(global_result)
        # results = idx_results
        #
        # results = {
        #     result_idx: results[result_idx] for result_idx in range(len(results))
        # }

        # metrics = compute_metrics_from_results(results, k_list=None)

        # return [metrics, results]
        return idx_results[0]
