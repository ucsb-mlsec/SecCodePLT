from __future__ import annotations

import logging
from pprint import pformat

from datasets import load_dataset as hf_load_dataset

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.execution.live_code_bench.input_generation import (
    check_testcase_input,
)

logger = logging.getLogger(__name__)


def make_direct_input_prompt(code, output):
    return f"""You will be given a function f and an output in the form f(??) == output. Find any input such that executing f on the input leads to the given output. There may be multiple answers, but you should only output one. In [ANSWER] and [/ANSWER] tags, complete the assertion with one such input that will produce the output when executing the function.

[PYTHON]
def f(my_list):
    count = 0
    for i in my_list:
        if len(i) % 2 == 0:
            count += 1
    return count
assert f(??) == 3
[/PYTHON]
[ANSWER]
assert f(["mq", "px", "zy"]) == 3
[/ANSWER]

[PYTHON]
def f(s1, s2):
    return s1 + s2
assert f(??) == "banana"
[/PYTHON]
[ANSWER]
assert f("ba", "nana") == "banana"
[/ANSWER]

[PYTHON]
{code}
assert f(??) == {output}
[/PYTHON]
[ANSWER]
"""


class GeneralCruxIntputGeneration(Task):
    TASK_FULL_NAME = "capability/generation/cruxeval/input_generation"
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
        # delete id=sample_258
        dataset = dataset.filter(lambda x: x["id"] != "sample_258")
        return dataset

    def get_prompt(self, doc):
        return make_direct_input_prompt(doc["code"], doc["output"])

    def get_reference(self, doc):
        """Builds the reference solution for the doc (sample from the test dataset)."""
        return doc["input"]

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
            global_result = check_testcase_input(extracted_generation, data.reference)
            idx_results.append(global_result)
        # results = idx_results
        #
        # results = {
        #     result_idx: results[result_idx] for result_idx in range(len(results))
        # }

        # metrics = compute_metrics_from_results(results, k_list=None)

        # return [metrics, results]
        return idx_results[0]
