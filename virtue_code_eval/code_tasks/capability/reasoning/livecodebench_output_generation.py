from __future__ import annotations

import json
import logging
from pprint import pformat

from datasets import load_dataset as hf_load_dataset

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.execution.live_code_bench.output_generation import (
    check_testcase_output,
)

logger = logging.getLogger(__name__)


class GeneralLiveCodeBenchOutputGeneration(Task):
    TASK_FULL_NAME = "capability/generation/live_code_bench/output_generation"
    AVAIL_METRICS = ["inout_prediction"]
    AVAIL_SUBTASKS = {
        "difficulty": ["easy", "medium", "hard"],
    }
    HF_DATASET_PATH = "livecodebench/test_generation"

    def __init__(
        self,
        subtasks: dict[str, list[str]],
        metric_functions: dict[str, callable],
        num_data: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
        fewshot_num: int | None = None,
    ):
        assert fewshot_num is None, "This task doesn't support fewshot examples."
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
        self.SYSTEM_MESSAGE_CHAT_GENERIC = "You are a helpful programming assistant and an expert Python programmer.\
 You are helping a user to write a test case to help to check the correctness of the function.\
 The user has written a input for the testcase.\
 You will calculate the output of the testcase and\
 write the whole assertion statement in the markdown code block with the correct output."

    def get_dataset(self):
        dataset = hf_load_dataset(self.HF_DATASET_PATH, split="test")
        dataset = dataset.map(lambda x: {**x, "question": x["question_content"]})
        dataset = dataset.map(lambda x: {**x, "test": json.loads(x["test"])})
        return dataset

    @staticmethod
    def parse_function_name_from_starter_code(starter_code):
        """
        starter_code : str
        """
        import ast

        tree = ast.parse(starter_code)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                assert fn is None
                fn = node.name
        return fn

    @staticmethod
    def format_testcase_func_name_input(function_name, testcase):
        """
        use the form of "assert func_name(input) == "
        """
        # TODO should there be a space after the == ?
        input_str = ", ".join(testcase.split("\n"))
        return f"assert {function_name}({input_str}) == # TODO"

    def get_generic_question_template_test_completion(
        self, sample, testcase_input: str
    ):
        prompt = f"Problem:\n{sample['question_content']}"
        prompt += f"Function:\n```\n{sample['starter_code']}\n```\n"

        # parse function name from starter_code
        func_name = self.parse_function_name_from_starter_code(sample["starter_code"])
        prompt += "Please complete the following test case:\n\n"
        prompt += f"```\n{self.format_testcase_func_name_input(func_name, testcase_input)}\n```\n"

        return prompt

    def get_system_prompt(self, doc) -> str | None:
        return self.SYSTEM_MESSAGE_CHAT_GENERIC

    def build_messages(self, doc) -> list[dict[str, str]]:
        """Builds the messages for the chatbot to generate from.
        :param doc: dict[str: str]
            sample from the test dataset
        """
        messages = []
        system_prompt = self.get_system_prompt(doc)
        if system_prompt is not None:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": self.get_prompt(doc)})

        return messages

    def get_prompt(self, doc):
        """Generate prompts for APPS
        Finetuning setup: prompt=question  with some starter code and function name if they exist.
        We also specify the type of the prompt, i.e. whether it is call-based or standard input-based.
        """
        prompt = self.get_generic_question_template_test_completion(
            doc, testcase_input=doc["test"][0]["input"]
        )
        return prompt

    def get_reference(self, doc):
        """Builds the reference solution for the doc (sample from the test dataset)."""
        return doc["test"][0]["output"]

    def get_id(self, doc):
        return doc["question_id"] + "_" + str(doc["test_id"])

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

        pattern = re.compile(r"```(?:\w+)?\s*([\s\S]*?)```", re.DOTALL)
        code_blocks = pattern.findall(response)
        if len(code_blocks) > 0:
            response = "\n".join(code_blocks)
        # check if answer is still in the response
        if "### Answer" in response:
            response = response.split("### Answer", 1)[1].strip()
        return response

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
