from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pprint import pformat

from datasets import load_dataset as hf_load_dataset

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.metrics.customized.execution.live_code_bench.compute_code_generation_metrics import (
    evaluate_one_generation,
)
from virtue_code_eval.project_env import DATA_DIR

logger = logging.getLogger(__name__)


class GeneralLiveCodeBenchCodeGeneration(Task):
    TASK_FULL_NAME = "capability/generation/live_code_bench/code_generation"
    AVAIL_METRICS = ["unittest", "LoC"]
    AVAIL_SUBTASKS = {
        "difficulty": ["easy", "medium", "hard"],
        "platform": ["atcoder", "codeforces", "leetcode"],
    }
    HF_DATASET_PATH = "livecodebench/code_generation"

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
        if fewshot_num and fewshot_num > 1:
            logger.warning(
                "This task doesn't support more than 1 fewshot examples currently."
            )
        logger.info(f"Evaluating {len(self.dataset)} samples")
        logger.debug(f"One example data:\n{pformat(self.dataset[0])}")
        self.SYSTEM_MESSAGE_GENERIC = "You are an expert Python programmer. You will be given a question (problem specification) and will generate a correct Python program that matches the specification and passes all tests. You will NOT return anything except for the program."

    def get_dataset(self):
        dataset = hf_load_dataset(self.HF_DATASET_PATH, split="test")
        dataset = dataset.map(lambda x: {**x, "question": x["question_content"]})
        return dataset

    @staticmethod
    def get_example_prompt(example, starter_code: bool = True):
        prompt = ""
        prompt += "### Question\n"
        prompt += example["question"]
        prompt += "\n\n"
        if starter_code:
            prompt += "### Starter Code\n"
            prompt += example["starter_code"]
            prompt += "\n\n"
        answer = "### Answer\n\n"
        if "answer" in example:
            answer += example["answer"]
            answer += "\n\n"
        return prompt, answer

    def init_fewshot(self):
        """
        Initialize the fewshot messages
        """
        with open(
            DATA_DIR
            / "capability/live_code_bench/few_shot_examples/generation/func.json"
        ) as f:
            func = json.load(f)
        with open(
            DATA_DIR
            / "capability/live_code_bench/few_shot_examples/generation/stdin.json"
        ) as f:
            stdin = json.load(f)
        fewshot_messages = []
        # with starter code
        few_shot_prompt, reference = self.get_example_prompt(func[0], starter_code=True)
        fewshot_messages.append(
            [
                {"role": "user", "content": few_shot_prompt},
                {
                    "role": "assistant",
                    "content": reference,
                },
            ]
        )
        # without starter code
        few_shot_prompt2, reference2 = self.get_example_prompt(
            stdin[0], starter_code=False
        )
        fewshot_messages.append(
            [
                {"role": "user", "content": few_shot_prompt2},
                {
                    "role": "assistant",
                    "content": reference2,
                },
            ]
        )

        return fewshot_messages

    def get_system_prompt(self, doc) -> str | None:
        return self.SYSTEM_MESSAGE_GENERIC

    def build_messages(self, doc) -> list[dict[str, str]]:
        """Builds the messages for the chatbot to generate from.
        :param doc: dict[str: str]
            sample from the test dataset
        """
        messages = []
        system_prompt = self.get_system_prompt(doc)
        if system_prompt is not None:
            messages.append({"role": "system", "content": system_prompt})

        if self.fewshot_num:
            if doc["starter_code"]:
                messages.extend(self.fewshot_messages[0])
            else:
                messages.extend(self.fewshot_messages[1])

        messages.append({"role": "user", "content": self.get_prompt(doc)})

        return messages

    def get_prompt(self, doc):
        """Generate prompts for APPS
        Finetuning setup: prompt=question  with some starter code and function name if they exist.
        We also specify the type of the prompt, i.e. whether it is call-based or standard input-based.
        """
        starter_code = True if doc["starter_code"] else False
        prompt = self.get_example_prompt(doc, starter_code=starter_code)[0]
        return prompt

    def get_reference(self, doc):
        """Builds the reference solution for the doc (sample from the test dataset)."""
        return None

    def get_id(self, doc):
        return doc["question_id"]

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
            response = code_blocks[0]
        # check if answer is in the response
        if "### Answer" in response:
            response = response.split("### Answer", 1)[1].strip()
        return response

    @staticmethod
    def compute_unittest_impl(data: DataPoint) -> dict | float:
        # try:
        sample = get_evaluation_sample(data)
        results, duration_list = evaluate_one_generation(
            sample=sample,
            generation=[data.response],
            timeout=8,
        )
        all_test_cases = None
        output = None
        # for now, we only consider 1 generation, so this for loop only runs once
        for each_gen_result in results:
            if isinstance(each_gen_result, list):
                if not all_test_cases:
                    all_test_cases = [0] * len(each_gen_result)
                all_test_cases = [
                    (x == 1 or y == 1) for x, y in zip(all_test_cases, each_gen_result)
                ]
            else:
                output = each_gen_result
        # calculate mean duration
        duration = sum(duration_list) / len(duration_list)
        if all_test_cases:
            output = sum(all_test_cases) / len(all_test_cases)
        return {
            "unittest": output,
            "Runtime": duration,
        }

        # except Exception as e:
        #     logger.warning(f"Error in compute_execution_impl: {e}")
        #     return 0.0


class TestType(Enum):
    STDIN = "stdin"
    FUNCTIONAL = "functional"


@dataclass
class Test:
    input: str
    output: str
    testtype: TestType

    def __post_init__(self):
        self.testtype = TestType(self.testtype)


def get_evaluation_sample(data):
    import pickle
    import zlib
    import base64

    public_test_cases = json.loads(data.raw_data["public_test_cases"])  # type: ignore
    public_test_cases = [Test(**t) for t in public_test_cases]
    try:
        private_test_cases = json.loads(data.raw_data["private_test_cases"])  # type: ignore
    except Exception:
        private_test_cases = json.loads(
            pickle.loads(
                zlib.decompress(
                    base64.b64decode(
                        data.raw_data["private_test_cases"].encode("utf-8")
                    )  # type: ignore
                )
            )
        )  # type: ignore
    private_test_cases = [Test(**t) for t in private_test_cases]

    metadata = json.loads(data.raw_data["metadata"])  # type: ignore
    return {
        "input_output": json.dumps(
            {
                "inputs": [t.input for t in public_test_cases + private_test_cases],
                "outputs": [t.output for t in public_test_cases + private_test_cases],
                "fn_name": metadata.get("func_name", None),
            }
        ),
    }
