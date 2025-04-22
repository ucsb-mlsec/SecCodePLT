from __future__ import annotations

import logging
from datasets import load_dataset as hf_load_dataset
from pprint import pformat
import re


from virtue_code_eval.project_env import DATA_DIR
from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from virtue_code_eval.code_tasks.safety.utils import describe_cwe

logger = logging.getLogger(__name__)


class CyberSecEvalInstruct(Task):
    """A task represents an entire benchmark including its dataset, problems,
    answers, generation settings and evaluation methods.
    """

    TASK_FULL_NAME = "safety/generation/insecure_code/text_to_code/instruct"
    AVAIL_METRICS = ["bleu", "codebleu", "insecure_code_detector", "syntax_error_rate"]
    AVAIL_SUBTASKS = {
        "cwe_identifier": ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-95', 'CWE-119', 'CWE-120', 'CWE-121',
                           'CWE-185', 'CWE-200', 'CWE-208', 'CWE-209', 'CWE-242', 'CWE-276', 'CWE-290', 'CWE-295',
                           'CWE-306', 'CWE-312', 'CWE-319', 'CWE-323', 'CWE-327', 'CWE-328', 'CWE-330', 'CWE-335',
                           'CWE-338', 'CWE-345', 'CWE-347', 'CWE-352', 'CWE-377', 'CWE-416', 'CWE-502', 'CWE-521',
                           'CWE-554', 'CWE-589', 'CWE-590', 'CWE-601', 'CWE-611', 'CWE-643', 'CWE-665', 'CWE-676',
                           'CWE-680', 'CWE-759', 'CWE-770', 'CWE-798', 'CWE-807', 'CWE-862', 'CWE-908', 'CWE-918',
                           'CWE-1240'],
        "language": [
            "python", "java", "c", "csharp", "cpp", "javascript", "php", "rust",
        ],
    }  # fmt: skip
    LOCAL_DATASET_PATH = str(DATA_DIR / "safety/cyber_sec_eval/instruct/instruct.json")

    def __init__(
        self,
        subtasks: dict[str, list[str]] | None,
        metric_functions: dict[str, callable],
        num_data: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
        fewshot_num: int | None = None,
    ):
        """
        :param subtasks: dict[str, list[str]]
        :param metric_functions: dict[str, callable]
        :param num_data: int
            load the first num_data examples
        :param shuffle_data: bool
            load the examples in random order
        """
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
        dataset = hf_load_dataset("json", data_files=self.LOCAL_DATASET_PATH)["train"]
        dataset = dataset.add_column("id", range(len(dataset)))
        return dataset

    def get_prompt(self, doc):
        """Builds the prompt for the LM to generate from."""
        return doc["test_case_prompt"]

    def get_reference(self, doc):
        """Builds the reference solution for the doc (sample from the test dataset)."""

        # test_func = doc["test"]
        # entry_point = f"check({doc['entry_point']})"
        # return "\n" + test_func + "\n" + entry_point
        return doc["origin_code"]

    def get_id(self, doc):
        return doc["id"]

    def postprocess_generation(self, response, data: DataPoint):
        """Defines the postprocessing for a LM generation.
        :param response: str
            code generation from LM
        :param data: data
            index of doc in the dataset to which the generation belongs
            (not used for Humaneval-Task)
        """

        # generation = generation.split("```python\n", 1)[1]
        # generation = generation.split("\n```", 1)[0]
        pattern = re.compile(r"```(?:\w+)?\s*([\s\S]*?)```", re.DOTALL)
        code_blocks = pattern.findall(response)
        if len(code_blocks) > 0:
            response = code_blocks[0]
        return response

    @staticmethod
    def describe_subtask(subtask: dict[str, str]) -> str:
        subtask_desc = ""
        if "cwe_identifier" in subtask:
            cwe_id_str = subtask["cwe_identifier"]
            cwe_id = int(cwe_id_str.split("-")[1])
            cwe_desc = describe_cwe(cwe_id)
            subtask_desc += f"CWE-{cwe_id}: {cwe_desc}\n"

        for k, v in subtask.items():
            if k == "cwe_identifier":
                continue
            subtask_desc += f"{k}: {v}\n"
        # remove the last \n
        subtask_desc = subtask_desc[:-1]
        return subtask_desc

    @staticmethod
    def argparse_code_bleu(data: DataPoint):
        return {
            "response": data.response,
            "reference": data.reference,
            "language": data.raw_data["language"],
        }

    @staticmethod
    def argparse_bleu(data: DataPoint):
        return {
            "response": data.response,
            "reference": data.reference,
        }
