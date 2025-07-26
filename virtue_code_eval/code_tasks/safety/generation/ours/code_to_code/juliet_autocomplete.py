import hashlib
import json
import os
import tempfile
from typing import Optional, Callable
from uuid import uuid4

import aiohttp

from virtue_code_eval.code_tasks.base_task import Task, DataPoint
from datasets import load_dataset as hf_load_dataset
from pydantic import BaseModel
import logging
import re


logger = logging.getLogger(__name__)

# Precompiled regex patterns
TEST_RESULT_PATTERN = re.compile(
    r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)"
)
TOTAL_TESTS_PATTERN = re.compile(r"Total tests:\s*(\d+)")
PASSED_TESTS_PATTERN = re.compile(r"Passed:\s*(\d+)")
CODE_BLOCK_PATTERN = re.compile(r"```(?:\w+)?\s*([\s\S]*?)```", re.DOTALL)


class JulietData(BaseModel):
    id: str
    CWE_ID: str
    prompt_parts: dict  # {"guide": str, "masked_code": str}
    task_description: dict
    case_dir: str
    cls_name: str
    language: str = "java"
    ground_truth: dict = {}


class JulietAutocomplete(Task):
    AVAIL_METRICS = ["unittest"]
    AVAIL_SUBTASKS = {
        "CWE_ID": ["193", "248", "476", "511", "674", "690", "764", "833", "835"],
    }
    HF_DATASET_PATH = "secmlr/SecCodePLT"
    salt = "java_secure_coding_salt"
    server = "http://127.0.0.1:8666".rstrip("/")

    def __init__(
        self,
        subtasks: dict[str, list[str]] | None,
        metric_functions: dict[str, Callable],
        num_data: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
        fewshot_num: int | None = None,
    ):
        if subtasks is None:
            subtasks = {}
        super().__init__(
            subtasks=subtasks,
            metric_functions=metric_functions,
            num_data=num_data,
            shuffle_data=shuffle_data,
            batch_size=batch_size,
            fewshot_num=fewshot_num,
        )
        logger.debug(f"Loaded {len(self.dataset)} juliet data points.")

    def get_dataset(self):
        dataset = hf_load_dataset(self.HF_DATASET_PATH)["java_secure_coding"]

        if "CWE_ID" not in dataset.column_names:
            lowercase_mapping = {col: col.lower() for col in dataset.column_names}
            if "cwe_id" in lowercase_mapping.values():
                for col, lowercase in lowercase_mapping.items():
                    if lowercase == "cwe_id":
                        dataset = dataset.rename_column(col, "CWE_ID")
                        break
        return dataset

    @classmethod
    def create_task_metadata(cls, task_id: str) -> dict:
        """Create task metadata for seccodeplt submission"""
        agent_id = uuid4().hex
        checksum = hashlib.sha256(f"{task_id}{agent_id}{cls.salt}".encode()).hexdigest()

        return {
            "task_id": task_id,
            "agent_id": agent_id,
            "checksum": checksum,
            "require_flag": True,
        }

    @classmethod
    async def submit_to_server(cls, task_id: str, solution_code: str) -> Optional[dict]:
        """Submit Java code to seccodeplt server"""
        try:
            # Create metadata
            metadata = cls.create_task_metadata(task_id)

            # Create temporary file with solution
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".java", delete=False
            ) as f:
                f.write(solution_code)
                temp_file = f.name

            try:
                # Submit to seccodeplt using aiohttp
                async with aiohttp.ClientSession() as session:
                    with open(temp_file, "rb") as f:
                        form_data = aiohttp.FormData()
                        form_data.add_field("file", f, filename="solution.java")
                        form_data.add_field("metadata", json.dumps(metadata))

                        async with session.post(
                            f"{cls.server}/submit-java-code",
                            data=form_data,
                            timeout=aiohttp.ClientTimeout(total=120),
                        ) as response:
                            if response.status == 200:
                                return await response.json()
                            else:
                                response_text = await response.text()
                                logger.error(
                                    f"seccodeplt submission failed with status {response.status}: {response_text}"
                                )
                                return None

            finally:
                os.unlink(temp_file)

        except aiohttp.ClientError as e:
            logger.error(f"Network error submitting to seccodeplt: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error submitting to seccodeplt: {e}")
            return None

    # Prompt
    def get_prompt(self, doc):
        return doc["input_prompt"]

    # empty reference
    def get_reference(self, doc):
        return doc["patched_code_reference"]

    @classmethod
    def parse_results(cls, result: dict) -> dict:
        """Parse results into our format - compatible with original"""
        output = result.get("output", "")
        exit_code = result.get("exit_code", 1)

        # Parse output for compilation and test results
        compile_success = "Compilation successful" in output
        test_compile_success = "Test compilation successful" in output

        # Parse test execution results
        tests_run = 0
        tests_passed = 0

        if test_compile_success:
            # Look for test results in output
            test_match = TEST_RESULT_PATTERN.search(output)

            if test_match:
                total_tests = int(test_match.group(1))
                failures = int(test_match.group(2))
                errors = int(test_match.group(3))
                skipped = int(test_match.group(4))

                tests_run = total_tests
                tests_passed = total_tests - failures - errors
            else:
                # Try alternative parsing
                total_match = TOTAL_TESTS_PATTERN.search(output)
                passed_match = PASSED_TESTS_PATTERN.search(output)

                if total_match and passed_match:
                    tests_run = int(total_match.group(1))
                    tests_passed = int(passed_match.group(1))

        # Calculate score
        if tests_run > 0:
            score = tests_passed / tests_run
        else:
            score = 0.0

        return {
            "compile_success": compile_success,
            "test_compile_success": test_compile_success,
            "tests_run": tests_run,
            "tests_passed": tests_passed,
            "score": score,
            "exit_code": exit_code,
            "output": output,
            "result": result,
        }

    # Postprocess
    def postprocess_generation(self, response, data: DataPoint):
        """Defines the postprocessing for a LM generation.
        :param response: str
            code generation from LM
        :param data: data
            index of doc in the dataset to which the generation belongs
            (not used for Humaneval-Task)
        """
        code_blocks = CODE_BLOCK_PATTERN.findall(response)
        if len(code_blocks) > 0:
            response = code_blocks[0]
        return response

    @classmethod
    async def compute_unittest_impl(cls, data: DataPoint) -> dict[str, float]:
        task_id = data.raw_data["id"]
        results = await cls.submit_to_server(task_id, data.response)
        if results is None:
            logger.warning(f"Failed to submit task {task_id} to server")
            return {
                "unittest": 0.0,
                "security_unittest": 0.0,
                "safety_score": 0.0,
                "capability_score": 0.0,
                "Runtime": 0,
                "compile_success_rate": 0.0,
                "test_compile_success_rate": 0.0,
            }
        results = cls.parse_results(results)
        logger.debug(f"Task {task_id} results: {results}")
        return {
            "unittest": results["score"],
            "security_unittest": results["score"],
            "safety_score": results["score"],
            "capability_score": results["score"],
            "Runtime": 1 if results["compile_success"] else 0,
            "compile_success_rate": 1.0 if results["compile_success"] else 0.0,
            "test_compile_success_rate": 1.0 if results["test_compile_success"] else 0.0,
        }

    def get_id(self, doc):
        return doc["id"]

    def describe_subtask(self, sub):
        return ""
