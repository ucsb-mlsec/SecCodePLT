import ast
import re
import os
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, Union
import requests
import warnings
import logging

from virtue_code_eval.code_tasks.base_task import DataPoint
from virtue_code_eval.code_tasks.capability.completion.safim.ast_utils import (
    get_parser,
    ErrorCheckVisitor,
)

warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)


class ExecOutcome(Enum):
    PASSED = "PASSED"  # code executes and output matches expected output
    WRONG_ANSWER = (
        "WRONG_ANSWER"  # code executes and output does NOT matches expected output
    )
    TIME_LIMIT_EXCEEDED = "TIME_LIMIT_EXCEEDED"  # code executes and didn't exit in time, output is ignored in this case
    RUNTIME_ERROR = "RUNTIME_ERROR"  # code failed to execute (crashed)
    COMPILATION_ERROR = "COMPILATION_ERROR"  # code failed to compile
    MEMORY_LIMIT_EXCEEDED = (
        "MEMORY_LIMIT_EXCEEDED"  # code exceeded memory limit during execution
    )


@dataclass
class ExtendedUnittest:
    input: str
    output: List[str] = field(default_factory=list)
    result: Optional[str] = None
    exec_outcome: Optional[ExecOutcome] = None

    def json(self):
        _json = self.__dict__
        if self.exec_outcome is not None:
            _json["exec_outcome"] = self.exec_outcome.name

        return _json

    @classmethod
    def from_json(cls, _json):
        return cls(
            input=_json.get("input", ""),
            output=_json.get("output", list()),
            result=_json.get("result", None),
            exec_outcome=_json.get("exec_outcome", None),
        )


class APICommunication:
    _session: requests.Session

    def __init__(self, server_url: str = "http://localhost:5000"):
        self._session = requests.Session()
        self.execute_code_url = f"{server_url}/api/execute_code"
        self.get_runtimes_url = f"{server_url}/api/all_runtimes"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._session.close()

    def get_runtimes(self):
        return self._session.get(self.get_runtimes_url).json()

    def execute_code(
        self,
        language: str,
        source_code: str,
        unittests: List[dict],
        limits: Optional[dict] = None,
        block_network: bool = True,
        stop_on_first_fail: bool = True,
        use_sanitizer: bool = False,
        compiler_program_name: Optional[str] = None,
        compiler_flags: Optional[str] = None,
        interpreter_cmd: Optional[str] = None,
        interpreter_flags: Optional[str] = None,
        sample_id: Optional[int] = None,
        task_id: Union[str, int, None] = None,
    ) -> Tuple[List[ExtendedUnittest], Optional[int], Union[str, int, None]]:
        if language is None:
            raise ValueError("EmptyLanguage")

        if source_code is None:
            raise ValueError("EmptySourceCode")

        if unittests is None or len(unittests) == 0:
            raise ValueError("EmptyUnittest")

        request_body = dict(
            language=language,
            source_code=source_code,
            unittests=unittests,
            limits=limits if isinstance(limits, dict) else None,
            compile_cmd=compiler_program_name,
            compile_flags=compiler_flags,
            execute_cmd=interpreter_cmd,
            execute_flags=interpreter_flags,
            block_network=block_network,
            stop_on_first_fail=stop_on_first_fail,
            use_sanitizer=use_sanitizer,
        )
        try:
            json_response = self._session.post(
                self.execute_code_url,
                json=request_body,
                headers={"Content-Type": "application/json"},
            ).json()
        except requests.exceptions.JSONDecodeError:
            json_response = {
                "task_id": task_id,
                "data": [
                    {"exec_outcome": "COMPILATION_ERROR", "result": "", "passed": False}
                ],
            }

        if "data" not in json_response:
            return json_response, sample_id, task_id

        return (
            json_response["data"],
            sample_id,
            task_id,
        )


LANG_TO_COMPILER = {
    "cpp": "GNU C++17",
    "csharp": "Mono C#",
    "java": "Java 17",
    "python": "PyPy 3",
}

execeval: APICommunication | None = None


def run_test(problem, completion):
    global execeval
    code = problem["eval_prompt"].replace("{{completion}}", completion)
    result = execeval.execute_code(
        language=LANG_TO_COMPILER[problem["lang"]],
        source_code=code,
        unittests=problem["unit_tests"],
        task_id=problem["task_id"],
    )[0]
    if not (isinstance(result, list) and isinstance(result[0], dict)):
        print(result)
        return "COMPILATION_ERROR", False
    for o in result:
        if o["result"] is not None and len(o["result"]) > 1000:
            o["result"] = o["result"][:1000]
    return result, sum(o["exec_outcome"] == "PASSED" for o in result) / len(result)


def build_execeval():
    global execeval
    if execeval is None:
        port = os.getenv("EXECEVAL_PORT")
        if not port:  # empty or None
            raise ValueError("EXECEVAL_PORT not set")
        execeval = APICommunication(server_url=f"http://localhost:{port}")


def check_syntax(code):
    parser = get_parser("python")
    code_bytes = code.encode("utf-8")
    tree = parser.parse(code_bytes)
    error_check = ErrorCheckVisitor()
    error_check(tree)
    return error_check.error_cnt == 0


def get_function_call_params(node):
    positional_args = [ast.dump(arg) for arg in node.args]
    keyword_args = {kw.arg: ast.dump(kw.value) for kw in node.keywords}
    return positional_args, keyword_args


def function_calls_match(call1, call2):
    params1 = get_function_call_params(call1)
    params2 = get_function_call_params(call2)
    return params1 == params2


def syntax_match(code1, code2, lang):
    code1 = re.sub(r"\s+", "", code1).strip()
    code2 = re.sub(r"\s+", "", code2).strip()
    if lang == "python":
        try:
            tree1 = ast.parse(code1, mode="eval")
            tree2 = ast.parse(code2, mode="eval")

            if isinstance(tree1.body, ast.Call) and isinstance(tree2.body, ast.Call):
                return function_calls_match(tree1.body, tree2.body)
        except Exception:
            pass  # If parsing fails, fall back to simple string comparison

    return code1 == code2


def compute_safim_tests_impl(response: str, sample: dict):
    build_execeval()

    results = []
    failures = []
    passed = 0  # change to passed ratio, 1 if all passed, 0 if none passed or error

    if "unit_tests" in sample and sample["unit_tests"]:
        if response == sample["ground_truth"]:
            result = "PASSED"
            passed = 1
        else:
            result, passed = run_test(sample, response)
    else:
        if syntax_match(response, sample["ground_truth"], sample["lang"]):
            result = "EXACT_MATCH"
            passed = 1
        else:
            result = "WRONG_ANSWER"
            passed = 0
    if not response.strip() and not passed:
        result = "EMPTY"
    if not passed:
        full_code = sample["eval_prompt"].replace("{{completion}}", response)
        if "unit_tests" in sample and not check_syntax(full_code):
            result = "COMPILATION_ERROR"
        failures.append(
            json.dumps({"inputs": "None", "output": "None", "expected": "None"})
        )

    results.append(
        {
            "task_id": sample["task_id"],
            "result": result,
            "passed": passed,
            "check_result": 0,
        }
    )
    return passed
