import subprocess as sp
import os
import pickle
import logging

from virtue_code_eval.project_env import DATA_DIR

logger = logging.getLogger(__name__)


def compute_ds1000_unittest_impl(
    response: str,
    sample: dict,
):
    # https://github.com/xlang-ai/DS-1000/blob/main/test_ds1000.py
    test_program = (
        sample["code_context"]
        + "\n"
        + f"code = {repr(response)}\n"
        + "test_execution(code)\n"
        + ("test_string(code)\n" if "test_string(" in sample["code_context"] else "\n")
    )

    ds1000_python_executable = os.getenv("DS1000_PYTHON_EXECUTABLE", "python")

    timeout = 120
    kwargs = dict(
        program=test_program,
        timeout=timeout,
    )

    try:
        proc = sp.run(
            [ds1000_python_executable, DATA_DIR / "capability/ds1000/executor.py"],
            encoding=None,
            input=pickle.dumps(kwargs),
            stdout=sp.PIPE,
            timeout=timeout + 10,
        )

        result = pickle.loads(proc.stdout)
    except sp.TimeoutExpired:
        logger.warning("Timeout in running the test")
        return 0
    except Exception as e:
        logger.warning(f"Error in running the test: {e}")
        return 0

    return int(result["passed"])
