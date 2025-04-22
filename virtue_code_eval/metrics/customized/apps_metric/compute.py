import logging

from virtue_code_eval.code_tasks.base_task import DataPoint

from .utils import check_correctness

logger = logging.getLogger(__name__)


def default_argparse_apps_tests(data: DataPoint):
    return {
        "response": data.response,
        "sample": data.raw_data,
    }


def compute_apps_tests(data: DataPoint):
    """
    data -> named arguments
    -> compute_x_metric_impl(data)
    """
    if hasattr(data.task, "argparse_apps_tests"):
        return compute_apps_tests_impl(**data.task.argparse_apps_tests(data))
    else:
        return compute_apps_tests_impl(**default_argparse_apps_tests(data))


def compute_apps_tests_impl(
    response: str, sample: dict, timeout: int = 10, debug=False
) -> float:
    """
    Run and check the ratio of passed testcases
    """
    results, _ = check_correctness(sample, response, timeout=timeout, debug=debug)

    num_runtime_errors = sum(1 for r in results if r == -1)
    num_compile_errors = sum(1 for r in results if r == -2)
    num_passed = sum(1 for r in results if r == 1)
    num_total = len(results)

    logger.debug(f"Total testcases: {num_total}")
    logger.debug(
        f"runtime errors: {num_runtime_errors} ({num_runtime_errors / num_total:.2f})"
    )
    logger.debug(
        f"compile errors: {num_compile_errors} ({num_compile_errors / num_total:.2f})"
    )

    return num_passed / num_total
