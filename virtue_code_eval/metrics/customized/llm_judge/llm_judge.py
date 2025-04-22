import logging
import os

from virtue_code_eval.code_tasks.base_task import DataPoint
from .llm import create as create_llm
from ...error_codes import ErrorCode
from ...refusal import is_response_llm_refusal

logger = logging.getLogger(__name__)


class LLMJudge:
    def __init__(self, llm_name: str):
        api_key = os.getenv(
            "OPENAI_API_KEY"
        )  # Set your OpenAI API key as an environment variable
        assert (
            api_key is not None
        ), "Please set your OpenAI API key as an environment variable"
        self.llm = create_llm(f"{llm_name}::{api_key}")

    def __call__(self, data: DataPoint):
        """
        data -> named arguments
        -> compute_x_metric_impl(data)
        """
        try:
            if hasattr(data.task, "compute_llm_judge_impl"):
                return data.task.compute_llm_judge_impl(llm=self.llm, data=data)
            else:
                if hasattr(data.task, "argparse_llm_judge"):
                    return default_compute_llm_judge_impl(
                        llm=self.llm, **data.task.argparse_llm_judge(data)
                    )
                else:
                    raise NotImplementedError(
                        "This task does not have a compute_llm_judge_impl method or argparse_llm_judge method"
                    )
        except TimeoutError as _:
            logger.warning("llm judge failed after retries.")
            return ErrorCode.TIMEOUT_ERROR.value


# def argparse_llm_judge_template(data: DataPoint):
#     return {
#         "prompt": str,
#         "extract_score": callable
#     }


def default_compute_llm_judge_impl(llm, prompt: str, extract_score: callable) -> float:
    llm_response = llm.query_with_retries(
        prompt=prompt,
        guided_decode_json_schema=None,
    )
    # check if llm refuse to answer, if so, return -1
    # Then check if llm_response is float, if so, return llm_response
    # Otherwise, return 1
    if is_response_llm_refusal(llm_response):
        return ErrorCode.LLMJUDGE_REFUSAL.value
    else:
        return extract_score(llm_response)
