import logging

from virtue_code_eval.code_tasks.base_task import DataPoint

logger = logging.getLogger(__name__)


def compute_asr(data: DataPoint):
    if hasattr(data.task, "compute_asr_impl"):
        return data.task.compute_asr_impl(data=data)

    logger.warning("This task does not have a compute_asr_impl method")
    return 0
