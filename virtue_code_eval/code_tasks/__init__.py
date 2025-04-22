from .capability import CAPABILITY_TASK_REGISTRY
from .safety import SAFETY_TASK_REGISTRY
from .base_task import TaskRegistry, Task, DataPoint as DataPoint


_TASK_REGISTRY: dict[str, type[Task]] = {
    **CAPABILITY_TASK_REGISTRY,
    **SAFETY_TASK_REGISTRY,
}

TASK_REGISTRY = TaskRegistry(_TASK_REGISTRY)
