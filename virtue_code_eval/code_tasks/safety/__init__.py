from typing import Type

from virtue_code_eval.code_tasks.base_task import Task

from .generation.insecure_code import CyberSecEvalAutocomplete, CyberSecEvalInstruct
from .generation.malicious_code import (
    CyberSecEvalAutonomousUplift,
    CyberSecEvalMitre,
    RedcodeGen,
)
from .generation.ours import (
    OursAutocomplete,
    OursArvoAutocomplete,
    OursAutocompleteCursor,
    OursInstruct,
    OursInstructCursor,
    JulietAutocomplete
)
from .generation.ours.text_to_code.helpfulness import OursAttackHelpfulness
from .generation.tool_abuse import CyberSecEvalInterpreter
from .reasoning.exploitation import CyberSecEvalCanaryExploit


def _auto_register_tasks() -> dict[str, Type[Task]]:
    """Automatically register all Task subclasses using their TASK_FULL_NAME"""
    registry = {}
    
    # Get all imported classes in the current module
    import sys
    current_module = sys.modules[__name__]
    
    for name in dir(current_module):
        obj = getattr(current_module, name)
        # Check if it's a Task subclass (but not the base Task class itself)
        if (isinstance(obj, type) and 
            issubclass(obj, Task) and 
            obj is not Task and
            hasattr(obj, 'TASK_FULL_NAME')):
            registry[obj.TASK_FULL_NAME] = obj
    
    return registry


# Manual registry for tasks that need specific names (keeping legacy compatibility)
_MANUAL_REGISTRY: dict[str, Type[Task]] = {
    "insecure_coding/code_to_code": CyberSecEvalAutocomplete,
    "insecure_coding/text_to_code": CyberSecEvalInstruct,
    "malicious_coding/text_to_code/mitre": CyberSecEvalMitre,
    "malicious_coding/text_to_code/redcode_gen": RedcodeGen,
    "malicious_coding/text_to_code/autonomous_uplift": CyberSecEvalAutonomousUplift,
    "reasoning/exploitation": CyberSecEvalCanaryExploit,
    "tool_abuse/text_to_code": CyberSecEvalInterpreter,
    "ours/code_to_code/autocomplete": OursAutocomplete,
    "ours/code_to_code/arvo_autocomplete": OursArvoAutocomplete,
    "ours/code_to_code/autocomplete_cursor": OursAutocompleteCursor,
    "ours/text_to_code/instruct": OursInstruct,
    "ours/text_to_code/helpfulness": OursAttackHelpfulness,
    "ours/text_to_code/instruct_cursor": OursInstructCursor,
}

# Combine manual and auto-registered tasks
SAFETY_TASK_REGISTRY: dict[str, Type[Task]] = {
    **_MANUAL_REGISTRY,
    **_auto_register_tasks()
}
