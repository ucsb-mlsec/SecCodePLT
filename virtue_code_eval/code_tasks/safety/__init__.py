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
    juliet_autocomplete
)
from .generation.ours.text_to_code.helpfulness import OursAttackHelpfulness
from .generation.tool_abuse import CyberSecEvalInterpreter
from .reasoning.exploitation import CyberSecEvalCanaryExploit

SAFETY_TASK_REGISTRY: dict[str, Type[Task]] = {
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
    "ours/code_to_code/juliet_autocomplete": juliet_autocomplete,
}
