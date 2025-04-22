from typing import Type

from virtue_code_eval.code_tasks.base_task import Task

from .generation.apps import GeneralAPPS
from .completion.ds1000 import GeneralDS1000
from .generation.livecodebench_codegeneration import GeneralLiveCodeBenchCodeGeneration
from .reasoning.crux_input_generation import GeneralCruxIntputGeneration
from .reasoning.crux_output_generation import GeneralCruxOuputGeneration
from .reasoning.livecodebench_output_generation import GeneralLiveCodeBenchOutputGeneration
from .completion.safim import GeneralSAFIM

CAPABILITY_TASK_REGISTRY: dict[str, Type[Task]] = {
    "capability/generation/difficulty": GeneralAPPS,
    "capability/generation/live_code_bench/code_generation": GeneralLiveCodeBenchCodeGeneration,
    "capability/generation/live_code_bench/output_generation": GeneralLiveCodeBenchOutputGeneration,
    "capability/generation/cruxeval/input_generation": GeneralCruxIntputGeneration,
    "capability/generation/cruxeval/output_generation": GeneralCruxOuputGeneration,
    "capability/completion/library": GeneralDS1000,
    "capability/completion/FIM": GeneralSAFIM,
}
