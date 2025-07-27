from .customized.asr import compute_asr
from .customized.execution import Execution
from .customized.inout_prediction import compute_inout_prediction
from .customized.insecure_code_detector.api import compute_icd_score
from .customized.llm_judge import LLMJudge
from .customized.unittest import compute_unittest
from .generic.LoC import compute_LoC
from .generic.acc import compute_accuracy

# from .generic.Runtime import compute_Runtime
from .generic.bleu import compute_bleu_score
from .generic.code_bleu import compute_code_bleu
from .generic.syntax_check import compute_syntax_check
from .generic.virustotal import compute_vt_score

METRIC_REGISTRY = {
    "bleu": compute_bleu_score,
    "codebleu": compute_code_bleu,
    "llm_judge": LLMJudge,
    "virus_total": compute_vt_score,
    # "execution": Execution,
    "syntax_error_rate": compute_syntax_check,
    "insecure_code_detector": compute_icd_score,
    "unittest": compute_unittest,
    "inout_prediction": compute_inout_prediction,
    "LoC": compute_LoC,
    "Attack success(malicious)": compute_asr,
    "accuracy": compute_accuracy,
    # "Runtime": compute_Runtime,
}

# for customized metrics, you need to pass arguments
METRICS_WITH_ARGUMENTS = ["llm_judge"]
