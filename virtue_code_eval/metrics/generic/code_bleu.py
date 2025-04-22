from codebleu import calc_codebleu

from virtue_code_eval.code_tasks.base_task import DataPoint

AVAILABLE_LANGS = [
    "java",
    "javascript",
    "c_sharp",
    "php",
    "c",
    "cpp",
    "python",
    "go",
    "ruby",
    "rust",
]  # keywords available

LANG_ALIASES = {"csharp": "c_sharp"}


def default_argparse_code_bleu(data: DataPoint):
    return {
        "response": data.response,
        "reference": data.reference,
        "language": data.raw_data["language"],
    }


def compute_code_bleu(data: DataPoint):
    """
    data -> named arguments
    -> compute_x_metric_impl(data)
    """
    if hasattr(data.task, "argparse_code_bleu"):
        return compute_code_bleu_impl(**data.task.argparse_code_bleu(data))
    else:
        return compute_code_bleu_impl(**default_argparse_code_bleu(data))


def compute_code_bleu_impl(response: str, reference: str, language: str) -> float:
    weights = (0.25, 0.25, 0.25, 0.25)
    lang = LANG_ALIASES.get(language, language)
    return calc_codebleu(
        references=[[reference]],
        predictions=[response],
        lang=lang,
        weights=weights,
    )["codebleu"]
