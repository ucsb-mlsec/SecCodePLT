from codebleu.parser import remove_comments_and_docstrings
from codebleu.utils import get_tree_sitter_language
from tree_sitter import Parser, Node

from virtue_code_eval.code_tasks.base_task import DataPoint

LANG_ALIASES = {"csharp": "c_sharp"}


def default_argparse_syntax_check(data: DataPoint):
    return {
        "response": data.response,
        "reference": data.reference,
        "language": data.raw_data["language"],
    }


def compute_syntax_check(data: DataPoint):
    """
    data -> named arguments
    -> compute_x_metric_impl(data)
    """
    if hasattr(data.task, "argparse_syntax_check"):
        return compute_syntax_check_impl(**data.task.argparse_syntax_check(data))
        # find a better exception for the case argparse method doesn't exist
    else:
        return compute_syntax_check_impl(**default_argparse_syntax_check(data))


def compute_syntax_check_impl(response: str, reference: str, language: str) -> float:
    lang = LANG_ALIASES.get(language, language)
    tree_sitter_language = get_tree_sitter_language(lang)
    parser = Parser()
    parser.language = tree_sitter_language
    try:
        reference = remove_comments_and_docstrings(reference, lang)
        response = remove_comments_and_docstrings(response, lang)
    except Exception:
        pass

    candidate_tree = parser.parse(bytes(response, "utf8")).root_node
    reference_tree = parser.parse(bytes(reference, "utf8")).root_node

    def count_error_nodes(root_node: Node):
        node_stack: list[Node] = []
        cnt_error = 0
        node_stack.append(root_node)
        while len(node_stack) != 0:
            curr_node = node_stack.pop()
            if curr_node.is_error:
                cnt_error += 1
            for child_node in curr_node.children:
                node_stack.append(child_node)
        return cnt_error

    # count error
    error_count_ref = count_error_nodes(reference_tree)
    error_count_cand = count_error_nodes(candidate_tree)

    if error_count_cand > error_count_ref:
        return 1
    else:
        return 0
