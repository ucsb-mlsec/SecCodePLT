import json
import logging

logger = logging.getLogger(__name__)


def parse_assert_statement(statement):
    import ast

    """
    Parse a Python assert statement and extract the expected input
    from the left side of the '==' operator as a string.

    :param statement: A string containing the assert statement.
    :return: The expected input from the assert statement as a string.
    """
    try:
        parsed = ast.parse(statement, mode="exec")
    except SyntaxError:
        return "Invalid syntax"

    if len(parsed.body) == 0:
        return "Empty statement"

    if not isinstance(parsed.body[0], ast.Assert):
        return "Not an assert statement"

    comparison = parsed.body[0].test

    if not isinstance(comparison, ast.Compare) or not isinstance(
        comparison.ops[0], ast.Eq
    ):
        return "Not an equality assertion"

    if not isinstance(comparison.left, ast.Call):
        return "Left side is not a function call"

    # Extract and return the function call's arguments as a string
    function_call = comparison.left
    args = [ast.get_source_segment(statement, arg) for arg in function_call.args]
    # Extract and return the left side of the '==' operator as a string
    return ", ".join(args)


def check_each_line(line: str, expected_output: str) -> bool:
    if "assert" in line:
        line = str(parse_assert_statement(line))
    else:
        line = line
    try:
        expected_output_eval = eval(expected_output)
    except NameError as e:
        if "true" in expected_output or "false" in expected_output:
            expected_output_eval = json.loads(expected_output)
        else:
            raise f"{e} This should not happen"
    except SyntaxError as e:
        logger.debug("Failed to eval expected testcase output", expected_output)
        if expected_output == "":
            expected_output_eval = ""
        else:
            raise f"{e} This should not happen"
    try:
        testcase_output_eval = eval(line)
    except SyntaxError as e:
        if line == "":
            testcase_output_eval = ""
        else:
            logger.debug(e)
            return False
    except Exception as e:
        logger.debug(e)
        return False
        # print("Failed to eval testcase output", testcase_output_str)
        # breakpoint()

    return testcase_output_eval == expected_output_eval


def check_testcase_input(testcase_str, expected_output) -> float:
    if len(testcase_str.splitlines()) > 1:
        for line in testcase_str.splitlines():
            if line.startswith("#"):
                continue
            line = line.strip()
            if check_each_line(line, expected_output):
                return 1
    else:
        testcase_str = testcase_str.strip()
        if check_each_line(testcase_str, expected_output):
            return 1

    return 0
