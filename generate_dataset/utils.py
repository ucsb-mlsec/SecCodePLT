import ast
import os
import shutil
import subprocess
import sys

import nltk
import numpy as np
from nltk import word_tokenize
from nltk.data import find
from tqdm import tqdm


def convert_py_to_json(code: str):
    metadata = code.split("## START METADATA ##")[1].split("## END METADATA ##")[0]
    metadata = ast.literal_eval(metadata)
    assert "CWE_ID" in metadata
    assert "task_description" in metadata

    setup_part = code.split("## START SETUP ##")[1].split("## END SETUP ##")[0]
    code_before_part = code.split("## START CODE BEFORE ##")[1].split(
        "## END CODE BEFORE ##"
    )[0]
    vulnerable_code = code.split("## START VULN CODE ##")[1].split(
        "## END VULN CODE ##"
    )[0]
    patched_code = code.split("## START PATCHED CODE ##")[1].split(
        "## END PATCHED CODE ##"
    )[0]
    code_after_part = code.split("## START CODE AFTER ##")[1].split(
        "## END CODE AFTER ##"
    )[0]
    testcases = code.split("## START TESTCASES ##")[1].split("## END TESTCASES ##")[0]
    if "## START PACKAGE ##" in code:
        install_requires = (
            code.split("## START PACKAGE ##")[1]
            .split("## END PACKAGE ##")[0]
            .strip()
            .splitlines()
        )
    else:
        install_requires = []

    metadata["ground_truth"] = {
        "code_before": code_before_part.rstrip(),
        "vulnerable_code": vulnerable_code.rstrip(),
        "patched_code": patched_code.rstrip(),
        "code_after": code_after_part.rstrip(),
    }

    metadata["unittest"] = {
        "setup": setup_part.strip(),
        "testcases": testcases.strip(),
    }
    metadata["install_requires"] = install_requires
    return metadata


def create_virtualenv(env_name):
    subprocess.check_call([sys.executable, "-m", "venv", env_name])


def install_package(env_name: str, package_name: list):
    try:
        if os.name == "nt":  # Windows
            pip_path = os.path.join(env_name, "Scripts", "pip")
        else:  # macOS/Linux
            pip_path = os.path.join(env_name, "bin", "pip")
        exec_command_list = [pip_path, "install"]
        exec_command_list.extend(package_name)
        subprocess.check_call(exec_command_list)
    except subprocess.CalledProcessError:
        print(f"Failed to install {package_name}, but continuing anyway.")


def delete_virtualenv(env_name):
    shutil.rmtree(env_name)


def openai_chat(input_data: str, client, model: str, seed: int) -> str:
    messages = [
        {
            "role": "user",
            "content": input_data,
        },
    ]
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=1,
        seed=seed,
    )

    result = response.choices[0].message.content
    return result


def anthropic_chat(input_data: str, client, model: str, seed: int) -> str:
    messages = [
        {"role": "user", "content": [{"type": "text", "text": input_data}]},
    ]
    response = client.messages.create(
        model=model,
        messages=messages,
        max_tokens=8192,
        temperature=1,
    )

    result = response.content[0].text
    return result


def distance_lcs(preds: list, refs: list):
    """
    Editing distance: calculate the editing needed to change the generated responses to reference responses
    :param preds: a list of generated responses
    :param refs: a list of reference responses with the same size as preds
    :return: normalized score
    """

    try:
        find("tokenizers/punkt")
    except LookupError:
        nltk.download("punkt", quiet=True)

    def sigmoid(x, k=5, x0=0.6):
        # want to have a large diff when x is close to 0.6
        return 1 / (1 + np.exp(-k * (x - x0)))

    # def substring_match(text1, text2):
    #     return text2 in text1
    #
    # def lcs_length(s1, s2):
    #     m, n = len(s1), len(s2)
    #     dp = np.zeros((m + 1, n + 1), dtype=int)
    #     for i in range(1, m + 1):
    #         for j in range(1, n + 1):
    #             if s1[i - 1] == s2[j - 1]:
    #                 dp[i][j] = dp[i - 1][j - 1] + 1
    #             else:
    #                 dp[i][j] = np.max([dp[i - 1][j], dp[i][j - 1]])
    #     return dp[m][n]

    def word_levenshtein_distance(words1, words2):
        """
        Edit distance between two lists of words
        """
        len1, len2 = len(words1), len(words2)
        dp = np.zeros((len1 + 1, len2 + 1), dtype=float)

        for i in range(len1 + 1):
            dp[i][0] = i
        for j in range(len2 + 1):
            dp[0][j] = j

        for i in range(1, len2 + 1):
            for j in range(1, len1 + 1):
                if words1[j - 1] == words2[i - 1]:
                    dp[j][i] = dp[j - 1][i - 1]
                else:
                    dp[j][i] = np.min(
                        [dp[j - 1][i] + 1, dp[j][i - 1] + 1, dp[j - 1][i - 1] + 1]
                    )

        # for i in range(1, len1 + 1):
        #     dp[i][len2] /= i
        if len1 < len2:
            return (dp[len1, len2]) / len2
        else:
            return (np.min(dp[len2:, len2])) / len2

    scores = []
    for pred, ref in tqdm(zip(preds, refs)):
        response_words, instruction_words = word_tokenize(pred), word_tokenize(ref)
        len_response, len_instruction = len(response_words), len(instruction_words)
        if len_response < len_instruction:
            max_score = np.log(
                1 / word_levenshtein_distance(response_words, instruction_words)
            )
        else:
            max_score = 0
            for start in range(0, len_response - len_instruction + 1):
                edit_dis = word_levenshtein_distance(
                    response_words[start : (start + len_instruction)], instruction_words
                )
                if edit_dis == 0:
                    max_score = np.inf
                    break
                else:
                    new_score = np.log(1 / edit_dis)
                    if new_score > max_score:
                        max_score = new_score
        scores.append(sigmoid(max_score))
    return scores
