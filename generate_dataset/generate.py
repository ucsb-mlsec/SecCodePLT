import json
import ast
import os
import signal
import sys
from pathlib import Path
import argparse
import tempfile
import subprocess as sp
from pydantic import BaseModel, Field
import pickle

from utils import install_package, create_virtualenv


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException


signal.signal(signal.SIGALRM, timeout_handler)
timeout = 10


def get_python_path_in_virtualenv(env_name):
    if os.name == "nt":  # Windows
        python_path = os.path.join(env_name, "Scripts", "python")
    else:  # macOS/Linux
        python_path = os.path.join(env_name, "bin", "python")
    return python_path


class TaskDescription(BaseModel):
    function_name: str
    description: str
    security_policy: str
    context: str
    arguments: str
    return_: str = Field(alias="return")
    raise_: str = Field(alias="raise")


class GroundTruth(BaseModel):
    code_before: str
    vulnerable_code: str
    patched_code: str
    code_after: str


class Unittest(BaseModel):
    setup: str
    testcases: str


class CVEInfo(BaseModel):
    CWE_ID: str
    CVE_ID: str = ""
    task_description: TaskDescription
    ground_truth: GroundTruth
    unittest: Unittest
    install_requires: list[str]
    rule: str = ""


def convert_py_to_json_dump(info_py: Path, output_json: Path):
    with open(info_py, "r") as f:
        code = f.read()

    metadata = code.split("## START METADATA ##")[1].split("## END METADATA ##")[0]
    metadata = ast.literal_eval(metadata)
    assert "task_description" in metadata
    assert "CWE_ID" in metadata
    cwe_id = metadata["CWE_ID"]
    if cwe_id.startswith("CWE-"):
        metadata["CWE_ID"] = cwe_id[4:]

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
    try:
        install_requires = (
            code.split("## START PACKAGE ##")[1]
            .split("## END PACKAGE ##")[0]
            .strip()
            .splitlines()
        )
    except IndexError:
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
    with open(output_json, "w") as f:
        json.dump(metadata, f, indent=2)


def generate_test_code(
    template_path: Path,
    setup_part: str,
    code_part: str,
    testcases_part: str,
    func_name: str,
):
    with open(template_path, "r") as f:
        template = f.read()
    code = template
    setup_pos = template.find("## START SETUP ##\n")
    code = code[:setup_pos] + setup_part + code[setup_pos:]
    code_pos = code.find("## START CODE ##\n")
    code = code[:code_pos] + code_part + code[code_pos:]
    testcases_pos = code.find("## START TESTCASES ##\n")
    code = code[:testcases_pos] + testcases_part + code[testcases_pos:]
    rename_pos = code.find("## START RENAME FUNCTION ##\n")
    code = code[:rename_pos] + f"__func = {func_name}\n" + code[rename_pos:]

    return code


def test_code(
    template_path: Path,
    setup_part: str,
    code_part: str,
    testcases_part: str,
    func_name: str,
    python_interpreter: str,
):
    code = generate_test_code(
        template_path,
        setup_part,
        code_part,
        testcases_part,
        func_name,
    )
    results = None
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fp:
        fp.write(code)
        fp.flush()
        with tempfile.NamedTemporaryFile(
            "w", suffix=".pickle", delete=False
        ) as fp_results:
            ret = sp.run(
                [python_interpreter, fp.name],
                env={"UNITTEST_RESULTS_PATH": fp_results.name},
            )
            if ret.returncode != 0:
                print("Test failed")
            else:
                with open(fp_results.name, "rb") as f:
                    results = pickle.load(f)
            os.remove(fp_results.name)
        os.remove(fp.name)

    return results


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--full_code", type=Path, required=True)
    parser.add_argument("--output_json", type=Path, required=True)
    parser.add_argument("--python_interpreter", type=str, default=sys.executable)
    parser.add_argument("--skip_test", action="store_true")

    args = parser.parse_args()
    env_name = "temp_env"
    convert_py_to_json_dump(args.full_code, args.output_json)
    # get the package name

    ## test the generated code
    with open(args.output_json, "r") as f:
        info = CVEInfo.model_validate_json(f.read())
    
    if args.skip_test:
        return
    if info.unittest.testcases.strip() == "":
        print("No testcases provided")
        return
    try:
        create_virtualenv(env_name)
        if info.install_requires:
            install_package(env_name, info.install_requires)
        python_path = get_python_path_in_virtualenv(env_name)
        # python_path = args.python_interpreter
        results_vuln = test_code(
            args.template,
            info.unittest.setup,
            info.ground_truth.code_before
            + info.ground_truth.vulnerable_code
            + info.ground_truth.code_after,
            info.unittest.testcases,
            info.task_description.function_name,
            # args.python_interpreter,
            python_path,
        )
        signal.alarm(0)
        print(results_vuln)
        assert all(r == 1 for r in results_vuln["capability"])
        assert not any(r == 1 for r in results_vuln["safety"])
        signal.alarm(timeout)
        results_patched = test_code(
            args.template,
            info.unittest.setup,
            info.ground_truth.code_before
            + info.ground_truth.patched_code
            + info.ground_truth.code_after,
            info.unittest.testcases,
            info.task_description.function_name,
            args.python_interpreter,
        )
        print(results_patched)
        assert all(r == 1 for r in results_patched["capability"])
        assert all(r == 1 for r in results_patched["safety"])
    finally:
        # delete_virtualenv(env_name)
        pass


if __name__ == "__main__":
    main()
    # python3 generate.py --template cve_test_template.py --full_code cve_2024_39903.py --output_json cve_2024_39903.json
