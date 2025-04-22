import argparse
import json
import signal
from pathlib import Path

from generate import CVEInfo, get_python_path_in_virtualenv, test_code
from utils import create_virtualenv, install_package


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException


signal.signal(signal.SIGALRM, timeout_handler)
timeout = 10
if __name__ == "__main__":
    argument = argparse.ArgumentParser()
    argument.add_argument("--cwe_ids", type=str, nargs="+", required=True)
    argument.add_argument("--template", type = Path, required = True)
    args = argument.parse_args()
    env_name = "temp_env"
    for cwe_id in args.cwe_ids:
        with open(f"data/{cwe_id}/succeed_list.json", "r") as f:
            json_data_list = json.load(f)
        # read python file
        with open(f"data/{cwe_id}/succeed_python_list.json", "r") as f:
            python_data_list = json.load(f)
        for i, (json_data, python_data) in enumerate(
            zip(json_data_list, python_data_list)
        ):
            try:
                json_result_str = json.dumps(json_data, indent = 2)
                info = CVEInfo.model_validate_json(json_result_str)
                if "rule" in json_data.keys():
                    if info.unittest.testcases.strip():
                        print(f"Testcases provided for rule in {cwe_id} {i}")
                    print("No testcases provided")
                    continue
                create_virtualenv(env_name)
                if info.install_requires:
                    install_package(env_name, info.install_requires)
                python_path = get_python_path_in_virtualenv(env_name)
                # python_path = args.python_interpreter
                # signal.alarm(timeout)
                results_vuln = test_code(
                    args.template,
                    info.unittest.setup,
                    info.ground_truth.code_before
                    + info.ground_truth.vulnerable_code
                    + info.ground_truth.code_after,
                    info.unittest.testcases,
                    info.task_description.function_name,
                    python_path,
                )
                signal.alarm(0)
                print(results_vuln)
                assert all(r == 1 for r in results_vuln["capability"])
                assert not any(r == 1 for r in results_vuln["safety"])
                # signal.alarm(timeout)
                results_patched = test_code(
                    args.template,
                    info.unittest.setup,
                    info.ground_truth.code_before
                    + info.ground_truth.patched_code
                    + info.ground_truth.code_after,
                    info.unittest.testcases,
                    info.task_description.function_name,
                    python_path,
                )
                print(results_patched)
                assert all(r == 1 for r in results_patched["capability"])
                assert all(r == 1 for r in results_patched["safety"])
            except ValueError as e:
                raise e
            except Exception as e:
                print(f"Error in testing {cwe_id} {i}")
                raise e
    print("All tests passed!")