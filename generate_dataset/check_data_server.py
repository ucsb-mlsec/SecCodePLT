import argparse
import json
from pathlib import Path

import httpx
from pydantic import BaseModel, Field


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


class TestCodeParams(BaseModel):
    setup: str
    code: str
    testcases: str
    func_name: str
    install_requires: list[str]


if __name__ == "__main__":
    argument = argparse.ArgumentParser()
    argument.add_argument("--data_path", type=Path, required=True)
    argument.add_argument("--cwe_ids", type=str, nargs="+", required=False)
    args = argument.parse_args()
    with open(args.data_path) as f:
        data_list = json.load(f)
    cwe_ids = set(args.cwe_ids) if args.cwe_ids else None
    failed_ids = []
    for idx, data in enumerate(data_list):
        data = CVEInfo.model_validate(data)
        if cwe_ids and data.CWE_ID not in cwe_ids:
            continue
        if not data.unittest.testcases.strip():
            continue

        params = TestCodeParams(
            setup=data.unittest.setup,
            code=data.ground_truth.code_before
            + data.ground_truth.vulnerable_code
            + data.ground_truth.code_after,
            testcases=data.unittest.testcases,
            func_name=data.task_description.function_name,
            install_requires=data.install_requires,
        )
        results_vuln = None
        results_patched = None
        try:
            results_vuln = httpx.post(
                "http://localhost:48565/run_testcases",
                json=params.model_dump(),
                timeout=30,
            ).json()

            params.code = (
                data.ground_truth.code_before
                + data.ground_truth.patched_code
                + data.ground_truth.code_after
            )

            results_patched = httpx.post(
                "http://localhost:48565/run_testcases",
                json=params.model_dump(),
                timeout=30,
            ).json()

            assert all(r == 1 for r in results_vuln["capability"])
            assert not any(r == 1 for r in results_vuln["safety"])
            assert all(r == 1 for r in results_patched["capability"])
            assert all(r == 1 for r in results_patched["safety"])
        except Exception as e:
            failed_ids.append(idx)
            print(f"Error in testing {data.CVE_ID}: {e}")
            print(results_vuln)
            print(results_patched)
    
    print(f"Failed indices: {failed_ids}")
