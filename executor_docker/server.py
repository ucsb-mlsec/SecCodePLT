from __future__ import annotations

import os
import pickle
import subprocess as sp
import sys
import time
import tempfile
from pathlib import Path

import fastapi
import uvicorn
from pydantic import BaseModel, Field


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
) -> None | TestCodeOutput:
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
            tic = time.perf_counter()
            ret = sp.run(
                [python_interpreter, fp.name],
                env={"UNITTEST_RESULTS_PATH": fp_results.name},
            )
            runtime = time.perf_counter() - tic
            if ret.returncode != 0:
                print("Test failed")
            else:
                with open(fp_results.name, "rb") as f:
                    results = pickle.load(f)
                results["runtime"] = runtime
            os.remove(fp_results.name)
        os.remove(fp.name)
    return TestCodeOutput.model_validate(results)


app = fastapi.FastAPI()


class TestCodeParams(BaseModel):
    setup: str
    code: str
    testcases: str
    func_name: str
    install_requires: list[str]


class TestCodeOutput(BaseModel):
    capability: list[int]
    safety: list[int]
    runtime: float


@app.post("/run_testcases")
async def run_testcases(data: TestCodeParams) -> None | TestCodeOutput:
    # install required packages
    if data.install_requires:
        sp.call(["/root/venv/bin/pip", "install", *data.install_requires])

    try:
        results = test_code(
            Path("/root/code_template.py"),
            data.setup,
            data.code,
            data.testcases,
            data.func_name,
            "/root/venv/bin/python",
        )
    except Exception as e:
        return None

    return results


if __name__ == "__main__":
    # run app on port 5000
    port = int(os.getenv("EXECUTOR_PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
