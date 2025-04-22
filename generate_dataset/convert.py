import argparse
import os

from generate import CVEInfo
import json


def json_to_py(obj: dict) -> str:
    cve_info = CVEInfo.model_validate(obj)
    task_desc = cve_info.task_description.model_dump()
    # change return_ to return
    task_desc["return"] = task_desc.pop("return_")
    task_desc["raise"] = task_desc.pop("raise_")

    metadata = {
        "CVE_ID": cve_info.CVE_ID,
        "CWE_ID": cve_info.CWE_ID,
        "task_description": task_desc,
    }
    if "rule" in obj.keys():
        metadata["rule"] = obj["rule"]
    meatadata_str = json.dumps(metadata, indent=4)
    install_requires_str = "\n".join(cve_info.install_requires)
    py_str = """\
## START METADATA ##
{}
## END METADATA ##
## START PACKAGE ##
{}
## END PACKAGE ##
## START SETUP ##
{}
## END SETUP ##
## START CODE BEFORE ##
{}
## END CODE BEFORE ##
## START VULN CODE ##
{}
## END VULN CODE ##
## START PATCHED CODE ##
{}
## END PATCHED CODE ##
## START CODE AFTER ##
{}
## END CODE AFTER ##
## START TESTCASES ##
{}
## END TESTCASES ##
""".format(
        meatadata_str,
        install_requires_str,
        cve_info.unittest.setup.lstrip("\n"),
        cve_info.ground_truth.code_before.lstrip("\n"),
        cve_info.ground_truth.vulnerable_code.lstrip("\n"),
        cve_info.ground_truth.patched_code.lstrip("\n"),
        cve_info.ground_truth.code_after.lstrip("\n"),
        cve_info.unittest.testcases.lstrip("\n"),
    )
    return py_str


if __name__ == "__main__":
    import json
    from pathlib import Path

    argument = argparse.ArgumentParser()
    argument.add_argument("--cwe_id", type=str, required=True)
    argument.add_argument("--out_dir", type=Path, required=True)
    argument.add_argument("--results_file", type=Path, required=True)
    argument.add_argument("--data_file", type=Path, required=True)
    args = argument.parse_args()

    index_set = set()
    with open(args.data_file, "r") as f:
        data_list = json.load(f)
    with open(args.results_file, "r") as f:
        response_list = json.load(f)
    os.makedirs(args.out_dir, exist_ok=True)
    for result in response_list["chatgpt-4o-latest"]["ours/code_to_code/autocomplete"]:
        if args.cwe_id == result["subtask"]["CWE_ID"]:
            prefix = ""
            idx = int(result["id_"])
            index_set.add(idx)
            data = data_list[idx]
            py_contents = json_to_py(data)

            unittest = result["metrics"]["unittest"]
            if isinstance(unittest, dict) and unittest:
                if unittest["unittest"] == 1 and unittest["security_unittest"] < 1:
                    prefix = "issue_"
            with open(args.out_dir / f"{prefix}{idx}.py", "w") as f:
                f.write(py_contents)
                f.write("\n")
                f.write("## START RESPONSE ##\n")
                f.write(result["response"])
                f.write("\n## END RESPONSE ##\n")
                f.write("\n")
                f.write("Security unittest scores: ")
                f.write(str(unittest))

    for i, data in enumerate(data_list):
        if args.cwe_id == data["CWE_ID"]:
            if i not in index_set:
                py_contents = json_to_py(data)
                with open(args.out_dir / f"{i}.py", "w") as f:
                    f.write(py_contents)