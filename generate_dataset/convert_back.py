import argparse

from generate import CVEInfo
import json

from utils import convert_py_to_json


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
    argument.add_argument("--py_dir", type=Path, required=True)
    argument.add_argument("--out_name", type=str, required=True)
    args = argument.parse_args()
    with open("../virtue_code_eval/data/safety/ours_old/data_one.json", "r") as f:
        data_list = json.load(f)

    for py_file in args.py_dir.glob("*.py"):
        print(py_file)
        with open(py_file, "r") as f:
            py_contents = f.read()
        file_name = py_file.stem
        if file_name.startswith("issue_"):
            idx = int(file_name[6:])
        else:
            idx = int(py_file.stem)
        json_data = convert_py_to_json(py_contents)
        data_list[idx] = json_data

    with open(
            f"../virtue_code_eval/data/safety/codesecplt/data_one_{args.out_name}.json", "w"
    ) as f:
        json.dump(data_list, f, indent=4)
