from generate import CVEInfo
import json

def json_to_py(obj: dict) -> str:
    cve_info = CVEInfo.model_validate(obj)
    task_desc = cve_info.task_description.model_dump()
    # change return_ to return
    task_desc["return"] = task_desc.pop("return_")
    task_desc["raise"] = task_desc.pop("raise_")

    metadata = {"CVE_ID": cve_info.CVE_ID, "CWE_ID": cve_info.CWE_ID,"task_description": task_desc}
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
    import sys
    import json
    from pathlib import Path

    in_file = Path(sys.argv[1])
    out_file = Path(sys.argv[2])
    with open(in_file, "r") as f:
        objs = json.load(f)
    if isinstance(objs, dict):
        py_contents = json_to_py(objs)
        with open(out_file, "w") as f:
            f.write(py_contents)
    else:
        py_contents = [json_to_py(obj) for obj in objs]

        with open(out_file, "w") as f:
            f.write(json.dumps(py_contents, indent=2))
