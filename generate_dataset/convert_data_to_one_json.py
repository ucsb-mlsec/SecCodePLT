import os
import glob
import json
import sys

global_data_list = []
special_cwe_list = ["22", "74", "78", "352", "327", "120", "281"]


def process_json_file(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)
    if "cwe-" in file_path:
        global_data_list.append(data)
    elif "succeed_list" in file_path:
        assert isinstance(data, list)
        is_special_cwe = any([cwe in file_path for cwe in special_cwe_list])
        for item in data:
            # change CVE_ID to N/A
            if not is_special_cwe or "CVE_ID" not in item:
                item["CVE_ID"] = file_path
            global_data_list.append(item)
    else:
        # generated data without CVE_ID
        assert isinstance(data, list)
        for item in data:
            # change CVE_ID to N/A
            each_data = json.loads(item["json"])
            each_data["CVE_ID"] = file_path
            global_data_list.append(each_data)


def process_directory(directory, out_path):
    patterns = [
        "**/task_code_list.json",
        "**/succeed_list.json",
        "**/cwe-*.json",
    ]

    for pattern in patterns:
        for file_path in glob.glob(os.path.join(directory, pattern), recursive=True):
            process_json_file(file_path)
    print(f"Total data: {len(global_data_list)}")
    with open(out_path, "w") as f:
        json.dump(global_data_list, f, indent=4)


if __name__ == "__main__":
    out_path = sys.argv[1]
    root_directory = "data/"
    process_directory(root_directory, out_path)
