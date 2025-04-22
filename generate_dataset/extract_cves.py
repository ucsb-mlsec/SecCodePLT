import argparse
import glob
import json
import os


def download(data_folder="~"):
    if os.path.exists(os.path.join(data_folder, "cvelistV5-main")):
        print("Data already exists")
        return
    # run wget
    os.system(
        f"wget -P {data_folder} https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    )
    os.system(f"unzip {data_folder}/main.zip -d {data_folder}")
    os.system(f"rm {data_folder}/main.zip")


def find_key_in_dict(data, target_key):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == target_key:
                return value
            if isinstance(value, (dict, list)):
                result = find_key_in_dict(value, target_key)
                if result is not None:
                    return result
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                result = find_key_in_dict(item, target_key)
                if result is not None:
                    return result
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data_folder", type=str, default="/scratch/yuzhou/tmp", help="Data folder"
    )
    args = parser.parse_args()
    results_path = os.path.join(args.data_folder, "cves.json")

    download(args.data_folder)

    # for data after 2019
    pattern = os.path.join(
        args.data_folder, "cvelistV5-main", "cves/20[2-9][0-9]/**/*.json"
    )
    results = {
        "cwe-798": [],
        "cwe-94": [],
        "cwe-312": [],
        "cwe-89": [],
        "cwe-328": [],
        "cwe-502": [],
        "cwe-78": [],
        "cwe-338": [],
    }
    failed_results = []
    for file_path in glob.iglob(pattern, recursive=True):
        with open(file_path, "r") as file:
            cve = json.load(file)
            cve_str = json.dumps(cve)
            if "python" in cve_str.lower() and "cwe" in cve_str.lower():
                cwe = find_key_in_dict(cve, "cweId")
                if cwe:
                    cwe = cwe.lower()
                    if cwe in results:
                        results[cwe].append(cve)
                else:
                    failed_results.append(cve)
    print(f"Found {len(results)} CVEs with Python after 2017")
    print(f"Found {len(failed_results)} CVEs with cwe but without cweId")
    for cwe_name, data in results.items():
        with open(os.path.join(args.data_folder, f"cves_{cwe_name}.json"), "w") as file:
            json.dump(data, file)
    with open(os.path.join(args.data_folder, "failed_cves.json"), "w") as file:
        json.dump(failed_results, file)
