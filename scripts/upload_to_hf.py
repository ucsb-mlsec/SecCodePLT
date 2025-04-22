from datasets import Dataset
import json
import argparse
from uuid import uuid4
from collections import OrderedDict


CWE_use_rule = {
    "295",
    "367",
    "732",
    "400",
    "338",
    "611",
    "22",
    "78",
    "120",
    "281",
}

# TODO: tmp workaround for error datapoints
BLACKLIST_INDICES = set(
    [72, 73, 74, 75, 76, 77, 78, 79, 80, 82, 84, 85, 87, 89, 1259] + # part of 1333
    [90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 1261, 1262, 1263, 1264, 1265, 1392] # disable 179
)  # fmt: skip


def clean_install_requires(install_requires):
    new_lst = []
    for req in install_requires:
        if "requests" in req:
            new_lst.append("requests")
            continue

        if "import " in req:
            continue
        if req in {"re", "html", "operator", "functools", "ast"}:
            continue

        new_lst.append(req)
    return new_lst


def main(raw_args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset_path",
        type=str,
        default="virtue_code_eval/data/safety/ours/data_one.json",
    )
    parser.add_argument("--hf_dataset_path", type=str, required=True)
    args = parser.parse_args(raw_args)

    with open(args.dataset_path) as f:
        data = json.load(f)

    new_data = []
    for idx, d in enumerate(data):
        d["use_rule"] = d["CWE_ID"] in CWE_use_rule
        d["id"] = uuid4().hex[:8]
        d.pop("CVE_ID")

        d["install_requires"] = clean_install_requires(d["install_requires"])

        if idx not in BLACKLIST_INDICES:
            new_data.append(d)

    new_data.sort(key=lambda x: int(x["CWE_ID"]))
    features_order = [
        "id",
        "CWE_ID",
        "task_description",
        "ground_truth",
        "unittest",
        "install_requires",
        "rule",
        "use_rule",
    ]

    new_data_dct = OrderedDict()
    for feature in features_order:
        new_data_dct[feature] = [d.get(feature) for d in new_data]

    dataset = Dataset.from_dict(new_data_dct)
    print(dataset)
    dataset.push_to_hub(
        args.hf_dataset_path,
        split="test",
    )


if __name__ == "__main__":
    main()
    # python3 scripts/upload_to_hf.py --hf_dataset_path xxx/yyy
