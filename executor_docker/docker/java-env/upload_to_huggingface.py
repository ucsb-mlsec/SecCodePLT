#!/usr/bin/env python3

import json
from datasets import Dataset

def upload_to_huggingface(
    json_file: str = "juliet_java_dataset.json",
    repo_id: str = "secmlr/SecCodePLT", 
    split_name: str = "java_secure_coding",
    private: bool = False
):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    hf_dataset = Dataset.from_list(data)
    hf_dataset.push_to_hub(repo_id=repo_id, split=split_name, private=private)

def main():
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-file", default="juliet_java_dataset.json")
    parser.add_argument("--repo-id", default="secmlr/SecCodePLT")
    parser.add_argument("--split", default="java_secure_coding")
    parser.add_argument("--private", action="store_true")
    
    args = parser.parse_args()
    
    upload_to_huggingface(
        json_file=args.json_file,
        repo_id=args.repo_id,
        split_name=args.split,
        private=args.private
    )

if __name__ == "__main__":
    main() 