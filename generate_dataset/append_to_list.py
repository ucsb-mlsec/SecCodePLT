import json

from generate import CVEInfo
from utils import convert_py_to_json

if __name__ == "__main__":
    with open("test.py", "r") as f:
        code = f.read()
    with open("data/347/succeed_list.json", "r") as f:
        succeed_list = json.load(f)
    with open("data/347/succeed_python_list.json", "r") as f:
        succeed_python_list = json.load(f)
    json_result = convert_py_to_json(code)
    json_result_str = json.dumps(json_result, indent = 2)
    info = CVEInfo.model_validate_json(json_result_str)
    succeed_list.append(json_result)
    succeed_python_list.append(code)

    with open("data/347/succeed_list.json", "w") as f:
        json.dump(succeed_list, f)
    with open("data/347/succeed_python_list.json", "w") as f:
        json.dump(succeed_python_list, f)
