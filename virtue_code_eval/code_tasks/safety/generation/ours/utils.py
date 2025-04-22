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


class CWEData(BaseModel):
    CWE_ID: str
    CVE_ID: str = ""
    task_description: TaskDescription
    ground_truth: GroundTruth
    unittest: Unittest
    install_requires: list[str]
    rule: str = ""


class TestCodeParams(BaseModel):
    setup: str
    code: str
    testcases: str
    func_name: str
    install_requires: list[str]


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
    map(str, 
    [72, 73, 74, 75, 76, 77, 78, 79, 80, 82, 84, 85, 87, 89, 1259] + # part of 1333
    [90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 1261, 1262, 1263, 1264, 1265, 1392] # disable 179
    )
)  # fmt: skip
