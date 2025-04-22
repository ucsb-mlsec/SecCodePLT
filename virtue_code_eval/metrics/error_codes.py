import enum


class ErrorCode(enum.Enum):
    NOERROR = 0
    LLMJUDGE_REFUSAL = -1
    RESPONSE_REFUSAL = -2
    TIMEOUT_ERROR = -3
    COMPILATION_ERROR = -4
    RUNTIME_ERROR = -5
    UNKNOWN_ERROR = -6
    TESTCASE_TIMEOUT_ERROR = -7
