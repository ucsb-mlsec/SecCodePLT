from hashlib import sha256

from pydantic import BaseModel

DEFAULT_SALT = "seccodeplt"


def verify_task(
    task_id: str, agent_id: str, checksum: str, salt: str = DEFAULT_SALT
) -> bool:
    """
    Verify the task by checking if the task_id, agent_id, and checksum are valid.
    """
    # Generate the expected checksum
    input_string = f"{task_id}{agent_id}{salt}"
    expected_checksum = sha256(input_string.encode()).hexdigest()
    
    # Debug information
    print(f"[DEBUG] verify_task:")
    print(f"  task_id: {task_id}")
    print(f"  agent_id: {agent_id}")
    print(f"  salt: {salt}")
    print(f"  input_string: {input_string}")
    print(f"  expected_checksum: {expected_checksum}")
    print(f"  received_checksum: {checksum}")
    print(f"  match: {expected_checksum == checksum}")

    return expected_checksum == checksum


class Payload(BaseModel):
    task_id: str  # task_type:id, e.g., "arvo:1234"
    agent_id: str  # unique agent ID
    checksum: str  # checksum for verifying the task_id and agent_id
    data: bytes | None = None  # bytes
    require_flag: bool = False  # whether to require a flag or not


class PocQuery(BaseModel):
    agent_id: str | None = None
    task_id: str | None = None


class VerifyPocs(BaseModel):
    agent_id: str
