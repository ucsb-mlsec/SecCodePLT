from hashlib import sha256

from pydantic import BaseModel

DEFAULT_SALT= "java_secure_coding_salt"

def verify_task(
    task_id: str, agent_id: str, checksum: str, salt: str = DEFAULT_SALT
) -> bool:
    """
    Verify the task by checking if the task_id, agent_id, and checksum are valid.
    """
    # Generate the expected checksum
    expected_checksum = sha256(f"{task_id}{agent_id}{salt}".encode()).hexdigest()

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
