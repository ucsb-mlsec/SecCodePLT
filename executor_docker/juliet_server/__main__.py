import argparse
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Security,
    UploadFile,
    status,
)
from fastapi.security import APIKeyHeader
from .server_utils import _post_process_result, submit_poc
from .types import Payload, DEFAULT_SALT

SALT = DEFAULT_SALT
LOG_DIR = Path("./logs")
API_KEY = "seccodeplt-030a0cd7-5908-4862-8ab9-91f2bfc7b56d"
API_KEY_NAME = "X-API-Key"
DOCKER_IMAGE = "seccodeplt-juliet-java"

app = FastAPI()

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
        return api_key
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


public_router = APIRouter()
private_router = APIRouter(dependencies=[Depends(get_api_key)])


@public_router.post("/submit-java-code")
def submit_java_code(
    metadata: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
):
    """Submit Java code for CWE testing"""
    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None

    # Check if this is a Java task
    if not payload.task_id.startswith("juliet-java:"):
        raise HTTPException(
            status_code=400, detail="This endpoint is only for Java tasks"
        )

    payload.data = file.file.read()
    res = submit_poc(
        payload, mode="vul", log_dir=LOG_DIR, salt=SALT, image=DOCKER_IMAGE
    )
    res = _post_process_result(res)

    # Add Java-specific information to response
    res["language"] = "java"
    res["task_type"] = "code_completion"

    return res


@public_router.post("/submit-java-patch")
def submit_java_patch(
    metadata: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
):
    """Submit complete Java file for patch testing (no template insertion)"""
    try:
        payload = Payload.model_validate_json(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata format") from None

    # Check if this is a Java task
    if not payload.task_id.startswith("juliet-java:"):
        raise HTTPException(
            status_code=400, detail="This endpoint is only for Java tasks"
        )

    payload.data = file.file.read()
    res = submit_poc(
        payload, mode="patch", log_dir=LOG_DIR, salt=SALT, image=DOCKER_IMAGE
    )
    res = _post_process_result(res)

    # Add Java-specific information to response
    res["language"] = "java"
    res["task_type"] = "patch_generation"

    return res


@public_router.get("/")
def root():
    return {
        "message": "SecCodePlt Server API",
        "version": "1.0.0",
        "endpoints": {"public": ["POST /submit-java-code", "POST /submit-java-patch"], "private": []},
    }


app.include_router(public_router)
app.include_router(private_router)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecCodePLT Server")
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host to run the server on"
    )
    parser.add_argument(
        "--port", type=int, default=8666, help="Port to run the server on"
    )
    parser.add_argument("--salt", type=str, default=SALT, help="Salt for checksum")
    parser.add_argument(
        "--log_dir", type=Path, default=LOG_DIR, help="Directory to store logs"
    )
    parser.add_argument(
        "--image",
        type=str,
        default=DOCKER_IMAGE,
        help="Docker image for Juliet Java tests",
    )

    args = parser.parse_args()
    SALT = args.salt
    LOG_DIR = args.log_dir
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    DOCKER_IMAGE = args.image

    uvicorn.run(app, host = args.host, port = args.port)
