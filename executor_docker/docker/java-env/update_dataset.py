from huggingface_hub import HfApi

api = HfApi()
api.create_repo("secmlr/SecCodePLT-Juliet", exist_ok=True)
api.upload_large_folder(
    folder_path="./dataset",
    repo_id="secmlr/SecCodePLT-Juliet",
    repo_type="dataset",
)
