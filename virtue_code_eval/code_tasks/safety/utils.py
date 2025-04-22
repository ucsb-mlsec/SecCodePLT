import pandas as pd
import logging

from virtue_code_eval.project_env import DATA_DIR

logger = logging.getLogger(__name__)

cwe_descriptions = None


def _init_cwe_descriptions():
    global cwe_descriptions
    cwe_df = pd.read_csv(DATA_DIR / "safety/cwe-details.csv")
    cwe_descriptions = {}
    for _, row in cwe_df.iterrows():
        cwe_descriptions[row["CWE-ID"]] = row["Name"]


def describe_cwe(cwe_id: int) -> str:
    """
    Describe the CWE with the given ID.

    Args:
        cwe_id: The ID of the CWE to describe.

    Returns:
        A string containing the description of the CWE.
    
    Example:
    input: 120
    output: 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)'
    """
    if cwe_descriptions is None:
        _init_cwe_descriptions()

    return cwe_descriptions.get(cwe_id, "Unknown CWE")
