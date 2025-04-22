from virtue_code_eval.code_tasks.base_task import DataPoint


def compute_LoC(data: DataPoint):
    """
    data: DataPoint
    """
    return data.response.count("\n") + 1
