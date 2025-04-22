from virtue_code_eval.code_tasks.base_task import DataPoint


class Execution:
    AVAIL_METHODS = ["canary_exploit", "autonomous_uplift", "live_code_bench"]

    def __init__(self, method):
        if method in self.AVAIL_METHODS:
            self.method = method
        else:
            raise NotImplementedError(f"Method {method} is not implemented")

    def __call__(self, data: DataPoint):
        """
        data -> named arguments
        -> compute_x_metric_impl(data)
        """
        if hasattr(data.task, "compute_execution_impl"):
            return data.task.compute_execution_impl(data=data)
        else:
            raise NotImplementedError(
                "This task does not have a compute_execution_score_impl method"
            )
