# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

import warnings

from virtue_code_eval.code_tasks.base_task import DataPoint

warnings.filterwarnings("ignore")


def default_argparse_bleu(data: DataPoint):
    return {
        "response": data.response,
        "reference": data.reference,
    }


def compute_accuracy(data: DataPoint):
    """
    data -> named arguments
    -> compute_x_metric_impl(data)
    """
    if hasattr(data.task, "argparse_bleu"):
        return compute_accuracy_impl(**data.task.argparse_bleu(data))
    else:
        return compute_accuracy_impl(**default_argparse_bleu(data))


def compute_accuracy_impl(response: str, reference: str) -> float:
    """Compute BLEU score between two strings using SacreBleu."""
    # Compute and return the BLEU score using SacreBleu
    # for now we only use the first output
    return (
        accuracy(
            [response],
            [[reference]],
            smooth_method="exp",
            force=False,
            lowercase=False,
            use_effective_order=False,
        ).score
        / 100
    )
