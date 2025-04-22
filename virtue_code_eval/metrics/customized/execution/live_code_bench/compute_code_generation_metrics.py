# borrowed and extended from
# https://github.com/Naman-ntc/codescratch/blob/main/evaluation/bigcode-evaluation-harness/lm_eval/tasks/custom_metrics/apps_custom_metrics/utils.py
import faulthandler
import os
import multiprocessing
import time

from virtue_code_eval.metrics.error_codes import ErrorCode
from .pass_k_utils import compute_metrics_from_results
from .testing_util import run_test, TimeoutException

os.environ["TOKENIZERS_PARALLELISM"] = "false"
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
import logging
from tqdm import tqdm

logger = logging.getLogger(__name__)


def _temp_run(sample, generation, result, metadata_list, timeout):
    res, metadata = run_test(sample, test=generation, timeout=timeout)
    result.append(res)
    metadata_list.append(metadata)


def check_correctness(sample, generation, timeout, return_list):
    """Check correctness of code generation with a global timeout.
    The global timeout is to catch some extreme/rare cases not handled by the timeouts
    inside `run_test`"""
    faulthandler.enable()
    try:
        results = run_test(sample, test=generation, timeout=timeout)
        if "error_code" in results:
            if results["error_code"] == ErrorCode.COMPILATION_ERROR:
                logger.debug("Compilation error")
                ret = ErrorCode.COMPILATION_ERROR.value
            elif results["error_code"] == ErrorCode.RUNTIME_ERROR:
                logger.debug("Runtime error")
                ret = ErrorCode.RUNTIME_ERROR.value
            elif results["error_code"] == ErrorCode.UNKNOWN_ERROR:
                logger.debug("No test case found error")
                ret = ErrorCode.UNKNOWN_ERROR.value
            else:
                raise ValueError(f"Unknown error code {results['error_code']}")
        else:
            ret = results["output"]  # list
    except TimeoutException:
        ret = ErrorCode.TIMEOUT_ERROR.value
        logger.debug("global timeout")
    # result, metadata = _temp_run_one(sample, generation, timeout)
    # manager = multiprocessing.Manager()
    # result = manager.list()
    # metadata_list = manager.list()
    # p = multiprocessing.Process(
    #     target=_temp_run,
    #     args=(sample, generation, result, metadata_list, timeout),
    # )
    # p.start()
    # p.join(
    #     timeout=(timeout + 1) * len(json.loads(sample["input_output"])["inputs"]) + 5
    # )
    # if p.is_alive():
    #     p.kill()
    # if not result:
    #     in_outs = json.loads(sample["input_output"])
    #     # consider that all tests failed
    #     result = [[ErrorCode.TIMEOUT_ERROR for _ in range(len(in_outs["inputs"]))]]
    #     logger.debug("global timeout")
    faulthandler.disable()
    return_list.append(ret)


def evaluate_generations_by_problem(
    problem_generations: list[str], sample, timeout: int
) -> tuple[list[int], list[float]]:
    return_list = multiprocessing.Manager().list()
    duration_list = []
    for o_idx, o in enumerate(problem_generations):
        p = multiprocessing.Process(
            target=check_correctness, args=(sample, o, timeout, return_list)
        )
        process_timeout = (timeout + 1) * len(
            json.loads(sample["input_output"])["inputs"]
        ) + 5
        start_time = time.time()
        p.start()
        p.join(timeout=process_timeout)
        if p.is_alive():
            p.kill()
            return_list.append(ErrorCode.TIMEOUT_ERROR.value)
        else:
            duration_list.append(time.time() - start_time)
        # logger.debug(f"\nSuccessful compilation of task {o_idx}!")
        # if not np.all(curr_res==0):
        #     logger.debug(f"Results were not True for all test cases {curr_res=}\n")
        #     # break
        # curr_metadata = {}
        # assert isinstance(curr_res, list)
        # assert isinstance(curr_metadata, dict)
        # metadata.append(curr_metadata)

    return list(return_list), duration_list


def evaluate_one_generation(
    sample: dict,
    generation: list[str],
    timeout=6,
) -> tuple[list[int], list[float]]:
    """We take the list of code generations and try to compile them
     and the run their corresponding unit tests which are retrieved from the APPS dataset.

    Args:
        sample: sample from the APPS dataset
        generation: list of code generations (same order as samples in APPS dataset)
        timeout: timeout for each test case

    Returns:
        results: dictionary of results, key is the problem index, value is a list of results for each generation
        [-2] = compile error, [-1] = runtime error [False] = failed test case [True] = passed test case
    """
    result, duration_list = evaluate_generations_by_problem(generation, sample, timeout)
    return result, duration_list


def evaluate_generations(
    samples_list: list,
    generations_list: list[list[str]],
    debug: bool = False,
    num_process_evaluate: int = 16,
    timeout=6,
):
    """We take the list of code generations and try to compile them
     and the run their corresponding unit tests which are retrieved from the APPS dataset.

    Args:
        samples_list: samples from the APPS dataset
        generations_list: list of code generations (same order as samples in APPS dataset)
        debug: whether to run in debug mode
        num_process_evaluate: number of processes to use for evaluation
        timeout: timeout for each test case

    Returns:
        results: dictionary of results, key is the problem index, value is a list of results for each generation
        [-2] = compile error, [-1] = runtime error [False] = failed test case [True] = passed test case
    """

    # generations are code generations in the same order of the dataset

    inputs = [
        [(generations_list[index], samples_list[index], timeout), index]
        for index in range(len(generations_list))
    ]

    with tqdm(total=len(inputs)) as pbar:
        with ProcessPoolExecutor(
            max_workers=1 if debug else num_process_evaluate
        ) as executor:
            futures = {
                executor.submit(evaluate_generations_by_problem, *arg): index
                for arg, index in inputs
            }

            results = {}
            metadata = {}
            for future in as_completed(futures):
                index = futures[future]
                results[index], metadata[index] = future.result()
                pbar.update(1)

    assert len(results) == len(
        inputs
    ), f"results = {len(results)} inputs = {len(inputs)} {results=}"
    # results = {i: r for r, (_, i) in zip(results, inputs)}

    return results, metadata


def codegen_metrics(
    samples,
    generations,
    k_list=None,
    num_process_evaluate=16,
    timeout=6,
    debug=False,
):
    if k_list is None:
        k_list = [1, 5, 10, 50, 100, 150, 200]
    results, metadata = evaluate_generations(
        samples,
        generations,
        debug=debug,
        num_process_evaluate=num_process_evaluate,
        timeout=timeout,
    )
    metrics = compute_metrics_from_results(results, k_list=k_list)

    final_metadata = []
    for key in sorted(list(metadata.keys())):
        final_metadata.append(metadata[key])
    for i in range(len(final_metadata)):
        if type(final_metadata[i]) is not list:
            final_metadata[i] = [json.dumps(final_metadata[i])]
        else:
            final_metadata[i] = [json.dumps(x) for x in final_metadata[i]]

        assert len(final_metadata[i]) == len(
            generations[0]
        ), f"{len(final_metadata[i])=}"

    return [metrics, results, final_metadata]
