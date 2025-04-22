from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from datasets import Dataset

from virtue_code_eval.metrics.error_codes import ErrorCode
from virtue_code_eval.metrics.refusal import is_response_llm_refusal

logger = logging.getLogger(__name__)


@dataclass
class DataPoint:
    raw_data: Any
    id_: str
    task: Task
    subtask: dict[str, str]
    subtask_desc: str
    reference: str | list[str] | None
    messages: list[dict[str, str]]
    response: str | None = None
    raw_response: str | None = None
    rejected: bool | None = None
    metrics: dict[str, float | None] | None = None


class Task(ABC):
    """A task represents an entire benchmark including its dataset, problems,
    answers, generation settings and evaluation methods.
    """

    FEWSHOT_RESERVE = 10

    AVAIL_METRICS: list[str] | None = None
    AVAIL_SUBTASKS: dict[str, list[str]] | None = None

    TASK_FULL_NAME: str | None = None

    def __str__(self):
        return self.TASK_FULL_NAME

    def __init__(
        self,
        metric_functions: dict[str, callable],
        subtasks: dict[str, list[str]] | None = None,
        num_data: int | None = None,
        fewshot_num: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
    ):
        """
        :param subtasks: dict[str, list[str]]
        :param metric_functions: dict[str, callable]
        :param num_data: int
            load the first num_data examples
        :param shuffle_data: bool
            load the examples in random order
        :param stop_words: list[str]
            list of stop words if the generation uses a stopping criteria during generation
        :param requires_execution: bool
            whether the task requires code execution during evaluation or not
        :param language: str
            the language of the task, all represents all languages
        """
        self.subtasks = subtasks
        self.shuffle_data = shuffle_data
        self.batch_size = batch_size
        self.fewshot_num = fewshot_num if fewshot_num else 0

        self.dataset = self.get_dataset()

        # check parameters
        if self.fewshot_num > 10:
            raise ValueError("Few-shot examples should be no more than 10")

        # init fewshot
        self.fewshot_messages = self.init_fewshot() if self.fewshot_num else []

        # filter the dataset based on the subtasks
        if self.subtasks:
            for subtask, values in self.subtasks.items():
                # examine if the subtask and values are valid
                if subtask not in self.AVAIL_SUBTASKS:
                    raise ValueError(f"Invalid subtask: {subtask}")
                if not set(values).issubset(self.AVAIL_SUBTASKS[subtask]):
                    raise ValueError(f"Invalid values for subtask {subtask}: {values}")

                if set(values) == set(self.AVAIL_SUBTASKS[subtask]):
                    continue
                self.dataset = self.dataset.filter(lambda x: x[subtask] in values)
        else:
            self.subtasks = self.AVAIL_SUBTASKS

        if shuffle_data:
            self.dataset = self.dataset.shuffle()

        if num_data is not None and num_data != -1:
            num_data = min(num_data, len(self.dataset))
            self.dataset = self.dataset.take(num_data)

        # init metrics
        self.metric_functions = {}
        for metric_name, metric_func in metric_functions.items():
            if metric_name not in self.AVAIL_METRICS:
                logger.warning(
                    f"Task [{self.TASK_FULL_NAME}] doesn't support metric [{metric_name}]"
                )
            else:
                self.metric_functions[metric_name] = metric_func

    def __len__(self):
        return len(self.dataset)

    def filter_existing_ids(self, existing_ids: set) -> None:
        """
        Filter out the existing ids from the dataset
        """
        logger.info("Before filtering, dataset size: %d", len(self.dataset))
        # if the dataset is a HF dataset
        if hasattr(self.dataset, "filter"):
            self.dataset = self.dataset.filter(
                lambda x: self.get_id(x) not in existing_ids
            )
        else:
            # BUG: list does not support subtask filtering
            self.dataset = [
                x for x in self.dataset if self.get_id(x) not in existing_ids
            ]
        logger.info("After filtering, dataset size: %d", len(self.dataset))

    def get_one_datapoint(self, idx) -> DataPoint:
        # get one datapoint
        if idx >= len(self):
            raise IndexError("Index out of range")
        raw_data = self.dataset[idx]

        data_subtask = {}
        for name in self.AVAIL_SUBTASKS:
            data_subtask[name] = raw_data[name]

        return DataPoint(
            raw_data=raw_data,
            id_=self.get_id(raw_data),
            task=self,
            subtask=data_subtask,
            subtask_desc=self.describe_subtask(data_subtask),
            reference=self.get_reference(raw_data),
            messages=self.build_messages(raw_data),
        )

    def __getitem__(self, idx) -> list[DataPoint] | DataPoint:
        """
        :param idx: int
            index of the datapoint

        :return: DataPoint
        """
        if isinstance(idx, slice):
            return [self.get_one_datapoint(i) for i in range(*idx.indices(len(self)))]
        # evaluate one datapoint
        else:
            return self.get_one_datapoint(idx)

    def batch_iter(self):
        for i in range(0, len(self), self.batch_size):
            yield self[i : i + self.batch_size]

    @staticmethod
    def describe_subtask(subtask: dict[str, str]) -> str:
        """
        Describe the subtask.
        """
        return ", ".join(f"{k}: {v}" for k, v in subtask.items())

    def init_fewshot(self):
        """
        Initialize the fewshot messages
        """
        fewshot_reserves = self.dataset.take(self.FEWSHOT_RESERVE)
        self.dataset = self.dataset.skip(self.FEWSHOT_RESERVE)
        fewshot_messages = []
        for sample in fewshot_reserves:
            fewshot_messages.append(
                [
                    {"role": "user", "content": self.get_prompt(sample)},
                    {
                        "role": "assistant",
                        "content": self.get_reference_model_output(sample),
                    },
                ]
            )

        return fewshot_messages

    @abstractmethod
    def get_dataset(self) -> Dataset:
        pass

    @abstractmethod
    def get_prompt(self, doc) -> str:
        """Builds the prompt for the LM to generate from.
        :param doc: dict[str: str]
            sample from the test dataset
        """
        pass

    def get_system_prompt(self, doc) -> str | None:
        return None

    def build_messages(self, doc) -> list[dict[str, str]]:
        """Builds the messages for the chatbot to generate from.
        :param doc: dict[str: str]
            sample from the test dataset
        """
        messages = []
        system_prompt = self.get_system_prompt(doc)
        if system_prompt is not None:
            messages.append({"role": "system", "content": system_prompt})

        if self.fewshot_num:
            for m in self.fewshot_messages[: self.fewshot_num]:
                messages.extend(m)

        messages.append({"role": "user", "content": self.get_prompt(doc)})

        return messages

    @abstractmethod
    def get_reference(self, doc) -> str | list[str]:
        """Builds the reference solution for the doc.
        :param doc: dict[str: str]
            sample from the test dataset
        """
        pass

    def get_reference_model_output(self, doc) -> str:
        """Builds the reference raw answer from the model for the doc.
        Use it when you want to reformat the reference answer like in a code block or json format.
        :param doc: dict[str: str]
            sample from the test dataset
        """
        return self.get_reference(doc)

    @abstractmethod
    def get_id(self, doc) -> str:
        """
        Get the id of the doc
        :param doc: dict[str: str]
            sample from the test dataset
        """
        pass

    @abstractmethod
    def postprocess_generation(self, response: str, data: DataPoint):
        """Defines the postprocessing for a LM generation.
        :param response: str
            code generation from LM
        :param data: str
            data
        """
        pass

    def evaluate(self, data: DataPoint):
        """Takes the list of LM generations and evaluates them against ground truth references,
        returning the metric for the generations.
        :param data: DataPoint
        """
        results = {}
        # before everything, we need to examine if llm reject to answer the prompt
        if is_response_llm_refusal(data.response):
            data.rejected = True
            # all metrics equals to REFUSAL
            data.metrics = {
                name: ErrorCode.RESPONSE_REFUSAL.value for name in self.metric_functions
            }
        else:
            data.rejected = False
            # if llm does not refuse to answer the prompt, we can evaluate the response
            for name, metric in self.metric_functions.items():
                score = metric(data)
                results[name] = score
            data.metrics = results


class MultiTurnTask(Task, ABC):
    """A multi-turn task represents an entire benchmark including its dataset, problems, answers, generation settings and evaluation methods."""

    FEWSHOT_RESERVE = 0

    AVAIL_METRICS: list[str] | None = None
    AVAIL_SUBTASKS: dict[str, list[str]] | None = None

    TASK_FULL_NAME: str | None = None

    def __str__(self):
        return self.TASK_FULL_NAME

    def __init__(
        self,
        metric_functions: dict[str, callable],
        subtasks: dict[str, list[str]] | None = None,
        num_data: int | None = None,
        fewshot_num: int | None = None,
        shuffle_data: bool = False,
        batch_size: int = 1,
    ):
        """
        :param subtasks: dict[str, list[str]]
        :param metric_functions: dict[str, callable]
        :param num_data: int
            load the first num_data examples
        :param shuffle_data: bool
            load the examples in random order
        :param stop_words: list[str]
            list of stop words if the generation uses a stopping criteria during generation
        :param requires_execution: bool
            whether the task requires code execution during evaluation or not
        :param language: str
            the language of the task, all represents all languages
        """
        # check parameters
        assert self.FEWSHOT_RESERVE, "Multi-turn task does not support fewshot"
        super().__init__(
            metric_functions, subtasks, num_data, fewshot_num, shuffle_data, batch_size
        )

    def __len__(self):
        return len(self.dataset)

    @abstractmethod
    def initial_env(self, data: DataPoint):
        pass

    @abstractmethod
    def update_prompt(self, feedback: str, data: DataPoint):
        pass

    @abstractmethod
    def feedback(self, data: DataPoint) -> str:
        pass


class TaskRegistry:
    def __init__(self, tasks: dict[str, type[Task]]):
        self.tasks = tasks

    def __getitem__(self, task_name: str) -> type[Task]:
        # directly match with task name
        task_cand = self.tasks.get(task_name)
        if task_cand is not None:
            return task_cand

        # TODO: try to match with regex pattern
        raise ValueError(f"Task {task_name} not found in the registry.")
