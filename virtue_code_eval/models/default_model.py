from __future__ import annotations

import asyncio
import logging
import os
from pprint import pformat

from together import AsyncTogether, Together, error

logger = logging.getLogger(__name__)

TEST_MODEL_NAME = "TEST"


class TogetherModel:
    def __init__(
        self,
        model_name,
        timeout=20,
        max_retries=3,
        chat_config: dict | None = None,
        client_config: dict | None = None,
    ):
        default_client_config = dict(
            api_key=os.environ.get("TOGETHER_API_KEY"),
            timeout=timeout,
            max_retries=max_retries,
        )
        if client_config is None:
            client_config = {}
        client_config = {**default_client_config, **client_config}

        if chat_config is None:
            chat_config = {}

        self.client = Together(**client_config)
        self.model_name = model_name
        self.chat_config = chat_config

    def __call__(self, messages) -> str | None:
        if self.model_name == TEST_MODEL_NAME:
            logger.debug(f"model [{TEST_MODEL_NAME}] reserved for testing")
            return "Test Test"

        try:
            # TODO: Support config
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                **self.chat_config,
            )
            return response.choices[0].message.content
        except error.TogetherException as e:
            logger.info(f"Failed in TogetherModel query: {e}")

        return None


class AsyncTogetherModel:
    def __init__(
        self,
        model_name,
        timeout=20,
        max_retries=3,
        chat_config: dict | None = None,
        client_config: dict | None = None,
    ):
        default_client_config = dict(
            api_key=os.environ.get("TOGETHER_API_KEY"),
            timeout=timeout,
            max_retries=max_retries,
        )
        if client_config is None:
            client_config = {}
        client_config = {**default_client_config, **client_config}

        if chat_config is None:
            chat_config = {}

        self.async_client = AsyncTogether(**client_config)
        self.model_name = model_name
        self.chat_config = chat_config

    def __call__(self, messages_lst: list[list[dict[str, str]]]) -> list[str | None]:
        """
        :param messages_lst: list of str
            list of messages to query the model
        """
        if self.model_name == TEST_MODEL_NAME:
            logger.debug(f"model [{TEST_MODEL_NAME}] reserved for testing")
            return ["Test Test"] * len(messages_lst)

        responses = asyncio.run(self.batch_async_chat_completion(messages_lst))

        return responses

    async def async_chat_completion(self, messages: list[dict[str, str]]) -> str | None:
        try:
            logger.debug(f"Querying model: {self.model_name}")
            logger.debug(f"Messages: {pformat(messages)}")
            response = await self.async_client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                **self.chat_config,
            )
            return response.choices[0].message.content
        except error.TogetherException as e:
            logger.info(f"Failed in TogetherModel query: {e}")
        except AssertionError as e:
            if "Unexpected error response None" in str(e):
                logger.warning("Workaround for local vllm no proper error format.")
            else:
                raise

        return None

    async def batch_async_chat_completion(
        self, messages_lst: list[list[dict[str, str]]]
    ) -> list[str | None]:
        tasks = [self.async_chat_completion(messages) for messages in messages_lst]

        return await asyncio.gather(*tasks)
