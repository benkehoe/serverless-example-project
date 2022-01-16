# Copyright 2023 Ben Kehoe
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import dataclasses
import functools
import json
from typing import Any

import requests

import boto3


@dataclasses.dataclass
class Config:
    api_url: str
    stack_name: str
    session: boto3.Session = dataclasses.field(init=False)
    stack: Any = dataclasses.field(init=False)

    def __post_init__(self):
        self.session = boto3.Session()
        cfn = boto3.resource("cloudformation")
        self.stack = cfn.Stack(self.stack_name)

    def _join(self, base: str, path: str) -> str:
        base = base.rstrip("/")
        path = path.lstrip("/")
        return base + "/" + path

    def get_url(self, path: str) -> str:
        if not self.api_url:
            raise ValueError("API URL not set")
        return self._join(self.api_url, path)


class Caller:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.session = requests.Session()

    def __getattr__(self, name: str):
        method = name.upper()
        return functools.partial(self.call, method=method)

    def call(
        self,
        *,
        path: str,
        method: str,
        params=None,
        body=None,
        headers: dict = None,
    ):
        url = self.config.get_url(path)

        if headers:
            headers = headers.copy()
        else:
            headers = {}

        args = dict(
            method=method,
            url=url,
            params=params,
            headers=headers,
        )
        if body:
            args["json"] = body

        request = requests.Request(**args)
        prepared_request = request.prepare()

        print(">" * 20)
        print(type, prepared_request.method, prepared_request.url)
        for key, value in prepared_request.headers.items():
            print(f"{key}: {value}")
        if prepared_request.body:
            print(prepared_request.body)

        print("-" * 20)

        response = self.session.send(prepared_request)

        print(response.status_code, response.reason)
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        try:
            print(json.dumps(response.json(), indent=2))
        except:
            print(response.text)

        print("<" * 20)

        return response

    def paginate(
        self,
        *,
        path: str,
        method: str,
        pagination_key: str,
        params=None,
        body=None,
        headers: dict = None,
    ):
        response = self.call(
            path=path, method=method, params=params, body=body, headers=headers
        )
        yield response
        while pagination_key in response.json():
            response = self.call(
                path=path, method=method, params=params, body=body, headers=headers
            )
            yield response
