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

import pytest

import urllib
import dataclasses
import json
import functools

import requests

from common import Config, Caller


def _get_option(pytestconfig, name):
    value = pytestconfig.getoption(name)
    if not value:
        raise ValueError(f"Missing {name}")
    return value


def pytest_addoption(parser):
    parser.addoption("--api-url")
    parser.addoption("--stack-name")


@pytest.fixture(scope="session")
def config(pytestconfig):
    api_url = _get_option(pytestconfig, "--api-url")
    stack_name = _get_option(pytestconfig, "--stack-name")
    return Config(
        api_url=api_url,
        stack_name=stack_name,
    )


@pytest.fixture(scope="function")
def caller(config):
    return Caller(config)
