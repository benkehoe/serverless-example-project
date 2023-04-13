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

import secrets

import pytest

from common import Config, Caller


def rand_str():
    return secrets.token_hex(4)


def test_create_and_get(config: Config, caller: Caller):
    name = rand_str()
    key = rand_str()
    value = rand_str()
    item = {
        "Name": name,
        key: value,
    }
    response = caller.call(path="/items/create", method="POST", body=item)
    response.raise_for_status()
    response_json = response.json()
    assert "Item" in response_json
    response_item = response_json["Item"]
    assert "Name" in response_item
    assert response_item["Name"] == name
    assert key in response_item
    assert response_item[key] == value
    assert "pk" not in response_item
    assert "sk" not in response_item

    response = caller.call(path=f"/items/get/{name}", method="GET")
    response.raise_for_status()
    response_json = response.json()
    assert "Item" in response_json
    response_item = response_json["Item"]
    assert "Name" in response_item
    assert response_item["Name"] == name
    assert key in response_item
    assert response_item[key] == value
    assert "pk" not in response_item
    assert "sk" not in response_item


def test_create_and_list(config: Config, caller: Caller):
    name = rand_str()
    key = rand_str()
    value = rand_str()
    item = {
        "Name": name,
        key: value,
    }
    response = caller.call(path="/items/create", method="POST", body=item)
    response.raise_for_status()
    response_json = response.json()
    assert "Item" in response_json
    response_item = response_json["Item"]
    assert "Name" in response_item
    assert response_item["Name"] == name
    assert key in response_item
    assert response_item[key] == value
    assert "pk" not in response_item
    assert "sk" not in response_item

    for response in caller.paginate(
        path=f"/items/list", method="GET", pagination_key="NextToken"
    ):
        response.raise_for_status()
        response_json = response.json()
        assert "Items" in response_json
        for response_item in response_json["Items"]:
            assert "pk" not in response_item
            assert "sk" not in response_item
            assert "Name" in response_item
            if response_item["Name"] == name:
                assert key in response_item
                assert response_item[key] == value
                break
        else:
            continue
        break
    else:
        assert False, f"List did not return item {name}"


def test_create_invalid(config: Config, caller: Caller):
    name = rand_str()
    pk = rand_str()
    sk = rand_str()

    item = {}
    response = caller.call(path="/items/create", method="POST", body=item)
    assert response.status_code == 400
    response_json = response.json()
    assert "Error" in response_json
    assert "Code" in response_json["Error"]
    assert response_json["Error"]["Code"] == "InvalidPayload"

    item = {"Name": name, "pk": pk}
    response = caller.call(path="/items/create", method="POST", body=item)
    assert response.status_code == 400
    response_json = response.json()
    assert "Error" in response_json
    assert "Code" in response_json["Error"]
    assert response_json["Error"]["Code"] == "InvalidPayload"

    item = {"Name": name, "sk": sk}
    response = caller.call(path="/items/create", method="POST", body=item)
    assert response.status_code == 400
    response_json = response.json()
    assert "Error" in response_json
    assert "Code" in response_json["Error"]
    assert response_json["Error"]["Code"] == "InvalidPayload"

    item = {"Name": name, "pk": pk, "sk": sk}
    response = caller.call(path="/items/create", method="POST", body=item)
    assert response.status_code == 400
    response_json = response.json()
    assert "Error" in response_json
    assert "Code" in response_json["Error"]
    assert response_json["Error"]["Code"] == "InvalidPayload"
