# Copyright 2022 Ben Kehoe
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

import os
from http import HTTPStatus

import boto3

import aws_lambda_api_event_utils as api_utils
from aws_error_utils import errors

from common.identifiers import get_name_key

TABLE_NAME = os.environ["TABLE_NAME"]

ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "Name": {
            "type": "string",
            # TODO: min length
        }
    },
    "required": ["Name"],
}

# Because we're inlining these properties into the table item
# we explicitly prevent setting the table keys
DISALLOW_PK_SK_SCHEMA = {
    "not": {
        "anyOf": [
            {"required": ["pk"]},
            {"required": ["sk"]},
        ]
    }
}

# Combine item schema with disallowing
SCHEMA = {"allOf": [ITEM_SCHEMA, DISALLOW_PK_SK_SCHEMA]}

SESSION = boto3.Session()
TABLE_RESOURCE = SESSION.resource("dynamodb").Table(TABLE_NAME)


@api_utils.json_body(api_utils.CompiledFastJSONSchema(SCHEMA))
def handler(event, context):
    payload = event["body"]

    name = payload["Name"]
    pk, sk = get_name_key(name)

    item = payload.copy()
    item["pk"] = pk
    item["sk"] = sk

    try:
        TABLE_RESOURCE.put_item(Item=item)
    except (errors.ProvisionedThroughputExceededException, errors.RequestLimitExceeded):
        api_utils.APIErrorResponse.re_raise_as(HTTPStatus.SERVICE_UNAVAILABLE)

    return {"Item": payload}
