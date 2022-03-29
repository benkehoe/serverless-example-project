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
from aws_error_utils import errors, catch_aws_error

from common.identifiers import get_name_key

TABLE_NAME = os.environ["TABLE_NAME"]

SCHEMA = {
    "type": "object",
    "properties": {
        "Name": {
            "type": "string",
            # TODO: min length
        }
    },
    "required": ["Name"],
}

SESSION = boto3.Session()
TABLE_RESOURCE = SESSION.resource("dynamodb").Table(TABLE_NAME)


@api_utils.json_body(SCHEMA)
def handler(event, context):
    payload = event["body"]

    name = payload["Name"]
    pk, sk = get_name_key(name)

    item = {"pk": pk, "sk": sk, **payload}

    try:
        TABLE_RESOURCE.put_item(Item=item)
    except catch_aws_error(
        "ProvisionedThroughputExceededException", "RequestLimitExceeded"
    ):
        raise api_utils.APIErrorResponse.from_status_code(
            HTTPStatus.SERVICE_UNAVAILABLE
        )

    return {"Item": payload}
