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
from aws_error_utils import errors, ClientError, catch_aws_error

from common.identifiers import get_name_key, unquote

TABLE_NAME = os.environ["TABLE_NAME"]

SESSION = boto3.Session()
TABLE_RESOURCE = SESSION.resource("dynamodb").Table(TABLE_NAME)


@api_utils.path_parameters(keys=["name"])
def handler(event, context):
    name = unquote(event["pathParameters"]["name"])

    pk, sk = get_name_key(name)

    try:
        response = TABLE_RESOURCE.get_item(
            Key={
                "pk": pk,
                "sk": sk,
            }
        )
        if "Item" not in response:
            raise api_utils.APIErrorResponse.from_status_code(HTTPStatus.NOT_FOUND)
        item = response["Item"]
    except catch_aws_error(
        "ProvisionedThroughputExceededException", "RequestLimitExceeded"
    ):
        raise api_utils.APIErrorResponse.from_status_code(
            HTTPStatus.SERVICE_UNAVAILABLE
        )

    item.pop("pk")
    item.pop("sk")

    return {"Item": item}
