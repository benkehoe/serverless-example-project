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
from aws_error_utils import errors, ClientError

from common.identifiers import parse_key
from common.pagination import (
    get_encryption_client,
    encode_pagination_token,
    decode_pagination_token,
)

print("initializing")

TABLE_NAME = os.environ["TABLE_NAME"]
PAGINATION_KEY_ARN = os.environ["PAGINATION_KEY_ARN"]

SESSION = boto3.Session()
TABLE_RESOURCE = SESSION.resource("dynamodb").Table(TABLE_NAME)

ENCRYPTION_CLIENT = get_encryption_client(SESSION, PAGINATION_KEY_ARN)
ENCRYPT_PAGINATION_TOKENS = True


def item_filter(item):
    pk, sk = parse_key(item["pk"], item["sk"])
    if pk[0] != "Name":
        return False
    if sk != ("__item__",):
        return False
    return True


@api_utils.api_event_handler
def handler(event, context):
    pagination_token = (event.get("queryStringParameters") or {}).get("NextToken")

    exclusive_start_key = None
    if pagination_token:
        exclusive_start_key = decode_pagination_token(
            pagination_token,
            require_encrypted=ENCRYPT_PAGINATION_TOKENS,
            encryption_client=ENCRYPTION_CLIENT,
        )

    try:
        scan_args = {"Limit": 2}  # TODO: remove this
        if exclusive_start_key:
            scan_args["ExclusiveStartKey"] = exclusive_start_key
        response = TABLE_RESOURCE.scan(**scan_args)
        items = response.get("Items") or []
        last_evaluated_key = response.get("LastEvaluatedKey")
    except (errors.ProvisionedThroughputExceededException, errors.RequestLimitExceeded):
        api_utils.APIErrorResponse.re_raise_as(HTTPStatus.SERVICE_UNAVAILABLE)

    items = list(filter(item_filter, items))
    for item in items:
        item.pop("pk")
        item.pop("sk")

    response = {"Items": items}
    if last_evaluated_key:
        response["NextToken"] = encode_pagination_token(
            last_evaluated_key,
            encrypted=ENCRYPT_PAGINATION_TOKENS,
            encryption_client=ENCRYPTION_CLIENT,
        )

    return response
