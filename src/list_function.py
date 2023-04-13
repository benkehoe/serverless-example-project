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
from datetime import timedelta

import boto3

import aws_lambda_api_event_utils as api_utils
from aws_error_utils import errors, ClientError

from common.identifiers import parse_key
from common.encryption import get_encryption_client
from common.pagination import (
    PaginationTokenContext,
    PaginationToken,
    PaginationTokenEncoder,
    PaginationTokenDecoder,
)
from common import event_utils
from common.timedelta_iso import fromisoformat

# TODO: set up proper logging
api_utils.APIErrorResponse.DECORATOR_LOGGER = lambda s, m: print(m.replace("\n", "\r"))
api_utils.APIErrorResponse.DECORATOR_LOGGER_TRACEBACK = True

TABLE_NAME = os.environ["TABLE_NAME"]
PAGINATION_KEY_ARN = os.environ["PAGINATION_KEY_ARN"]

ENCRYPT_PAGINATION_TOKENS = os.environ["ENCRYPT_PAGINATION_TOKENS"].lower() in [
    "1",
    "true",
]
DISABLE_PAGINATION_TOKEN_CONTEXT_VALIDATION = os.environ.get(
    "DISABLE_PAGINATION_TOKEN_CONTEXT_VALIDATION", ""
).lower() in ["1", "true"]
PAGINATION_TOKEN_MAX_AGE = fromisoformat(
    os.environ.get("PAGINATION_TOKEN_MAX_AGE") or "PT5M"
)

# force pagination for now
PAGINATION_MAX_ITEMS = int(os.environ.get("PAGINATION_MAX_ITEMS", "2"))

SESSION = boto3.Session()
TABLE_RESOURCE = SESSION.resource("dynamodb").Table(TABLE_NAME)

ENCRYPTION_CLIENT = get_encryption_client(SESSION, PAGINATION_KEY_ARN)


def item_filter(item):
    pk, sk = parse_key(item["pk"], item["sk"])
    if pk[0] != "Name":
        return False
    if sk != ("__item__",):
        return False
    return True


def get_pagination_token_context_kv(event) -> dict:
    context = {}

    # Ensure that a token issued for one user can't be used by another user.
    caller_identity = event_utils.get_caller_identity(event)
    if caller_identity:
        context["cid"] = caller_identity

    # Ensure that tokens issued for one API can't be used in another API
    api_id = event_utils.get_api_id(event)
    if api_id:
        context["api"] = api_id

    # Ensure that a token issued for one resource type / path can't be used for
    # another resource type.
    path = event_utils.get_path(event)
    if path:
        context["pat"] = path

    return context


@api_utils.api_event_handler
def handler(event, context):
    encoded_pagination_token = (event.get("queryStringParameters") or {}).get(
        "NextToken"
    )

    pagination_token_context = PaginationTokenContext(
        version="1", context_kv=get_pagination_token_context_kv(event)
    )

    exclusive_start_key = None
    if encoded_pagination_token:
        # TODO: hash and log the token for tracking
        pagination_token = PaginationTokenDecoder(
            encoded_pagination_token=encoded_pagination_token,
            pagination_token_context=pagination_token_context,
            require_encrypted=ENCRYPT_PAGINATION_TOKENS,
            disable_context_validation=DISABLE_PAGINATION_TOKEN_CONTEXT_VALIDATION,
            max_age=PAGINATION_TOKEN_MAX_AGE,
            encryption_client=ENCRYPTION_CLIENT,
        ).decode()
        exclusive_start_key = pagination_token.value

    try:
        scan_args = {"Limit": PAGINATION_MAX_ITEMS}  # TODO: allow user value
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
        next_token = PaginationTokenEncoder(
            pagination_token=PaginationToken(
                context=pagination_token_context,
                value=last_evaluated_key,
            ),
            encrypted=ENCRYPT_PAGINATION_TOKENS,
            encryption_client=ENCRYPTION_CLIENT,
        ).encode()
        # TODO: hash and log the token for tracking
        response["NextToken"] = next_token

    return response
