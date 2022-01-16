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

from dataclasses import dataclass
from datetime import timedelta
import base64
import json
from typing import Union, Optional, Any

import boto3
import aws_encryption_sdk

import aws_lambda_api_event_utils as api_utils


class PaginationTokenError(api_utils.APIErrorResponse):
    STATUS_CODE = 400
    ERROR_CODE = "InvalidNextToken"
    ERROR_MESSAGE = "The provided NextToken is invalid."


@dataclass
class EncryptionClient:
    client: aws_encryption_sdk.EncryptionSDKClient
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    cache: aws_encryption_sdk.caches.base.CryptoMaterialsCache
    materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager

    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        ciphertext, header = self.client.encrypt(
            source=plaintext,
            materials_manager=self.materials_manager,
        )
        return ciphertext

    def decrypt(self, ciphertext: Union[str, bytes]) -> bytes:
        plaintext, header = self.client.decrypt(
            source=ciphertext,
            materials_manager=self.materials_manager,
        )
        return plaintext


def get_encryption_client(
    session: boto3.Session,
    kms_key_arn: str,
    cache_capacity=100,
    cache_max_age: timedelta = timedelta(hours=6),  # longer than the Lambda container
) -> EncryptionClient:
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=aws_encryption_sdk.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(
        botocore_session=session._session, key_ids=[kms_key_arn]
    )
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=cache_capacity)
    materials_manager = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=kms_key_provider,
        cache=cache,
        max_age=cache_max_age.total_seconds(),
    )

    return EncryptionClient(
        client=client,
        key_provider=kms_key_provider,
        cache=cache,
        materials_manager=materials_manager,
    )


def _decode_plaintext_pagination_token(pagination_token: str) -> dict:
    pagination_token_bytes = base64.urlsafe_b64decode(pagination_token)
    parsed_pagination_token = json.loads(pagination_token_bytes)
    return parsed_pagination_token


def _encode_plaintext_pagination_token(last_evaluated_key: dict) -> str:
    serialized_last_evaluated_key = json.dumps(last_evaluated_key)
    pagination_token_bytes = base64.urlsafe_b64encode(
        serialized_last_evaluated_key.encode("ascii")
    )
    pagination_token = str(pagination_token_bytes, "ascii")
    return pagination_token


def _decode_encrypted_pagination_token(
    encryption_client: EncryptionClient, pagination_token: str
) -> dict:
    pagination_token_bytes = base64.urlsafe_b64decode(pagination_token)
    decrypted_pagination_token = encryption_client.decrypt(pagination_token_bytes)
    parsed_pagination_token = json.loads(decrypted_pagination_token)
    return parsed_pagination_token


def _encode_encrypted_pagination_token(
    encryption_client: EncryptionClient, last_evaluated_key: dict
) -> str:
    serialized_last_evaluated_key = json.dumps(last_evaluated_key)
    encrypted_pagination_token_bytes = encryption_client.encrypt(
        serialized_last_evaluated_key
    )
    pagination_token_bytes = base64.urlsafe_b64encode(encrypted_pagination_token_bytes)
    pagination_token = str(pagination_token_bytes, "ascii")
    return pagination_token


def decode_pagination_token(
    pagination_token: str,
    require_encrypted: bool,
    encryption_client: EncryptionClient = None,
) -> dict:
    parts = pagination_token.split("-", 1)
    if len(parts) == 1:
        raise PaginationTokenError(internal_message=f"No version ID.")
    version, pagination_token = parts
    if version == "1":
        if require_encrypted:
            raise PaginationTokenError(
                internal_message=f"Plaintext token given but encryption required.",
            )
        try:
            return _decode_plaintext_pagination_token(pagination_token)
        except Exception as e:
            raise PaginationTokenError(internal_message=f"{type(e).__name__}: {str(e)}")
    elif version == "2":
        if not encryption_client:
            raise PaginationTokenError(
                internal_message=f"Encrypted token given but no encryption client provided.",
            )
        try:
            return _decode_encrypted_pagination_token(
                encryption_client, pagination_token
            )
        except Exception as e:
            raise PaginationTokenError(internal_message=f"{type(e).__name__}: {str(e)}")
    else:
        raise PaginationTokenError(internal_message=f"Invalid version ID {version}.")


def encode_pagination_token(
    pagination_token: str, encrypted: bool, encryption_client: EncryptionClient = None
) -> str:
    if encrypted and not encryption_client:
        raise ValueError("Can't encrypt pagination token without an EncryptionClient.")
    if encrypted:
        return "2-" + _encode_encrypted_pagination_token(
            encryption_client, pagination_token
        )
    else:
        return "1-" + _encode_plaintext_pagination_token(pagination_token)
