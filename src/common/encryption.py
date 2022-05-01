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
from datetime import timedelta, datetime, timezone
import os
from typing import Union, Optional

import boto3
import aws_encryption_sdk


@dataclass(frozen=True)
class EncryptionClient:
    client: aws_encryption_sdk.EncryptionSDKClient
    key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    cache: aws_encryption_sdk.caches.base.CryptoMaterialsCache
    materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        # encryption_context: Optional[dict] = None,
    ) -> bytes:
        ciphertext, header = self.client.encrypt(
            source=plaintext,
            materials_manager=self.materials_manager,
            # encryption_context=encryption_context,
        )
        return ciphertext

    def decrypt(
        self,
        ciphertext: Union[str, bytes],
    ) -> bytes:
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
