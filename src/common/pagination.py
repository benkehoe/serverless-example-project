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
import base64
import json
import os
from typing import Optional, ClassVar, Any, Tuple

import aws_lambda_api_event_utils as api_utils

from .event_utils import get_caller_identity, get_api_id, get_path
from .encryption import EncryptionClient


class PaginationTokenError(api_utils.APIErrorResponse):
    STATUS_CODE = 400
    ERROR_CODE = "InvalidNextToken"
    ERROR_MESSAGE = "The provided NextToken is invalid."


@dataclass(frozen=True)
class PaginationTokenContext:
    """Represents a context to include in the pagination token.
    The context in a token can then be validated against the current context,
    to require that token cannot be reused across contexts."""
    context: dict
    expiration: datetime
    DISABLE_PAGINATION_CONTEXT_STRICT_VALIDATION_ENV_KEY: ClassVar[
        str
    ] = "DISABLE_PAGINATION_CONTEXT_STRICT_VALIDATION"

    def __post_init__(self):
        if "tok" in self.context:
            raise KeyError("Context cannot contain key 'tok'")
        if "exp" in self.context:
            raise KeyError("Context cannot contain key 'exp'")

    def package(self, token: Any) -> dict:
        """Package the token and context into a dict."""
        data = {
            "tok": token,
            "exp": int(self.expiration.timestamp()),
        }
        data.update(self.context)
        return data

    def load(self, data: dict, *, validate: bool = True) -> Any:
        """Load the token and validate the context."""
        if "tok" not in data:
            raise KeyError("Missing key 'tok'")
        token = data["tok"]
        if "exp" not in data:
            raise KeyError("Missing key 'exp'")
        try:
            expiration = datetime.fromtimestamp(data["exp"], tz=timezone.utc)
        except Exception as e:
            raise ValueError(f"Invalid expiration: {e}")
        context = dict((k, v) for k, v in data.items() if k not in ["tok", "exp"])

        if not validate:
            return token

        disable_strict_validation = os.environ.get(
            self.DISABLE_PAGINATION_CONTEXT_STRICT_VALIDATION_ENV_KEY, ""
        ).lower() in ["true", "1"]

        now = datetime.now(timezone.utc)
        self._validate(
            expiration=expiration,
            context=context,
            disable_strict_validation=disable_strict_validation,
            now=now,
        )
        return token

    def _validate(
        self,
        *,
        expiration: datetime,
        context: dict,
        disable_strict_validation: bool,
        now: datetime,
    ):
        if expiration < now:
            raise ValueError(f"Token expired")

        for key in self.context.keys():
            if key not in context:
                if disable_strict_validation:
                    continue
                raise KeyError(f"Missing key '{key}'")
            if context[key] != self.context[key]:
                raise ValueError(f"Mismatch in key '{key}'")


def pagination_token_context_from_event(
    event: dict, *, duration: timedelta, now: Optional[datetime] = None
) -> PaginationTokenContext:
    """Create a context from the current event and a token validity duration."""
    context = {
        # Ensure that a token issued for one user can't be used by another user.
        "caller_identity": get_caller_identity(event),
        # Ensure that tokens issued for one API can't be used in another API
        "api_id": get_api_id(event),
        # Ensure that a token issued for one resource type / path can't be used for
        # another resource type.
        "path": get_path(event),
    }

    if now is None:
        now = datetime.now(timezone.utc)
    expiration = now + duration

    return PaginationTokenContext(context=context, expiration=expiration)


def _decode_plaintext_pagination_token(
    pagination_token: str, context: PaginationTokenContext
) -> dict:
    pagination_token_bytes = base64.urlsafe_b64decode(pagination_token)
    parsed_pagination_token_data = json.loads(pagination_token_bytes)
    pagination_token = context.load(parsed_pagination_token_data)
    return pagination_token


def _encode_plaintext_pagination_token(
    pagination_token_data: Any, context: PaginationTokenContext
) -> str:
    packaged_data = context.package(pagination_token_data)
    serialized_data = json.dumps(packaged_data, ensure_ascii=True)
    pagination_token_bytes = base64.urlsafe_b64encode(serialized_data.encode("ascii"))
    pagination_token = str(pagination_token_bytes, "ascii")
    return pagination_token


def _decode_encrypted_pagination_token(
    encryption_client: EncryptionClient,
    pagination_token: str,
    context: PaginationTokenContext,
) -> dict:
    pagination_token_bytes = base64.urlsafe_b64decode(pagination_token)
    decrypted_pagination_token = encryption_client.decrypt(
        pagination_token_bytes,
    )
    parsed_pagination_token_data = json.loads(decrypted_pagination_token)
    validated_pagination_token_data = context.load(parsed_pagination_token_data)
    return validated_pagination_token_data


def _encode_encrypted_pagination_token(
    encryption_client: EncryptionClient,
    pagination_token_data: Any,
    context: PaginationTokenContext,
) -> str:
    packaged_data = context.package(pagination_token_data)
    serialized_data = json.dumps(packaged_data)
    encrypted_pagination_token_bytes = encryption_client.encrypt(
        serialized_data,
    )
    pagination_token_bytes = base64.urlsafe_b64encode(encrypted_pagination_token_bytes)
    pagination_token = str(pagination_token_bytes, "ascii")
    return pagination_token


def decode_pagination_token(
    pagination_token: str,
    *,
    context: PaginationTokenContext,
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
            return _decode_plaintext_pagination_token(pagination_token, context)
        except Exception as e:
            raise PaginationTokenError(internal_message=f"{type(e).__name__}: {str(e)}")
    elif version == "2":
        if not encryption_client:
            raise PaginationTokenError(
                internal_message=f"Encrypted token given but no encryption client provided.",
            )
        try:
            return _decode_encrypted_pagination_token(
                encryption_client, pagination_token, context
            )
        except Exception as e:
            raise PaginationTokenError(internal_message=f"{type(e).__name__}: {str(e)}")
    else:
        raise PaginationTokenError(internal_message=f"Invalid version ID {version}.")


def encode_pagination_token(
    pagination_token_data: str,
    *,
    encrypted: bool,
    context: PaginationTokenContext,
    encryption_client: EncryptionClient = None,
) -> str:
    if encrypted and not encryption_client:
        raise ValueError("Can't encrypt pagination token without an EncryptionClient.")
    if encrypted:
        return "2-" + _encode_encrypted_pagination_token(
            encryption_client=encryption_client,
            pagination_token_data=pagination_token_data,
            context=context,
        )
    else:
        return "1-" + _encode_plaintext_pagination_token(
            pagination_token_data=pagination_token_data, context=context
        )
