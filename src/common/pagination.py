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
from datetime import datetime, timedelta, timezone
import base64
import json
import hashlib
import binascii
from typing import Union, Optional, Any, Callable

import boto3

import aws_lambda_api_event_utils as api_utils

from .encryption import EncryptionClient, AWSEncryptionSDKClientError
from .timedelta_iso import isoformat

"""
These encrypted tokens are huge.
This is because we're using the AWS Encryption SDK, which has two implications.

First, we want to ensure the token is only used in the same context; currently
we check that it's used on the same API instance, the same path, and from the
same caller. Ideally, I think, we'd use key derivation for this, so the decryption
would just fail if the context was different. But the AWS Encryption SDK doesn't
provide for that, so we bundle it along with the token and check it manually.

Second, the AWS Encryption SDK wraps the ciphertext with extra information, like
the KMS key ARN. This is a useful thing for it to do in general, because it means
you don't have to store that info separately. But here, we know the key ARN anyway,
and the impact of not being able to decrypt a pagination token if which key a token
was encrypted with was forgotten is probably not huge.

So an implementation that used key derivation for the context and just returned the
bare encrypted token (with version and expiration) could be a lot smaller.
But there's danger in rolling your own crypto, even if you're using a mature library
for the actual crypto operations, both in terms of the risk of a flaw in the implementation
opening up an attack vector, and the risk of doing it wrong and causing something to break.
With the AWS Encryption SDK, you're not running that risk.
"""


def _now():
    return datetime.now(timezone.utc)


class PaginationTokenError(api_utils.APIErrorResponse):
    STATUS_CODE = 400
    ERROR_CODE = "InvalidNextToken"
    ERROR_MESSAGE = "The provided NextToken is invalid."


@dataclass
class PaginationTokenContext:
    """Context needed to process pagination tokens and check their validity.

    First, we need a version, so that the format of both the pagination token
    and this context itself can evolve over time.

    Second, we have a set of key-value pairs that can enforce a context is
    matched. In particular, we use this to ensure the token is bound to
    various properties of the API call, both static (like the path) and
    dynamic (like the caller identity). We don't want to include the key-value
    pairs themselves in the token, because that risks exposing them and we don't
    have a bound on how many we might want to include, so we use a hash instead.

    Third, we have a timestamp of when the token was issued. This will let us
    enforce an expiration. We could separately include an expiration, but to reduce
    token size, we only include the issuance time.
    """

    version: str
    context_kv: Optional[dict]
    context_kv_hash: Optional[str] = None
    issued_at: Optional[datetime] = None
    time_fetcher: Callable[[], datetime] = _now  # allow tests to mock out time

    def __post_init__(self):
        # version is required
        if not self.version:
            raise ValueError("Must set a version")

        # by default, set issued_at to now
        if not self.issued_at:
            self.issued_at = self.time_fetcher()

        # ensure the hash is correct by always calculating it ourselves
        if self.context_kv is not None and self.context_kv_hash:
            raise ValueError("Cannot set both context_kv and context_kv_hash")
        if self.context_kv is not None:
            hasher = hashlib.sha256()
            hasher.update(
                # To ensure the hash of equivalent dicts is always the same,
                # we sort the keys (so order in the dict doesn't matter)
                # and escape Unicode characters (so encoding doesn't matter).
                # We also use compact separators, which doesn't really matter here
                # but makes it the same settings as other calls to dump
                json.dumps(
                    self.context_kv,
                    sort_keys=True,
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )
            self.context_kv_hash = hasher.hexdigest()

    def validate(
        self,
        context_versions: list["PaginationTokenContext"],
    ):
        """Validate this context against a list of contexts (of different versions).

        This context will be extracted from an incoming token. It won't have context_kv
        set, only the hash.
        We need context versions to ...
        """
        context_map = {ctx.version: ctx for ctx in context_versions}
        if self.version not in context_map:
            # TODO: list supported versions?
            raise PaginationTokenError(
                f"Unknown pagination token version {self.version}"
            )
        context_to_match = context_map[self.version]
        if self.context_kv_hash != context_to_match.context_kv_hash:
            # We can't do more comprehensive error reporting because we only have the hashes
            raise PaginationTokenError("Pagination token context does not match")


@dataclass
class PaginationToken:
    context: PaginationTokenContext
    value: Any

    def bundle(self) -> dict:
        """Create a dict suitable for marshaling.

        To reduce size, we put all keys at the top level, and we use short
        keys, like in JWTs.
        """
        return {
            "v": self.context.version,
            "ctx": self.context.context_kv_hash,
            "iss": int(self.context.issued_at.timestamp()),
            "tok": self.value,
        }

    def marshal(self) -> bytes:
        """Serialize into a sequence of bytes.

        We use deterministic JSON serialization (sorting the keys, escaping Unicode),
        which isn't strictly necessary but is a good practice.
        """
        bundled = self.bundle()
        # To reduce size, we use compact separators (without trailing whitespace).
        # We also use the settings to make the output deterministic, which doesn't
        # really matter here but makes it the same settings as other calls to dump
        marshalled = json.dumps(
            bundled, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        return marshalled

    @classmethod
    def unbundle(cls, data: dict) -> "PaginationToken":
        """Create a PaginationToken from a dict."""
        if not isinstance(data, dict):
            raise PaginationTokenError("Token data is not an dict")
        # This way we can provide more comprehensive error reporting
        # rather than raising on the first missing key.
        missing = []
        for key in ["v", "tok", "ctx", "iss"]:
            if key not in data:
                missing.append(key)
        if missing:
            raise PaginationTokenError(f"Token data missing keys: {', '.join(missing)}")

        if not isinstance(data["v"], str):
            raise PaginationTokenError("Token data version is not a string")
        if not (data["ctx"] is None or isinstance(data["ctx"], str)):
            raise PaginationTokenError("Token data context is not a string or None")

        issued_at = datetime.fromtimestamp(data["iss"], timezone.utc)

        return cls(
            context=PaginationTokenContext(
                version=data["v"],
                context_kv=None,
                context_kv_hash=data["ctx"],
                issued_at=issued_at,
            ),
            value=data["tok"],
        )

    @classmethod
    def unmarshal(cls, data: bytes) -> "PaginationToken":
        """Create a PaginationToken from a sequence of bytes containing JSON."""
        try:
            unmarshalled = json.loads(data)
        except json.JSONDecodeError as e:
            raise PaginationTokenError(f"Token data is not valid JSON: {e}")
        unbundled = cls.unbundle(unmarshalled)
        return unbundled


def _encode_plaintext_pagination_token(
    pagination_token: PaginationToken,
) -> str:
    marshalled_pagination_token = pagination_token.marshal()
    encoded_pagination_token_bytes = base64.urlsafe_b64encode(
        marshalled_pagination_token
    )
    encoded_pagination_token = str(encoded_pagination_token_bytes, "ascii")
    return encoded_pagination_token


def _decode_plaintext_pagination_token(
    encoded_pagination_token: str,
) -> PaginationToken:
    try:
        pagination_token_bytes = base64.urlsafe_b64decode(encoded_pagination_token)
    except binascii.Error as e:
        raise PaginationTokenError(f"Token is not valid Base64: {e}")
    pagination_token = PaginationToken.unmarshal(pagination_token_bytes)
    return pagination_token


def _encode_encrypted_pagination_token(
    encryption_client: EncryptionClient, pagination_token: PaginationToken
) -> str:
    marshalled_pagination_token = pagination_token.marshal()
    encrypted_pagination_token_bytes = encryption_client.encrypt(
        marshalled_pagination_token
    )
    encoded_pagination_token_bytes = base64.urlsafe_b64encode(
        encrypted_pagination_token_bytes
    )
    encoded_pagination_token = str(encoded_pagination_token_bytes, "ascii")
    return encoded_pagination_token


def _decode_encrypted_pagination_token(
    encryption_client: EncryptionClient, encoded_pagination_token: str
) -> PaginationToken:
    try:
        encrypted_pagination_token_bytes = base64.urlsafe_b64decode(
            encoded_pagination_token
        )
    except binascii.Error as e:
        raise PaginationTokenError(f"Token is not valid Base64: {e}")
    try:
        decrypted_pagination_token = encryption_client.decrypt(
            encrypted_pagination_token_bytes
        )
    except AWSEncryptionSDKClientError as e:
        # TODO: can we separate exceptions caused by the ciphertext from exceptions caused by configuration?
        # the former should be caught and re-raised as PaginationTokenError
        # the latter should be allowed to propagate as-is (and handled higher level up)
        raise PaginationTokenError(f"Token could not be decrypted: {e}")
    pagination_token = PaginationToken.unmarshal(decrypted_pagination_token)
    return pagination_token


@dataclass
class PaginationTokenEncoder:
    """TODO

    We allow a list of PaginationTokens of different versions, selected by the
    current_version field. This is unnecessary but it's provided as symmetric with
    the list of contexts for decoding, that when migrating to a new token version,
    you don't want to change the token generation code in-place, you want to put both
    code paths in. You could easily do that outside the PaginationTokenEncoder, but
    this provides a reminder of it.
    """

    pagination_token: Union[PaginationToken, list[PaginationToken]]
    encrypted: bool
    current_version: Optional[str] = None
    encryption_client: EncryptionClient = None

    def __post_init__(self):
        # A list of tokens means one version needs to be selected
        if (
            not isinstance(self.pagination_token, PaginationToken)
            and not self.current_version
        ):
            raise ValueError(
                "Must provide current_version when pagination_token is a list"
            )

        # If it's just the single PaginationToken, set the current_version from it
        if isinstance(self.pagination_token, PaginationToken):
            # If it's already set but it's the same, that's fine
            if (
                self.current_version
                and self.current_version != self.pagination_token.context.version
            ):
                raise ValueError(
                    f"current_version {self.current_version} does not match pagination_token version {self.pagination_token.context.version}"
                )
            self.current_version = self.pagination_token.context.version

        if self.encrypted and not self.encryption_client:
            raise ValueError(
                "Can't encrypt pagination token without an EncryptionClient."
            )

    def get_pagination_token(self) -> PaginationToken:
        """Return the PaginationToken selected by current_version."""
        pagination_token_versions = self.pagination_token
        if isinstance(pagination_token_versions, PaginationToken):
            pagination_token_versions = [pagination_token_versions]
        versions = []
        for pagination_token in pagination_token_versions:
            versions.append(pagination_token.context.version)
            if pagination_token.context.version == self.current_version:
                return pagination_token
        raise RuntimeError(
            f"Unknown pagination token version {self.current_version}, known versions are {', '.join(versions)}"
        )

    def encode(self) -> str:
        """Encode the pagination token and context into an opaque string.

        The string is formatted with a version identifier, followed by a dash, followed by the contents.
        Having a version outside the serialization allows the serialization itself to be changed with
        versions. This isn't hugely important, it's unlikely to change from (URL-safe) base64.
        Instead of `version-base64(data)` we could have used `base64(version-data)`. But imagine that
        we had used the standard base64 encoding, and the token was only passed in the body of requests
        and responses, and then later we decided to allow it as a query parameter. Now switching to the
        URL-safe base64 alphabet becomes useful. Sure, we could track that it came in as a parameter and
        pass that in to this code, or attempt one and then the other, but having a version on the outside
        simplifies it significantly.

        Currently we use the version to distinguish between unencrypted (version 1) and encrypted (version 2).
        """
        pagination_token = self.get_pagination_token()
        if self.encrypted:
            return "2-" + _encode_encrypted_pagination_token(
                self.encryption_client, pagination_token
            )
        else:
            return "1-" + _encode_plaintext_pagination_token(pagination_token)


@dataclass
class PaginationTokenDecoder:
    encoded_pagination_token: str
    pagination_token_context: Union[
        PaginationTokenContext, list[PaginationTokenContext]
    ]
    require_encrypted: bool
    max_age: Optional[timedelta]
    disable_context_validation: bool = False
    encryption_client: EncryptionClient = None
    time_fetcher: Callable[[], datetime] = _now  # allow tests to mock out time

    def get_pagination_token_context_versions(self) -> list[PaginationTokenContext]:
        if isinstance(self.pagination_token_context, PaginationTokenContext):
            return [self.pagination_token_context]
        else:
            return self.pagination_token_context

    def decode(self) -> PaginationToken:
        encoded_pagination_token_string = self.encoded_pagination_token
        # use maxsplit so it'll either have two parts (if the - is present)
        # or one part (if it's missing)
        parts = encoded_pagination_token_string.split("-", maxsplit=1)
        if len(parts) == 1:
            raise PaginationTokenError(f"No version ID.")
        version, encoded_pagination_token = parts
        if version == "1":
            if self.require_encrypted:
                raise PaginationTokenError(
                    f"Plaintext token given but encryption required.",
                )
            try:
                pagination_token = _decode_plaintext_pagination_token(
                    encoded_pagination_token
                )
            except api_utils.APIErrorResponse:
                # This is all the errors we've planned for.
                raise
            except Exception as e:
                # When decoding, we don't want a maliciously crafted token to cause a 500,
                # revealing that it's an error we haven't handled.
                # So we wrap them all up as invalid token errors, which are 400.
                # Note that plaintext tokens can have the actual inner pagination token,
                # the exclusive start key for DynamoDB, crafted by the caller, which we
                # can't handle here.
                # TODO: log that it's a problem we're here
                raise PaginationTokenError(
                    f"Unexpected error {type(e).__name__}: {str(e)}"
                )
        elif version == "2":
            if not self.encryption_client:
                raise PaginationTokenError(
                    f"Encrypted token given but no encryption client provided.",
                )
            try:
                pagination_token = _decode_encrypted_pagination_token(
                    self.encryption_client,
                    encoded_pagination_token,
                )
            except api_utils.APIErrorResponse:
                # This is all the errors we've planned for.
                raise
            except Exception as e:
                # When decoding, we don't want a maliciously crafted token to cause a 500,
                # revealing that it's an error we haven't handled.
                # So we wrap them all up as invalid token errors, which are 400.
                # For encrypted tokens, the method used by the AWS Encryption SDK also
                # provides integrity checking, we know that the contents haven't been modified.
                # So if we're able to decode it, the actual inner pagination token,
                # the exclusive start key for DynamoDB, should not cause us any trouble.
                # TODO: log that it's a problem we're here
                raise PaginationTokenError(
                    f"Unexpected error {type(e).__name__}: {str(e)}"
                )
        else:
            raise PaginationTokenError(f"Invalid version ID {version}.")

        if not self.disable_context_validation:
            pagination_token.context.validate(
                self.get_pagination_token_context_versions(),
            )

        if self.max_age is not None:
            now = self.time_fetcher()
            token_age = now - pagination_token.context.issued_at
            if token_age > self.max_age:
                raise PaginationTokenError(
                    f"Token age {isoformat(token_age)} is older than max age {isoformat(self.max_age)}"
                )

        return pagination_token
