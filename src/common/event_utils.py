import json
import hashlib

from pagination import PaginationEncryptionContext


def get_user(event):
    # Customize this to use the appropriate identity field for your authorizer.
    return ((event.get("requestContext") or {}).get("identity") or {}).get("user") or ""


# Create an encryption context for the pagination token. This implementation
# uses a combination of principal, API ID, and the path being requested, so that
# tokens cannot be used by someone else or on a different API endpoint. The chance
# of a token re-use attack being successful is slim, but this should eliminate the
# risk entirely.
def pagination_token_encryption_context_for_event(event) -> PaginationEncryptionContext:
    # WARNING: changing this calculation is a breaking change; any outstanding pagination
    # tokens will not be able to be decrypted because the AAD verification will fail.
    # If you want to safely and smoothly upgrade, you will need to implement a versioning
    # mechanism for the context data.
    context_parts = {
        # Ensure that a token issued for one user can't be used by another user.
        "user": get_user(event),

        # Ensure that tokens issued for one API can't be used in another API
        "api_id": (event.get("requestContext") or {}).get("apiId") or "",

        # Ensure that a token issued for one resource type / path can't be used for
        # another resource type.
        "path": event.get("path") or "",
    }

    # A casual observer might wonder why we're using the digest here instead of returning
    # the `context_parts` directly. Congratulations! Today you get to learn that the
    # AWS Encryption SDK includes the encryption context in the "ciphertext". Surprise!
    # The values we are using are not necessarily particularly sensitive, but in the
    # interests of not exposing anything we don't have to, we'll return a digest instead.
    #
    # https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-structure

    m = hashlib.sha256()
    m.update(json.dumps(context_parts, sort_keys=True))

    return PaginationEncryptionContext({ "d": m.hexdigest() })
