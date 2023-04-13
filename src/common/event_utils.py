# Copyright 2023 Ben Kehoe
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

from typing import Optional


def get_caller_identity(event: dict) -> Optional[str]:
    """Extract the caller identity from the event.

    This will only return a value when using IAM auth.
    """
    if "requestContext" not in event or "identity" not in event["requestContext"]:
        return None
    user = event["requestContext"]["identity"].get("user")
    return user


def get_api_id(event: dict) -> Optional[str]:
    """Extract the API ID from the event."""
    if "requestContext" not in event:
        return None
    return event["requestContext"].get("apiId")


def get_path(event: dict) -> Optional[str]:
    """Extract the path from the event."""
    return event.get("path")
