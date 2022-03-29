from typing import Optional


def get_caller_identity(event: dict) -> Optional[str]:
    """Extract the caller identity from the event"""
    if "requestContext" not in event or "identity" not in event["requestContext"]:
        return None
    user = event["requestContext"]["identity"].get("user")
    return user


def get_api_id(event: dict) -> Optional[str]:
    """Extract the API ID from the event"""
    if "requestContext" not in event:
        return None
    return event["requestContext"].get("apiId")


def get_path(event: dict) -> Optional[str]:
    """Extract the path from the event"""
    return event.get("path")
