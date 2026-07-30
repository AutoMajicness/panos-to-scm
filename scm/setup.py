"""SCM setup helpers for migration target folders and snippets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scm import ApiRequestError


FOLDERS_ENDPOINT = "/config/setup/v1/folders"
SNIPPETS_ENDPOINT = "/config/setup/v1/snippets"


@dataclass(frozen=True)
class SetupTargetRequest:
    folder_name: str
    snippet_name: str
    parent_folder: str = "All"
    associate_snippet: bool = True
    create: bool = False


def ensure_setup_target(api_handler, request: SetupTargetRequest) -> dict[str, Any]:
    """Check or create the SCM folder/snippet pair used by a local firewall migration."""

    if not request.folder_name:
        raise ValueError("folder_name is required")
    if not request.snippet_name:
        raise ValueError("snippet_name is required")

    existing_snippet = find_setup_entry(api_handler, SNIPPETS_ENDPOINT, request.snippet_name)
    existing_folder = find_setup_entry(api_handler, FOLDERS_ENDPOINT, request.folder_name)

    actions: list[dict[str, Any]] = []
    snippet = existing_snippet
    folder = existing_folder

    if snippet:
        actions.append({"resource": "snippet", "name": request.snippet_name, "action": "exists"})
    elif request.create:
        snippet = create_snippet(api_handler, request.snippet_name)
        actions.append({"resource": "snippet", "name": request.snippet_name, "action": "created"})
    else:
        actions.append({"resource": "snippet", "name": request.snippet_name, "action": "missing"})

    if folder:
        actions.append({"resource": "folder", "name": request.folder_name, "action": "exists"})
    elif request.create:
        folder = create_folder(
            api_handler,
            request.folder_name,
            request.parent_folder,
            snippet_name=request.snippet_name if request.associate_snippet else "",
        )
        actions.append({"resource": "folder", "name": request.folder_name, "action": "created"})
    else:
        actions.append({"resource": "folder", "name": request.folder_name, "action": "missing"})

    return {
        "summary": {
            "create_enabled": request.create,
            "ready": bool(snippet and folder),
            "missing": [
                action["resource"]
                for action in actions
                if action["action"] == "missing"
            ],
        },
        "target": {
            "folder": request.folder_name,
            "snippet": request.snippet_name,
            "parent_folder": request.parent_folder,
            "associate_snippet": request.associate_snippet,
        },
        "scopes": {
            "object_scope": f"folder:{request.folder_name}",
            "policy_scope": f"folder:{request.folder_name}",
            "network_scope": f"snippet:{request.snippet_name}",
        },
        "actions": actions,
        "resources": {
            "folder": _resource_summary(folder),
            "snippet": _resource_summary(snippet),
        },
    }


def find_setup_entry(api_handler, endpoint: str, name: str) -> dict[str, Any] | None:
    try:
        entries = api_handler.get(endpoint, params={"name": name, "limit": 200, "offset": 0})
    except ApiRequestError as err:
        if "Status Code: 404" in str(err):
            return None
        raise
    if isinstance(entries, dict):
        entries = entries.get("data", [])
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name") == name:
            return entry
    return None


def create_snippet(api_handler, name: str) -> dict[str, Any]:
    payload = {
        "name": name,
        "description": "Created by panos-to-scm local firewall migration setup.",
    }
    result = api_handler.post(SNIPPETS_ENDPOINT, payload)
    if result.get("status") not in {"created", "exists"}:
        raise RuntimeError(f"Failed to create snippet '{name}': {result}")
    return {"name": name, "status": result.get("status")}


def create_folder(api_handler, name: str, parent: str, snippet_name: str = "") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "parent": parent,
        "description": "Created by panos-to-scm local firewall migration setup.",
    }
    if snippet_name:
        payload["snippets"] = [snippet_name]

    result = api_handler.post(FOLDERS_ENDPOINT, payload)
    if result.get("status") not in {"created", "exists"}:
        raise RuntimeError(f"Failed to create folder '{name}': {result}")
    return {"name": name, "parent": parent, "status": result.get("status")}


def _resource_summary(resource: dict[str, Any] | None) -> dict[str, Any] | None:
    if not resource:
        return None
    return {
        key: resource[key]
        for key in ("id", "name", "parent", "type", "status")
        if key in resource
    }
