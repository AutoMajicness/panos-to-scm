"""SCM setup helpers for migration target folders and snippets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scm import ApiRequestError


FOLDERS_ENDPOINT = "/config/setup/v1/folders"
SNIPPETS_ENDPOINT = "/config/setup/v1/snippets"
VIRTUAL_ROOT_NAMES = {"all firewalls", "ngfw-shared", "all", "root"}


@dataclass(frozen=True)
class SetupTargetRequest:
    folder_name: str
    snippet_name: str
    parent_folder: str = "ngfw-shared"
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
        actions.append({"resource": "snippet", "name": request.snippet_name, "action": snippet.get("status", "created")})
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


def list_setup_entries(api_handler, endpoint: str) -> list[dict[str, Any]]:
    """Return setup resources used to build the folder hierarchy."""
    entries = api_handler.get(endpoint, params={"limit": 2000, "offset": 0})
    if isinstance(entries, dict):
        entries = entries.get("data", [])
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _resource_id(resource: dict[str, Any] | None) -> str:
    return str((resource or {}).get("id") or "").strip()


def _parent_reference(resource: dict[str, Any]) -> str:
    parent = resource.get("parent", "")
    if isinstance(parent, dict):
        return str(parent.get("id") or parent.get("name") or "").strip()
    return str(parent or "").strip()


def _folder_path(resource: dict[str, Any], by_id: dict[str, dict[str, Any]], by_name: dict[str, list[dict[str, Any]]]):
    """Build a folder path and chain, detecting broken or cyclic ancestry."""
    chain = []
    seen = set()
    current = resource
    while current:
        current_id = _resource_id(current) or f"name:{current.get('name')}"
        if current_id in seen:
            raise ValueError(f"Cyclic SCM folder ancestry detected at '{current.get('name', current_id)}'")
        seen.add(current_id)
        chain.append(current)
        parent_ref = _parent_reference(current)
        if not parent_ref:
            break
        parent = by_id.get(parent_ref)
        if parent is None:
            if parent_ref.casefold() in VIRTUAL_ROOT_NAMES:
                break
            candidates = by_name.get(parent_ref, [])
            if len(candidates) == 1:
                parent = candidates[0]
        if parent is None:
            raise ValueError(
                f"Unable to resolve parent '{parent_ref}' for SCM folder '{current.get('name', current_id)}'"
            )
        current = parent
    chain.reverse()
    return "/".join(str(item.get("name", "")) for item in chain), chain


def resolve_folder_hierarchy(
    api_handler,
    *,
    folder_name: str = "",
    folder_path: str = "",
    folder_id: str = "",
    interactive: bool = False,
) -> dict[str, Any]:
    """Resolve an SCM folder by ID, full path, or name."""
    if not any((folder_name, folder_path, folder_id)):
        raise ValueError("folder_name, folder_path, or folder_id is required")

    folders = list_setup_entries(api_handler, FOLDERS_ENDPOINT)
    by_id = {_resource_id(folder): folder for folder in folders if _resource_id(folder)}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for folder in folders:
        by_name.setdefault(str(folder.get("name", "")), []).append(folder)

    candidates = []
    for folder in folders:
        path, chain = _folder_path(folder, by_id, by_name)
        if folder_id and _resource_id(folder) == folder_id:
            candidates.append((path, chain))
        elif folder_path:
            requested_path = folder_path.strip("/")
            path_aliases = {path}
            if not path.casefold().startswith("all firewalls/"):
                path_aliases.add(f"All Firewalls/{path}")
            if requested_path.casefold() in {alias.casefold() for alias in path_aliases}:
                candidates.append((path, chain))
        elif folder_name and folder.get("name") == folder_name:
            candidates.append((path, chain))

    if not candidates:
        selector = folder_id or folder_path or folder_name
        raise ValueError(f"SCM folder '{selector}' was not found")
    if len(candidates) > 1:
        if not interactive:
            paths = ", ".join(path for path, _ in candidates)
            raise ValueError(
                f"SCM folder name '{folder_name}' is ambiguous. Choose one of: {paths}; "
                "use --folder-path or --folder-id."
            )
        print("Multiple SCM folders matched:")
        for index, (path, _) in enumerate(candidates, 1):
            print(f"  {index}. {path}")
        choice = input(f"Select a folder [1-{len(candidates)}]: ").strip()
        try:
            selected_index = int(choice) - 1
            path, chain = candidates[selected_index]
        except (ValueError, IndexError) as err:
            raise ValueError("Invalid SCM folder selection") from err
    else:
        path, chain = candidates[0]

    selected_id = _resource_id(chain[-1])
    selected_path_ids = [_resource_id(item) for item in chain]
    descendants = []
    for folder in folders:
        candidate_path, candidate_chain = _folder_path(folder, by_id, by_name)
        candidate_ids = [_resource_id(item) for item in candidate_chain]
        if candidate_ids[: len(selected_path_ids)] == selected_path_ids:
            descendants.append((candidate_path, candidate_chain))

    descendants.sort(key=lambda item: (len(item[1]), item[0]))
    return {
        "path": path,
        "folder": _resource_summary(chain[-1]),
        "folders": [_resource_summary(item) for item in chain],
        "folder_names": [str(item.get("name", "")) for item in chain],
        "folder_ids": [_resource_id(item) for item in chain],
        "descendant_folders": [
            {
                "path": descendant_path,
                "folders": [_resource_summary(item) for item in descendant_chain],
                "folder_names": [str(item.get("name", "")) for item in descendant_chain],
                "folder_ids": [_resource_id(item) for item in descendant_chain],
            }
            for descendant_path, descendant_chain in descendants
        ],
    }


def resolve_folder_snippets(api_handler, folder_name: str) -> dict[str, Any]:
    """Resolve the ordered snippets associated with an SCM folder.

    SCM has returned both simple snippet-name lists and association objects in
    different API responses.  Normalize both forms while retaining the raw
    folder record for diagnostics and provenance.
    """
    if not folder_name:
        raise ValueError("folder_name is required")

    folder = find_setup_entry(api_handler, FOLDERS_ENDPOINT, folder_name)
    if not folder:
        raise ValueError(f"SCM folder '{folder_name}' was not found")

    return resolve_snippets_from_folder(folder)


def resolve_snippets_from_folder(folder: dict[str, Any]) -> dict[str, Any]:
    """Normalize snippets directly associated with an already resolved folder."""
    associations = folder.get("snippets", [])
    if isinstance(associations, dict):
        associations = associations.get("data", associations.get("items", []))
    if not isinstance(associations, list):
        associations = [associations] if associations else []

    snippets = []
    for index, association in enumerate(associations):
        if isinstance(association, str):
            name = association.strip()
            priority = None
        elif isinstance(association, dict):
            name = (
                association.get("name")
                or association.get("snippet")
                or association.get("snippet_name")
                or association.get("id")
            )
            priority = association.get("priority")
        else:
            name = None
            priority = None
        if not name:
            continue
        snippets.append({"name": str(name), "priority": priority, "order": index})

    # The API response order is the effective order.  If explicit numeric
    # priorities are supplied, sort highest priority first while preserving
    # response order for equal or missing priorities.
    if any(item["priority"] is not None for item in snippets):
        snippets.sort(
            key=lambda item: (
                item["priority"] is None,
                -(item["priority"] if isinstance(item["priority"], (int, float)) else 0),
                item["order"],
            )
        )

    # Avoid issuing duplicate requests if SCM repeats an association.
    unique = []
    seen = set()
    for item in snippets:
        if item["name"] in seen:
            continue
        seen.add(item["name"])
        unique.append(item)

    return {
        "folder": _resource_summary(folder),
        "snippets": unique,
        "snippet_names": [item["name"] for item in unique],
    }


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
    summary = {
        key: resource[key]
        for key in ("id", "name", "parent", "type", "status", "snippets")
        if key in resource
    }
    return summary
