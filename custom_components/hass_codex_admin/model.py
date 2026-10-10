"""Versioned, finite administrator operations. No network or activation on import."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

DOMAIN = "hass_codex_admin"
HELPERS = {"input_boolean", "input_number", "input_text", "input_select", "input_datetime", "input_button", "counter", "timer"}
FAMILIES = {"automation", "script", "dashboard", "integration", "service", "maintenance"} | HELPERS
SERVICES = {"light.turn_on", "light.turn_off", "switch.turn_on", "switch.turn_off", "cover.open_cover", "cover.close_cover", "media_player.media_play", "media_player.media_pause"}
MAINTENANCE = {"homeassistant.check_config", "homeassistant.reload_core_config", "homeassistant.restart", "backup.create", "hassio.addon_restart", "hassio.addon_update", "hassio.backup_full"}
SECRET_KEYS = re.compile(r"password|token|secret|api_key|authorization|credential", re.I)


class AdminError(Exception):
    """A stable sanitized error code; never return a raw backend exception."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise AdminError("invalid_json") from None
    if len(raw.encode()) > 131072:
        raise AdminError("payload_too_large")
    return raw


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AdminError("duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(AdminError("invalid_json")))
    except (ValueError, TypeError, RecursionError):
        raise AdminError("invalid_json") from None


def redact(value):
    if isinstance(value, dict):
        return {k: "[redacted]" if SECRET_KEYS.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"(?i)(Bearer\s+|(?:password|token|api_key|secret)\s*[=:]\s*)\S+", r"\1[redacted]", value)
    return value


@dataclass(frozen=True)
class Actor:
    user: str
    session: str
    bearer: str = field(repr=False, compare=False)


def operation(value):
    if not isinstance(value, dict) or set(value) != {"family", "action", "target", "value"}:
        raise AdminError("operation_schema")
    op = decode(canonical(value))
    family, action, target, data = (op[k] for k in ("family", "action", "target", "value"))
    if type(family) is not str or type(action) is not str or family not in FAMILIES or type(target) is not str or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,100}", target):
        raise AdminError("unsupported_operation")
    if family in {"service", "maintenance"}:
        catalog = SERVICES if family == "service" else MAINTENANCE
        if action != "call" or target not in catalog or not isinstance(data, dict):
            raise AdminError("unsupported_service")
        if family == "service":
            if set(data) != {"entity_ids", "data"} or not isinstance(data["data"], dict) or not isinstance(data["entity_ids"], list) or not 1 <= len(data["entity_ids"]) <= 20:
                raise AdminError("explicit_entities_required")
            if any(type(e) is not str or not re.fullmatch(r"[a-z_]+\.[a-z0-9_]+", e) or e.split(".")[0] != target.split(".")[0] for e in data["entity_ids"]) or len(set(data["entity_ids"])) != len(data["entity_ids"]):
                raise AdminError("entity_scope_mismatch")
            if {"entity_id", "area_id", "device_id", "floor_id", "label_id"} & set(data["data"]):
                raise AdminError("selector_injection")
            allowed = {"brightness", "color_temp_kelvin"} if target == "light.turn_on" else set()
            if set(data["data"]) - allowed:
                raise AdminError("service_argument_verifier_not_supported")
            for key, number in data["data"].items():
                low, high = (1, 255) if key == "brightness" else (1000, 10000)
                if type(number) is not int or not low <= number <= high:
                    raise AdminError("device_argument_range")
        elif target.startswith("hassio.addon_"):
            if set(data) != {"addon"} or not re.fullmatch(r"[a-z0-9_]+", str(data["addon"])):
                raise AdminError("exact_addon_required")
        elif data:
            raise AdminError("maintenance_arguments")
    elif family == "integration":
        if action != "reload" or data != {} or not re.fullmatch(r"(?:[A-Z0-9]{26}|[a-f0-9]{32})", target):
            raise AdminError("integration_schema")
    elif action not in {"create", "put", "delete"} or (action == "delete" and data is not None) or (action != "delete" and not isinstance(data, dict)):
        raise AdminError("configuration_schema")
    if family not in {"service", "maintenance"} and "." in target:
        raise AdminError("invalid_object_id")
    if action != "delete" and family in HELPERS and ({"type", "id", "entity_id", family+"_id"} & set(data)):
        raise AdminError("helper_reserved_argument")
    if family == "automation" and action != "delete" and "id" in data:
        raise AdminError("automation_id_is_target")
    if family in HELPERS and action == "create":
        # HA allocates the helper ID from its name. Approval includes the name
        # and expected ID; collisions remain uncertain, never an alias fallback.
        name = data.get("name")
        if type(name) is not str or re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") != target:
            raise AdminError("helper_name_id_mismatch")
    if family == "dashboard" and action != "delete":
        if not {"title", "config"} <= set(data) or set(data) - {"title", "config", "icon", "show_in_sidebar", "require_admin"} or type(data["title"]) is not str or not isinstance(data["config"], dict):
            raise AdminError("dashboard_schema")
        if any(key in data and type(data[key]) is not bool for key in ("show_in_sidebar", "require_admin")):
            raise AdminError("dashboard_schema")
        if action == "create":
            data.setdefault("show_in_sidebar", True)
            data.setdefault("require_admin", True)
    return op


def effects(op):
    """Do not treat configuration names as proof of their indirect effects."""
    if op["action"] == "delete":
        return "destructive", ["Delete exact object; inspect references and approve restoration scope."]
    if op["family"] in {"automation", "script", "dashboard"}:
        return "elevated", ["Configuration may invoke services, scripts, templates or dashboard actions later. Review the complete definition; no ordinary-device grant applies."]
    if op["family"] in HELPERS:
        return "elevated", ["Helper changes can trigger existing automations; review references and stored definition."]
    if op["family"] in {"integration", "maintenance"}:
        return "elevated", ["Administrative operation may interrupt service or alter the installed system."]
    return "elevated", ["Exact named device service and arguments only; a device may affect household security. Owner must review the actual entities and effects."]
