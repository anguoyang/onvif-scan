"""Offline comparison of schema-1 inventories, limited to seven field classes.

Inputs are the scrubbed JSON inventories produced by scan. No credentials,
transport, discovery or report serialization belong in this module.
"""
import json


def load_inventory(path):
    """Use the standard JSON loader; reject invalid inputs without echoing data."""
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    if (not isinstance(report, dict) or type(report.get("schema")) is not int
            or report["schema"] != 1 or report.get("kind") != "onvif_inventory"):
        raise ValueError("%s: expected schema == 1 and kind == onvif_inventory" % path)
    try:
        _index(report)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise ValueError("%s: invalid devices or duplicate/missing device identity" % path) from exc
    return report


def _scalar(value, expected):
    if value is not None and type(value) not in expected:
        raise ValueError("invalid compared field type")
    return value


def _fields(device):
    info = device.get("device_info") or {}
    profiles = {
        (_scalar(p.get("token"), (str,)), _scalar(p.get("media_gen"), (int,)))
        for p in device.get("profiles", [])
    }
    codes = {_scalar(f.get("code"), (str,)) for f in device.get("findings", [])}
    namespaces = {_scalar(s.get("namespace"), (str,))
                  for s in device.get("services_declared") or []}
    source_tokens = {_scalar(s.get("token"), (str,))
                     for s in device.get("sources") or []}
    return {
        "device_info.FirmwareVersion": _scalar(info.get("FirmwareVersion"), (str,)),
        "level": _scalar(device.get("level"), (str,)),
        # Stable set representation, retaining the generation paired with its token.
        "profiles": [{"token": token, "media_gen": gen}
                     for token, gen in sorted(profiles, key=lambda p: (
                         p[0] is not None, p[0] or "", p[1] is not None, p[1] or 0))],
        "channel_count": _scalar(device.get("channel_count"), (int,)),
        "findings.code": sorted(c for c in codes if c is not None),
        "services_declared.namespace": sorted(n for n in namespaces if n is not None),
        "sources": sorted(t for t in source_tokens if t is not None),
    }


def _index(report):
    devices = report["devices"]
    if not isinstance(devices, list):
        raise ValueError("devices must be an array")
    indexed = {}
    for device in devices:
        mac = _scalar(device.get("mac"), (str,))
        basis = "mac" if mac else "ip"
        key = mac.lower() if mac else _scalar(device.get("ip"), (str,))
        identity = (basis, key)
        if not key or identity in indexed:
            raise ValueError("duplicate or missing device identity")
        indexed[identity] = _fields(device)
    return indexed


def compare_inventories(old, new):
    """Return deterministic changes; IP moves do not change a MAC identity."""
    before, after = _index(old), _index(new)
    result = {
        "added": [key for basis, key in sorted(after.keys() - before.keys())],
        "removed": [key for basis, key in sorted(before.keys() - after.keys())],
        "changed": [], "unchanged": 0,
    }
    for identity in sorted(before.keys() & after.keys()):
        changes = [{"field": field, "old": value, "new": after[identity][field]}
                   for field, value in before[identity].items()
                   if value != after[identity][field]]
        if changes:
            basis, key = identity
            result["changed"].append({"key": key, "identity_basis": basis, "changes": changes})
        else:
            result["unchanged"] += 1
    return result
