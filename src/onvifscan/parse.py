"""Parsers for ONVIF SOAP responses.

Field devices are sloppy: unbound prefixes, missing namespace
declarations, vendor-specific element order. safe_parse() retries with
prefixes stripped; every parser matches on local element names only and
returns None/empty rather than raising, so one malformed device can
never break a whole scan.
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse


def local(el):
    return el.tag.split("}")[-1]


def safe_parse(xml):
    """(root, malformed_flag). root is None if unparseable even loosely."""
    try:
        return ET.fromstring(xml), False
    except ET.ParseError:
        pass
    cleaned = re.sub(r'\sxmlns:[a-zA-Z0-9]+="[^"]*"', "", xml)
    cleaned = re.sub(r"(</?)[a-zA-Z0-9]+:", r"\1", cleaned)
    cleaned = re.sub(r"\s[a-zA-Z0-9]+:([a-zA-Z]+)=", r" \1=", cleaned)
    try:
        return ET.fromstring(cleaned), True
    except ET.ParseError:
        return None, True


def texts(root, suffix):
    return [(el.text or "").strip() for el in root.iter() if local(el) == suffix]


def first_text(root, suffix):
    vals = texts(root, suffix)
    return vals[0] if vals and vals[0] else None


def parse_scopes(scopes_str):
    """Split the space-separated Scopes URIs into structured fields."""
    out = {"profiles": [], "name": None, "hardware": None, "mac": None,
           "location": None, "raw": scopes_str or ""}
    for tok in (scopes_str or "").split():
        low = tok.lower()
        if "/profile/" in low:
            out["profiles"].append(tok.rsplit("/", 1)[-1])
        elif "/name/" in low:
            out["name"] = unquote(tok.split("/name/", 1)[-1])
        elif "/hardware/" in low:
            out["hardware"] = unquote(tok.split("/hardware/", 1)[-1])
        elif "/mac/" in low:
            out["mac"] = unquote(tok.split("/mac/", 1)[-1]).lower()
        elif "/location/" in low:
            out["location"] = unquote(tok.split("/location/", 1)[-1])
    return out


def parse_system_datetime(xml):
    root, malformed = safe_parse(xml)
    if root is None:
        return None, malformed
    udt = None
    for el in root.iter():
        if local(el) == "UTCDateTime":
            udt = el
            break
    if udt is None:
        return None, malformed
    vals = {}
    for el in udt.iter():
        vals[local(el)] = el.text
    try:
        return datetime(int(vals["Year"]), int(vals["Month"]), int(vals["Day"]),
                        int(vals["Hour"]), int(vals["Minute"]), int(vals["Second"]),
                        tzinfo=timezone.utc), malformed
    except (KeyError, TypeError, ValueError):
        return None, True


_SERVICE_KEYS = {"Device": "device", "Media": "media", "Media2": "media2",
                 "PTZ": "ptz", "Events": "events", "Imaging": "imaging",
                 "Analytics": "analytics", "Recording": "recording",
                 "Search": "search", "Replay": "replay"}


def parse_capabilities(xml):
    """{service_key: xaddr} from a GetCapabilities response."""
    root, malformed = safe_parse(xml)
    services = {}
    if root is None:
        return services, malformed
    for el in root.iter():
        key = _SERVICE_KEYS.get(local(el))
        if key and key not in services:
            for sub in el.iter():
                if local(sub) == "XAddr" and sub.text:
                    services[key] = sub.text.strip()
                    break
    return services, malformed


_NS_TO_KEY = {"ver10/media": "media", "ver20/media": "media2",
              "ver20/ptz": "ptz", "ver10/ptz": "ptz", "ver10/device": "device",
              "ver10/events": "events", "ver20/imaging": "imaging",
              "ver10/recording": "recording"}


def parse_services(xml):
    """Return (routing dict, full declarations | None, malformed).

    Routes retain the first known XAddr per service class. Declarations retain
    every Service in response order, including unknown/duplicate/incomplete
    entries. None means no usable GetServices response; [] means success empty.
    Version components come only from Version, never from a namespace URI.
    """
    root, malformed = safe_parse(xml)
    services = {}
    if root is None:
        return services, None, malformed
    response = next((el for el in root.iter() if local(el) == "GetServicesResponse"), None)
    if response is None:
        return services, None, True
    declared = []
    for el in response:
        if local(el) != "Service":
            continue
        fields = {local(child): child for child in el}
        ns = first_text(fields["Namespace"], "Namespace") if "Namespace" in fields else None
        xaddr = first_text(fields["XAddr"], "XAddr") if "XAddr" in fields else None
        missing = [key for key, value in (("namespace", ns), ("xaddr", xaddr)) if value is None]
        invalid = []
        version = fields.get("Version")
        values = {local(child): (child.text or "").strip() for child in version} if version is not None else {}
        parsed_version = {}
        for key in ("Major", "Minor"):
            raw = values.get(key)
            value = None
            field = "version." + key.lower()
            if not raw:
                missing.append(field)
            else:
                try:
                    value = int(raw)
                    if value < 0:
                        raise ValueError
                except ValueError:
                    invalid.append(field)
                    malformed = True
                    value = None
            parsed_version[key.lower()] = value
        declared.append({"namespace": ns, "xaddr": redact_uri(xaddr),
                         "version": parsed_version, "missing_fields": missing,
                         "invalid_fields": invalid})
        if xaddr:
            for frag, key in _NS_TO_KEY.items():
                if frag in (ns or "") and key not in services:
                    services[key] = xaddr
    return services, declared, malformed


def parse_device_info(xml):
    root, malformed = safe_parse(xml)
    if root is None:
        return None, malformed
    info = {k: first_text(root, k) for k in
            ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId")}
    if all(v is None for v in info.values()):
        return None, malformed
    return info, malformed


def parse_network_interfaces(xml):
    """First interface's MAC + IPv4 (manual config preferred, else DHCP info)."""
    root, malformed = safe_parse(xml)
    if root is None:
        return None, malformed
    for el in root.iter():
        if local(el) != "NetworkInterfaces":
            continue
        mac = first_text(el, "HwAddress")
        addr = first_text(el, "Address")
        prefix = first_text(el, "PrefixLength")
        return {"mac": mac.lower() if mac else None,
                "ipv4": addr,
                "prefix": int(prefix) if prefix and prefix.isdigit() else None}, malformed
    return None, malformed


def parse_hostname(xml):
    root, _m = safe_parse(xml)
    if root is None:
        return None
    return first_text(root, "Name")


def _profile_from_element(el):
    p = {"token": el.get("token"), "name": first_text(el, "Name"),
         "source_token": None, "codec": None, "width": None, "height": None,
         "video_source_token": None, "encoder_configuration_token": None,
         "ptz_configuration_token": None, "ptz_node_token": None,
         "fps_limit": None, "bitrate_limit_kbps": None, "ptz_config": False}
    # Media1 has direct *Configuration children; Media2 uses Configurations.
    # Keep accepting the old Media1-shaped Media2 responses as well.
    configs = list(el)
    for child in el:
        if local(child) == "Configurations":
            configs.extend(child)
    for sub in configs:
        name = local(sub)
        if name in ("VideoSourceConfiguration", "VideoSource"):
            # Schema 1 compatibility: source_token is the configuration token.
            p["source_token"] = sub.get("token")
            p["video_source_token"] = sub.get("SourceToken") or first_text(sub, "SourceToken")
        elif name in ("VideoEncoderConfiguration", "VideoEncoder"):
            p["encoder_configuration_token"] = sub.get("token")
        elif name in ("PTZConfiguration", "PTZ"):
            p["ptz_config"] = True
            p["ptz_configuration_token"] = sub.get("token")
            p["ptz_node_token"] = first_text(sub, "NodeToken")
    for sub in el.iter():
        name = local(sub)
        if name == "Encoding" and p["codec"] is None:
            p["codec"] = (sub.text or "").strip() or None
        elif name == "Width":
            try:
                p["width"] = int(sub.text)
            except (TypeError, ValueError):
                pass
        elif name == "Height":
            try:
                p["height"] = int(sub.text)
            except (TypeError, ValueError):
                pass
        elif name == "FrameRateLimit":
            try:
                p["fps_limit"] = int(float(sub.text))
            except (TypeError, ValueError):
                pass
        elif name in ("BitrateLimit", "AverageBitrateLimit"):
            try:
                p["bitrate_limit_kbps"] = int(float(sub.text))
            except (TypeError, ValueError):
                pass
    return p


def parse_profiles(xml, media_gen):
    root, malformed = safe_parse(xml)
    profiles = []
    if root is None:
        return profiles, malformed
    for el in root.iter():
        if local(el) == "Profiles" and el.get("token") is not None:
            prof = _profile_from_element(el)
            prof["media_gen"] = media_gen
            prof["stream_uri"] = None
            prof["snapshot_uri"] = None
            profiles.append(prof)
    return profiles, malformed


def parse_stream_uri(xml):
    root, _m = safe_parse(xml)
    if root is None:
        return None
    return first_text(root, "Uri")


def redact_uri(uri):
    """Mask any password in a URI's userinfo. Usernames are kept (they are
    routinely part of an inventory); passwords never appear in output."""
    if not uri:
        return uri
    try:
        parts = urlparse(uri)
    except ValueError:
        return uri
    if parts.password:
        userinfo = (parts.username or "") + ":***"
        host = parts.hostname or ""
        netloc = userinfo + "@" + host
        if parts.port:
            netloc += ":%d" % parts.port
        return parts._replace(netloc=netloc).geturl()
    return uri
