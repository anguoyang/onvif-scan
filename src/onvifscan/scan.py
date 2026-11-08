"""Per-device inventory: the frozen flow from SPEC.md section 2.

B1 GetSystemDateAndTime (no auth) -> device clock offset
B2 GetCapabilities / GetServices -> service XAddrs
B3 GetDeviceInformation (no auth first; credentialed retry once)
B4 GetHostname / GetNetworkInterfaces (when auth state allows)
B5 Media/Media2 GetProfiles + GetStreamUri / GetSnapshotUri per profile
B6 PTZ node declarations and per-profile preset counts/names (read-only)
B7 XAddr host mismatch -> fall back to the discovery source IP

Credential discipline: one user-supplied credential per device, with no
credentialed calls after rejection (NotAuthorized or bare HTTP 401).
"""
import ipaddress
from xml.sax.saxutils import escape
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import parse as P
from .soap import fault_kind, is_fault, soap_call

TDS = "http://www.onvif.org/ver10/device/wsdl"
TRT = "http://www.onvif.org/ver10/media/wsdl"
TR2 = "http://www.onvif.org/ver20/media/wsdl"
TPTZ = "http://www.onvif.org/ver20/ptz/wsdl"

BODY_TIME = '<tds:GetSystemDateAndTime xmlns:tds="%s"/>' % TDS
BODY_CAPS = ('<tds:GetCapabilities xmlns:tds="%s"><tds:Category>All</tds:Category>'
             '</tds:GetCapabilities>' % TDS)
BODY_SERVICES = ('<tds:GetServices xmlns:tds="%s"><tds:IncludeCapability>false'
                 '</tds:IncludeCapability></tds:GetServices>' % TDS)
BODY_DEVINFO = '<tds:GetDeviceInformation xmlns:tds="%s"/>' % TDS
BODY_HOSTNAME = '<tds:GetHostname xmlns:tds="%s"/>' % TDS
BODY_NETIF = '<tds:GetNetworkInterfaces xmlns:tds="%s"/>' % TDS
BODY_PROFILES1 = '<trt:GetProfiles xmlns:trt="%s"/>' % TRT
BODY_NODES = '<tptz:GetNodes xmlns:tptz="%s"/>' % TPTZ
BODY_PROFILES2 = '<tr2:GetProfiles xmlns:tr2="%s"/>' % TR2


def _stream_uri_body(token, ns, tag):
    return ('<{t}:GetStreamUri xmlns:{t}="{ns}"><{t}:StreamSetup>'
            '<tt:Stream xmlns:tt="http://www.onvif.org/ver10/schema">RTP-Unicast</tt:Stream>'
            '<tt:Transport xmlns:tt="http://www.onvif.org/ver10/schema">'
            '<tt:Protocol>RTSP</tt:Protocol></tt:Transport></{t}:StreamSetup>'
            '<{t}:ProfileToken>{tok}</{t}:ProfileToken></{t}:GetStreamUri>'
            ).format(t=tag, ns=ns, tok=escape(token))


def _snapshot_uri_body(token, ns, tag):
    return ('<{t}:GetSnapshotUri xmlns:{t}="{ns}"><{t}:ProfileToken>{tok}'
            '</{t}:ProfileToken></{t}:GetSnapshotUri>').format(t=tag, ns=ns, tok=escape(token))


def _encoder_options_body(token, ns=TRT, tag="trt"):
    return ('<{t}:GetVideoEncoderConfigurationOptions xmlns:{t}="{ns}">'
            '<{t}:ConfigurationToken>{token}</{t}:ConfigurationToken>'
            '</{t}:GetVideoEncoderConfigurationOptions>').format(
                t=tag, ns=ns, token=escape(token))


def _ptz_body(operation, parameter, token):
    return ('<tptz:{op} xmlns:tptz="{ns}"><tptz:{param}>{token}</tptz:{param}>'
            '</tptz:{op}>').format(op=operation, param=parameter, ns=TPTZ, token=escape(token))


def _swap_host(url, new_host):
    parts = urlparse(url)
    if not parts.hostname or parts.hostname == new_host:
        return url
    netloc = new_host
    if parts.port:
        netloc += ":%d" % parts.port
    return parts._replace(netloc=netloc).geturl()


class _Caller:
    def __init__(self, timeout, source_ip):
        self.timeout = timeout
        self.source_ip = source_ip
        self.offset_s = 0.0
        self.cred = None
        self.auth_failed = False
        self.auth_ok = False
        self.malformed = False

    def call(self, url, body, auth=False):
        """One SOAP call; on transport failure with a differing source IP,
        retry once against the source IP (the XAddr-mismatch fallback)."""
        if auth and self.auth_failed:
            return None, "ERROR: credentialed call blocked after authentication failure"
        user = self.cred["user"] if (auth and self.cred) else None
        pw = self.cred["password"] if (auth and self.cred) else None
        status, text = soap_call(url, body, user, pw, self.offset_s, self.timeout)
        if status is None and self.source_ip:
            alt = _swap_host(url, self.source_ip)
            if alt != url:
                status, text = soap_call(alt, body, user, pw, self.offset_s, self.timeout)
        if auth and self.cred:
            if status == 200 and not is_fault(text):
                self.auth_ok = True
            elif fault_kind(text) == "NotAuthorized" or (status == 401 and not is_fault(text)):
                self.auth_failed = True
        return status, text

    def query(self, url, body, parser):
        """Status-bearing optional Get query through the same credential gate."""
        status, text = self.call(url, body, auth=bool(self.cred))
        if (self.auth_failed or fault_kind(text) == "NotAuthorized"
                or (status == 401 and not is_fault(text))):
            return {"status": "auth_blocked", "reason": "authentication rejected or blocked",
                    "data": None}
        if fault_kind(text) == "NotSupported":
            return {"status": "unsupported", "reason": "operation not supported", "data": None}
        if status != 200 or is_fault(text):
            return {"status": "failed", "reason": "request failed", "data": None}
        data, malformed = parser(text)
        self.malformed = self.malformed or malformed
        return {"status": "ok" if data is not None else "failed",
                "reason": None if data is not None else "unusable response", "data": data}


def _finding(code, severity, detail):
    return {"code": code, "severity": severity, "detail": detail}


def _inventory_device_url(xaddrs):
    """Prefer an advertised IPv4 XAddr for v0.1 inventory, retaining IPv6 too."""
    for xaddr in xaddrs:
        host = urlparse(xaddr).hostname
        if not host:
            continue
        try:
            if ipaddress.ip_address(host).version == 4:
                return xaddr
        except ValueError:
            continue
    return xaddrs[0] if xaddrs else None


def scan_device(entry, cred_resolver, timeout=5.0):
    """Inventory one discovered device. entry: discovery.merge_matches item
    (or a synthetic directed entry with xaddrs set). cred_resolver:
    callable(ip, endpoint, mac) -> {"user","password"} | None."""
    scopes = P.parse_scopes(entry.get("scopes"))
    xaddrs = entry.get("xaddrs") or []
    device_url = _inventory_device_url(xaddrs)
    source_ip = (entry.get("source_ips") or [None])[0]
    host = urlparse(device_url).hostname if device_url else source_ip
    rec = {
        "ip": host, "port": urlparse(device_url).port if device_url else None,
        "endpoint": entry.get("endpoint"), "types": entry.get("types"),
        "xaddrs": xaddrs, "source_ips": entry.get("source_ips") or [],
        "scopes": scopes, "device_info": None, "hostname": None,
        "mac": scopes.get("mac"), "mac_source": "scopes" if scopes.get("mac") else None,
        "ipv4": None, "clock": {"device_time": None, "offset_s": None, "skew": False},
        "services": {}, "service_sources": {}, "services_declared": None,
        "profiles": [], "channel_count": 0,
        "channel_count_basis": "profiles",
        "ptz": {"present": False, "evidence": None,
                "nodes_status": "unqueried", "nodes_reason": "not reached", "nodes": []},
        "auth": {"mode": "none", "username": None, "result": "not_tried"},
        "level": "UNREACHABLE", "findings": [], "next_steps": [],
    }
    if not device_url:
        rec["findings"].append(_finding("NO_XADDR", "warn", "ProbeMatch carried no XAddr"))
        return rec
    cred = cred_resolver(host, entry.get("endpoint"), scopes.get("mac"))
    caller = _Caller(timeout, source_ip)
    caller.cred = cred
    if cred:
        rec["auth"] = {"mode": "provided", "username": cred["user"], "result": "not_tried"}

    xaddr_host_differs = bool(source_ip and host and source_ip != host)

    # B1: device clock (pre-auth by design)
    status, text = caller.call(device_url, BODY_TIME)
    if status == 200:
        dt, malformed = P.parse_system_datetime(text)
        caller.malformed = caller.malformed or malformed
        if dt is not None:
            offset = (dt - datetime.now(timezone.utc)).total_seconds()
            caller.offset_s = round(offset, 1)
            rec["clock"] = {"device_time": dt.isoformat(), "offset_s": caller.offset_s,
                            "skew": abs(offset) > 60}
    reachable = status is not None
    if not reachable:
        rec["findings"].append(_finding(
            "UNREACHABLE", "warn", "device service did not answer: %s" % text[:120]))
        return rec

    # B2: capabilities, then services
    services = {}
    status, text = caller.call(device_url, BODY_CAPS)
    if status == 200:
        services, malformed = P.parse_capabilities(text)
        caller.malformed = caller.malformed or malformed
        if services:
            rec["findings"].append(_finding(
                "UNAUTH_CAPS_DISCLOSURE", "info",
                "GetCapabilities answered without authentication"))
    if not services and cred:
        status, text = caller.call(device_url, BODY_CAPS, auth=True)
        if status == 200:
            services, malformed = P.parse_capabilities(text)
            caller.malformed = caller.malformed or malformed
    service_sources = {key: "GetCapabilities" for key in services}
    # A normal inventory step, independent of capabilities. With credentials
    # use them once; without credentials make one anonymous request.
    status, text = caller.call(device_url, BODY_SERVICES, auth=bool(cred))
    if status == 200 and not is_fault(text):
        routes, declared, malformed = P.parse_services(text)
        rec["services_declared"] = declared
        caller.malformed = caller.malformed or malformed
        # Preserve capability routes; declarations only fill missing classes.
        for key, xaddr in routes.items():
            if key not in services:
                services[key] = xaddr
                service_sources[key] = "GetServices"
    base = "%s://%s" % (urlparse(device_url).scheme, urlparse(device_url).netloc)
    if not services:
        services = {"device": device_url, "media": base + "/onvif/Media"}
        service_sources = {"device": "device_url", "media": "conventional_path"}
        rec["findings"].append(_finding(
            "CAPS_FALLBACK", "info",
            "no capabilities/services response; conventional service paths assumed"))
    rec["services"] = {key: P.redact_uri(xaddr) for key, xaddr in services.items()}
    rec["service_sources"] = service_sources

    # B3: device information — one unauthenticated attempt, one credentialed
    info = None
    status, text = caller.call(device_url, BODY_DEVINFO)
    if status == 200:
        info, malformed = P.parse_device_info(text)
        caller.malformed = caller.malformed or malformed
        if info:
            rec["findings"].append(_finding(
                "UNAUTH_INFO_DISCLOSURE", "warn",
                "GetDeviceInformation answered without authentication (loose/legacy firmware)"))
    if info is None and cred:
        status, text = caller.call(device_url, BODY_DEVINFO, auth=True)
        if status == 200:
            info, malformed = P.parse_device_info(text)
            caller.malformed = caller.malformed or malformed
    rec["device_info"] = info

    # B4: hostname / network interfaces when the auth state allows a try
    may_try = cred or info is not None
    if may_try:
        status, text = caller.call(device_url, BODY_HOSTNAME, auth=bool(cred))
        if status == 200:
            rec["hostname"] = P.parse_hostname(text)
        status, text = caller.call(device_url, BODY_NETIF, auth=bool(cred))
        if status == 200:
            netif, malformed = P.parse_network_interfaces(text)
            caller.malformed = caller.malformed or malformed
            if netif:
                rec["ipv4"] = {"address": netif["ipv4"], "prefix": netif["prefix"]}
                if not rec["mac"] and netif["mac"]:
                    rec["mac"] = netif["mac"]
                    rec["mac_source"] = "GetNetworkInterfaces"

    # B5: profiles from Media and/or Media2
    profiles = []
    gens_seen = set()
    for key, gen, body in (("media", 1, BODY_PROFILES1), ("media2", 2, BODY_PROFILES2)):
        svc = services.get(key)
        if not svc:
            continue
        use_auth = bool(cred)
        status, text = caller.call(svc, body, auth=use_auth)
        if status == 200:
            found, malformed = P.parse_profiles(text, gen)
            caller.malformed = caller.malformed or malformed
            if found:
                gens_seen.add(gen)
                profiles.extend(found)
    # Options have no silent profile limit, including shared encoder tokens.
    svc_by_gen = {1: services.get("media"), 2: services.get("media2")}
    for prof in profiles:
        token = prof["encoder_configuration_token"]
        result = {"status": "unqueried", "reason": "missing encoder configuration token", "data": None}
        if caller.auth_failed:
            result.update(status="auth_blocked", reason="authentication gate closed")
        elif token:
            gen = prof["media_gen"]
            ns, tag = (TRT, "trt") if gen == 1 else (TR2, "tr2")
            result = caller.query(svc_by_gen[gen], _encoder_options_body(token, ns, tag),
                                  lambda xml: P.parse_encoder_options(xml, gen))
        prof["encoder_options"] = result
    # stream + snapshot URIs per profile (bounded)
    for prof in profiles[:8]:
        svc = svc_by_gen.get(prof["media_gen"])
        if not svc:
            continue
        ns, tag = (TRT, "trt") if prof["media_gen"] == 1 else (TR2, "tr2")
        use_auth = bool(cred)
        status, text = caller.call(svc, _stream_uri_body(prof["token"], ns, tag), auth=use_auth)
        if status == 200:
            uri = P.parse_stream_uri(text)
            if uri:
                prof["stream_uri"] = P.redact_uri(uri)
        status, text = caller.call(svc, _snapshot_uri_body(prof["token"], ns, tag), auth=use_auth)
        if status == 200:
            uri = P.parse_stream_uri(text)
            if uri:
                prof["snapshot_uri"] = P.redact_uri(uri)
    rec["profiles"] = profiles
    sources = {p["video_source_token"] for p in profiles if p["video_source_token"]}
    rec["channel_count"] = len(sources) if sources else len(profiles)
    rec["channel_count_basis"] = "video_source" if sources else "profiles"

    # B6: PTZ declarations; enumerate once and supplement only missing nodes.
    ptz_evidence = []
    if services.get("ptz"):
        ptz_evidence.append("capability_xaddr" if service_sources["ptz"] == "GetCapabilities"
                            else "service_xaddr")
    if any(p["ptz_config"] for p in profiles):
        ptz_evidence.append("profile_config")
    ptz = rec["ptz"]
    ptz.update(present=bool(ptz_evidence),
               evidence="+".join(ptz_evidence) if ptz_evidence else None)
    ptz_svc = services.get("ptz")
    ptz["nodes_reason"] = "no PTZ service route"
    nodes = {}
    if ptz_svc:
        enumeration = caller.query(ptz_svc, BODY_NODES, P.parse_ptz_nodes)
        ptz["nodes_status"] = enumeration["status"]
        ptz["nodes_reason"] = enumeration["reason"]
        for node in enumeration["data"] or []:
            token = node["token"]
            if token not in nodes:
                nodes[token] = {"token": token, "status": "ok", "reason": None,
                                "source": "GetNodes", "data": node}
    for prof in profiles:
        token = prof["ptz_node_token"]
        if token and token not in nodes:
            nodes[token] = {"token": token, "status": "unqueried", "reason": "node not obtained",
                            "source": None, "data": None}
    for token, node in nodes.items():
        data = node["data"]
        # Optional missing FixedHomePosition / SupportedPresetTour is unknown,
        # not a reason to issue another request for a complete node declaration.
        complete = data is not None and all(data[k] is not None for k in
                                            ("maximum_number_of_presets", "home_supported"))
        if not complete and token and ptz_svc:
            result = caller.query(ptz_svc, _ptz_body("GetNode", "NodeToken", token), P.parse_ptz_nodes)
            matched = next((n for n in result["data"] or [] if n["token"] == token), None)
            if result["status"] == "ok" and matched is None:
                result.update(status="failed", reason="requested node absent from response")
            node.update(status=result["status"], reason=result["reason"], source="GetNode", data=matched)
    ptz["nodes"] = list(nodes.values())
    for prof in profiles:
        node = nodes.get(prof["ptz_node_token"])
        prof["ptz_node_status"] = node["status"] if node else "unqueried"
        prof["ptz_node_reason"] = node["reason"] if node else "no associated NodeToken"
        result = {"status": "unqueried", "reason": "no PTZ configuration", "data": None}
        if prof["ptz_config"]:
            if caller.auth_failed:
                result.update(status="auth_blocked", reason="authentication gate closed")
            elif not ptz_svc:
                result["reason"] = "no PTZ service route"
            elif not prof["token"]:
                result["reason"] = "missing profile token"
            else:
                result = caller.query(ptz_svc, _ptz_body("GetPresets", "ProfileToken", prof["token"]),
                                      P.parse_ptz_presets)
        prof["ptz_presets"] = result

    # auth result rollup
    if cred:
        if caller.auth_failed:
            rec["auth"]["result"] = "failed"
        elif caller.auth_ok:
            rec["auth"]["result"] = "ok"
    else:
        rec["auth"]["result"] = "not_required" if info else "not_tried"

    # findings rollup
    if rec["clock"]["skew"]:
        rec["findings"].append(_finding(
            "CLOCK_SKEW", "warn",
            "device clock offset %.0fs; check NTP on the device" % rec["clock"]["offset_s"]))
    if xaddr_host_differs:
        rec["findings"].append(_finding(
            "XADDR_MISMATCH", "info",
            "XAddr host %s differs from responder %s" % (host, source_ip)))
    if not scopes.get("mac") or not scopes.get("name"):
        rec["findings"].append(_finding(
            "SCOPES_MINIMAL", "info",
            "discovery Scopes lack mac/name; identity completed from other sources where possible"))
    if gens_seen == {2}:
        rec["findings"].append(_finding("MEDIA2_ONLY", "info", "profiles only via Media2 (Profile T generation)"))
    elif gens_seen == {1}:
        rec["findings"].append(_finding("LEGACY_MEDIA_ONLY", "info", "profiles only via Media ver10"))
    if caller.auth_failed:
        rec["findings"].append(_finding(
            "AUTH_FAILED", "warn",
            "supplied credential rejected once; not retried. Note many vendors keep a "
            "separate ONVIF user (distinct from the web user)"))
    if profiles and not any(p["stream_uri"] for p in profiles):
        rec["findings"].append(_finding(
            "STREAM_URI_MISSING", "warn",
            "profiles found but GetStreamUri returned nothing; rkdoctor hand-off unavailable"))
    if not rec["ptz"]["present"] and (info or profiles):
        rec["findings"].append(_finding("NO_PTZ", "info", "no PTZ capability found"))
    if caller.malformed:
        rec["findings"].append(_finding(
            "RESPONSE_MALFORMED", "warn",
            "at least one SOAP response needed loose parsing (non-conformant XML)"))

    # level
    if info and profiles:
        rec["level"] = "FULL"
    elif info or services or profiles:
        rec["level"] = "PARTIAL"
    else:
        rec["level"] = "DISCOVERED_ONLY"

    for prof in profiles:
        if prof["stream_uri"]:
            rec["next_steps"].append("rkdoctor rtsp %s" % prof["stream_uri"])
    return rec
