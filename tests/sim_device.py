"""Simulated ONVIF devices used as test fixtures (fictional brands).

Three personas encode documented real-world vendor behaviours:
  standard : capabilities open, device info behind auth, Media (ver10),
             stream URI *with embedded credentials* (redaction test),
             PTZ present, clock accurate, dual-stack discovery XAddrs.
  legacy   : minimal discovery Scopes, device info WITHOUT auth (loose
             legacy firmware), single profile, no PTZ.
  strict   : even GetCapabilities needs auth, clock skewed +3723 s
             (auth only works with device-time-corrected digest),
             Media2 only, PTZ present.

Auth: WS-Security UsernameToken PasswordDigest, Created must be within
300 s of the *device* clock. The simulated ONVIF user is
onvif_user / SimPass123 (a fixture password, obviously not real).
"""
import base64
import hashlib
import socket
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

USER = "onvif_user"
PASSWORD = "SimPass123"

PERSONAS = {
    "standard": dict(
        port=18081, disc_port=37021, manufacturer="Acme (sim)", model="ViewCam AC-200",
        firmware="1.4.2 (sim)", serial="SIMSTD0001", hardware="AC-200",
        clock_offset_s=2, auth_devinfo=True, auth_caps=False, ptz=True, media2=False,
        stream_uri_with_creds=True, dual_stack=True,
        scopes="onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/Profile/T "
               "onvif://www.onvif.org/name/Sim%20Standard onvif://www.onvif.org/hardware/AC-200 "
               "onvif://www.onvif.org/mac/aa:bb:cc:00:00:01 onvif://www.onvif.org/location/lab",
        profiles=[("MainStream", "H264", 1920, 1080, 25, True),
                  ("SubStream", "H265", 640, 480, 15, False)],
    ),
    "legacy": dict(
        port=18082, disc_port=37022, manufacturer="OldBrand (sim)", model="OC-10",
        firmware="0.9.8 (sim)", serial="SIMLEG0002", hardware="OC-10",
        clock_offset_s=3, auth_devinfo=False, auth_caps=False, ptz=False, media2=False,
        stream_uri_with_creds=False,
        scopes="onvif://www.onvif.org/Profile/Streaming",
        profiles=[("Profile_1", "H264", 2560, 1440, 20, False)],
    ),
    "strict": dict(
        port=18083, disc_port=37023, manufacturer="SecureEye (sim)", model="SE-9",
        firmware="7.1.0 (sim)", serial="SIMSTR0003", hardware="SE-9",
        clock_offset_s=3723, auth_devinfo=True, auth_caps=True, ptz=True, media2=True,
        stream_uri_with_creds=False,
        scopes="onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/Profile/T "
               "onvif://www.onvif.org/name/Sim%20Strict onvif://www.onvif.org/hardware/SE-9 "
               "onvif://www.onvif.org/mac/aa:bb:cc:00:00:03",
        profiles=[("profile_0_h264", "H264", 1920, 1080, 30, True),
                  ("profile_0_h265", "H265", 1920, 1080, 30, True)],
    ),
}

NS = {"wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
      "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"}
TDS = "http://www.onvif.org/ver10/device/wsdl"
TT = "http://www.onvif.org/ver10/schema"


def device_now(p):
    return datetime.now(timezone.utc) + timedelta(seconds=p["clock_offset_s"])


def check_auth(p, root):
    tok = root.find(".//wsse:UsernameToken", NS)
    if tok is None:
        return False
    user = tok.findtext("wsse:Username", None, NS)
    digest = tok.findtext("wsse:Password", None, NS)
    nonce_b64 = tok.findtext("wsse:Nonce", None, NS)
    created = tok.findtext("wsu:Created", None, NS)
    if user != USER or not (digest and nonce_b64 and created):
        return False
    try:
        cdt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    if abs((device_now(p) - cdt).total_seconds()) > 300:
        return False
    expect = base64.b64encode(hashlib.sha1(
        base64.b64decode(nonce_b64) + created.encode() + PASSWORD.encode()).digest()).decode()
    return expect == digest


def fault(msg="authentication required / failed", kind="NotAuthorized"):
    return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>'
            '<s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>ter:%s</s:Value>'
            '</s:Subcode></s:Code><s:Reason><s:Text xml:lang="en">%s</s:Text></s:Reason>'
            '</s:Fault></s:Body></s:Envelope>' % (kind, msg))


def envelope(body):
    return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            '<s:Body>%s</s:Body></s:Envelope>' % body)


def handle_soap(p, path, raw):
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return 400, fault("unparseable", "InvalidArgVal")
    body = root.find("{http://www.w3.org/2003/05/soap-envelope}Body")
    operation = list(body)[0].tag if body is not None and len(body) else ""
    op = operation.split("}")[-1]
    authenticated = root.find(".//wsse:UsernameToken", NS) is not None
    # Metadata only: never retain raw SOAP, digests, nonces or passwords.
    p.setdefault("calls", []).append({"operation": op, "qname": operation,
                                      "path": path, "credentialed": authenticated})
    if op in p.get("responses", {}):
        return p["responses"][op]
    if authenticated and op == p.get("reject_at"):
        return (401, "") if p.get("bare_401") else (401, fault())
    text = raw.decode("utf-8", "ignore")
    base = "http://127.0.0.1:%d" % p["port"]
    if "GetSystemDateAndTime" in text:
        n = device_now(p)
        return 200, envelope(
            '<tds:GetSystemDateAndTimeResponse xmlns:tds="%s" xmlns:tt="%s">'
            '<tds:SystemDateAndTime><tt:DateTimeType>Manual</tt:DateTimeType>'
            '<tt:DaylightSavings>false</tt:DaylightSavings><tt:TimeZone><tt:TZ>UTC</tt:TZ></tt:TimeZone>'
            '<tt:UTCDateTime><tt:Time><tt:Hour>%d</tt:Hour><tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time>'
            '<tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date></tt:UTCDateTime>'
            '</tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>'
            % (TDS, TT, n.hour, n.minute, n.second, n.year, n.month, n.day))
    if "GetCapabilities" in text:
        if p["auth_caps"] and not check_auth(p, root):
            return 401, fault()
        ptz = ('<tt:PTZ><tt:XAddr>%s/onvif/PTZ</tt:XAddr></tt:PTZ>' % base) if p["ptz"] else ""
        # media2 personas are Media2-only (no ver10 Media service at all)
        media = "" if p["media2"] else ('<tt:Media><tt:XAddr>%s/onvif/Media</tt:XAddr></tt:Media>' % base)
        m2 = ('<tt:Media2><tt:XAddr>%s/onvif/media2</tt:XAddr></tt:Media2>' % base) if p["media2"] else ""
        return 200, envelope(
            '<tds:GetCapabilitiesResponse xmlns:tds="%s"><tds:Capabilities xmlns:tt="%s">'
            '<tt:Device><tt:XAddr>%s/onvif/device_service</tt:XAddr></tt:Device>'
            '%s%s%s'
            '</tds:Capabilities></tds:GetCapabilitiesResponse>'
            % (TDS, TT, base, media, ptz, m2))
    if "GetServices" in text:
        if not check_auth(p, root):
            return 401, fault()
        return 200, envelope(
            '<tds:GetServicesResponse xmlns:tds="%s">'
            '<tds:Service><tds:Namespace>%s</tds:Namespace><tds:XAddr>%s/onvif/device_service</tds:XAddr></tds:Service>'
            '<tds:Service><tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>'
            '<tds:XAddr>%s/onvif/Media</tds:XAddr></tds:Service></tds:GetServicesResponse>'
            % (TDS, TDS, base, base))
    if "GetDeviceInformation" in text:
        if p["auth_devinfo"] and not check_auth(p, root):
            return 401, fault()
        return 200, envelope(
            '<tds:GetDeviceInformationResponse xmlns:tds="%s">'
            '<tds:Manufacturer>%s</tds:Manufacturer><tds:Model>%s</tds:Model>'
            '<tds:FirmwareVersion>%s</tds:FirmwareVersion><tds:SerialNumber>%s</tds:SerialNumber>'
            '<tds:HardwareId>%s</tds:HardwareId></tds:GetDeviceInformationResponse>'
            % (TDS, p["manufacturer"], p["model"], p["firmware"], p["serial"], p["hardware"]))
    if "GetHostname" in text:
        if not check_auth(p, root):
            return 401, fault()
        return 200, envelope(
            '<tds:GetHostnameResponse xmlns:tds="%s"><tds:HostnameInformation>'
            '<tt:FromDHCP xmlns:tt="%s">false</tt:FromDHCP><tt:Name xmlns:tt="%s">simcam</tt:Name>'
            '</tds:HostnameInformation></tds:GetHostnameResponse>' % (TDS, TT, TT))
    if "GetNetworkInterfaces" in text:
        if not check_auth(p, root):
            return 401, fault()
        mac = p["scopes"].split("/mac/", 1)[-1].split()[0] if "/mac/" in p["scopes"] else "aa:bb:cc:00:00:09"
        return 200, envelope(
            '<tds:GetNetworkInterfacesResponse xmlns:tds="%s"><tds:NetworkInterfaces token="eth0" '
            'xmlns:tt="%s"><tt:Enabled>true</tt:Enabled><tt:Info><tt:Name>eth0</tt:Name>'
            '<tt:HwAddress>%s</tt:HwAddress></tt:Info><tt:IPv4><tt:Enabled>true</tt:Enabled>'
            '<tt:Config><tt:Manual><tt:Address>127.0.0.1</tt:Address><tt:PrefixLength>8</tt:PrefixLength>'
            '</tt:Manual><tt:DHCP>false</tt:DHCP></tt:Config></tt:IPv4></tds:NetworkInterfaces>'
            '</tds:GetNetworkInterfacesResponse>' % (TDS, TT, mac))
    if "GetProfiles" in text:
        if not check_auth(p, root):
            return 401, fault()
        gen2 = "/media2" in path
        profs = ""
        for token, codec, w, h, fps, has_ptz in p["profiles"]:
            ptzcfg = ('<tt:PTZConfiguration token="PTZ_1"><tt:NodeToken>PTZNode</tt:NodeToken>'
                      '</tt:PTZConfiguration>' if has_ptz and p["ptz"] else "")
            profs += ('<Profiles token="%s" fixed="true"><tt:Name>%s</tt:Name>'
                      '<tt:VideoSourceConfiguration token="VS_1"><tt:Name>VS</tt:Name></tt:VideoSourceConfiguration>'
                      '<tt:VideoEncoderConfiguration token="VE_1"><tt:Name>VE</tt:Name>'
                      '<tt:Encoding>%s</tt:Encoding><tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution>'
                      '<tt:RateControl><tt:FrameRateLimit>%d</tt:FrameRateLimit><tt:BitrateLimit>4096</tt:BitrateLimit></tt:RateControl>'
                      '</tt:VideoEncoderConfiguration>%s</Profiles>'
                      % (token, token, codec, w, h, fps, ptzcfg))
        if gen2:
            for old, new in (("VideoSourceConfiguration", "VideoSource"),
                             ("VideoEncoderConfiguration", "VideoEncoder"),
                             ("PTZConfiguration", "PTZ")):
                profs = profs.replace("tt:" + old, "tr2:" + new)
            profs = profs.replace('<tr2:VideoSource ', '<tr2:Configurations><tr2:VideoSource ')
            profs = profs.replace('</Profiles>', '</tr2:Configurations></tr2:Profiles>')
            profs = profs.replace('<Profiles ', '<tr2:Profiles ')
        # Legacy retains its v0.1 response shape, including missing SourceToken.
        if p.get("source_tokens", not p["manufacturer"].startswith("OldBrand")):
            profs = profs.replace('<tt:Name>VS</tt:Name>',
                                  '<tt:Name>VS</tt:Name><tt:SourceToken>Sensor_1</tt:SourceToken>')
        tag = "tr2" if gen2 else "trt"
        ns = "http://www.onvif.org/ver20/media/wsdl" if gen2 else "http://www.onvif.org/ver10/media/wsdl"
        return 200, envelope(
            '<%s:GetProfilesResponse xmlns:%s="%s" xmlns:tt="%s">%s</%s:GetProfilesResponse>'
            % (tag, tag, ns, TT, profs, tag))
    if "GetStreamUri" in text or "GetSnapshotUri" in text:
        if not check_auth(p, root):
            return 401, fault()
        snap = "GetSnapshotUri" in text
        if snap:
            uri = "http://127.0.0.1:%d/snap.jpg" % p["port"]
        elif p["stream_uri_with_creds"]:
            uri = "rtsp://%s:%s@127.0.0.1:554/stream1" % (USER, PASSWORD)
        else:
            uri = "rtsp://127.0.0.1:554/stream1"
        tag = "tr2" if "/media2" in path else "trt"
        ns = "http://www.onvif.org/ver20/media/wsdl" if "/media2" in path else "http://www.onvif.org/ver10/media/wsdl"
        op = "GetSnapshotUri" if snap else "GetStreamUri"
        return 200, envelope(
            '<%s:%sResponse xmlns:%s="%s" xmlns:tt="%s"><%s:MediaUri><tt:Uri>%s</tt:Uri>'
            '<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect></%s:MediaUri></%s:%sResponse>'
            % (tag, op, tag, ns, TT, tag, uri, tag, tag, op))
    return 400, fault("unsupported operation", "ActionNotSupported")


def _handler(p):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            code, out = handle_soap(p, self.path, self.rfile.read(n))
            data = out.encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/soap+xml; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    return H


PROBE_MATCH = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <s:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
 <wsa:RelatesTo>{relates}</wsa:RelatesTo></s:Header>
 <s:Body><d:ProbeMatches><d:ProbeMatch>
  <wsa:EndpointReference><wsa:Address>urn:uuid:{urn}</wsa:Address></wsa:EndpointReference>
  <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
  <d:Scopes>{scopes}</d:Scopes>
  <d:XAddrs>{xaddrs}</d:XAddrs>
  <d:MetadataVersion>1</d:MetadataVersion>
 </d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"""


def _discovery_loop(p, urn):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", p["disc_port"]))
    xaddrs = ["http://127.0.0.1:%d/onvif/device_service" % p["port"]]
    if p.get("dual_stack"):
        xaddrs.insert(0, "http://[2001:db8::1]:%d/onvif/device_service" % p["port"])
    while True:
        data, addr = sock.recvfrom(8192)
        if b"Probe" not in data:
            continue
        relates = "urn:uuid:unknown"
        try:
            root = ET.fromstring(data)
            for el in root.iter():
                if el.tag.endswith("MessageID") and el.text:
                    relates = el.text.strip()
        except ET.ParseError:
            pass
        time.sleep(0.02)
        sock.sendto(PROBE_MATCH.format(relates=relates, urn=urn, scopes=p["scopes"],
                                       xaddrs=" ".join(xaddrs)).encode(), addr)


class SimDevices:
    """Context manager: run all (or one) persona servers on localhost."""

    def __init__(self, names=None, http_only=False, overrides=None):
        self.names = names or list(PERSONAS)
        self.http_only = http_only
        self.overrides = overrides or {}
        self.personas = {}
        self.servers = []

    def __enter__(self):
        for name in self.names:
            p = dict(PERSONAS[name], **self.overrides.get(name, {}))
            p["calls"] = []
            self.personas[name] = p
            if not self.http_only:
                threading.Thread(target=_discovery_loop, args=(p, str(uuid.uuid4())),
                                 daemon=True).start()
            srv = HTTPServer(("127.0.0.1", 0 if self.http_only else p["port"]), _handler(p))
            p["port"] = srv.server_port
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv)
        time.sleep(0.2)
        return self

    def __exit__(self, *exc):
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()
        return False
