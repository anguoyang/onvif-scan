"""Minimal SOAP-over-HTTP client with WS-Security UsernameToken support.

Authentication rules enforced here and in scan.py:
- credentials are only ever the ones the user explicitly supplied;
- one supplied credential per device: NotAuthorized or bare HTTP 401 on a
  credentialed request ends all further credentialed calls;
- the password never leaves this module: callers get status + body only.
"""
import base64
import hashlib
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

WSSE_HEADER = (
    '<s:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/'
    'wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" s:mustUnderstand="1">'
    '<wsse:UsernameToken><wsse:Username>{user}</wsse:Username>'
    '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
    'username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>'
    '<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
    'wss-soap-message-security-1.0#Base64Binary">{nonce}</wsse:Nonce>'
    '<wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>')


def password_digest(nonce_raw, created, password):
    """Digest = Base64(SHA1(raw_nonce + Created + password))."""
    return base64.b64encode(
        hashlib.sha1(nonce_raw + created.encode() + password.encode()).digest()).decode()


def build_wsse_header(user, password, device_offset_s=0.0, nonce=None, now=None):
    """Created is stamped on the *device's* clock: cameras reject tokens
    whose timestamp differs from their own clock, and field cameras are
    routinely minutes to hours off. device_offset_s comes from the
    unauthenticated GetSystemDateAndTime call made before any auth."""
    nonce = nonce if nonce is not None else os.urandom(16)
    now = now if now is not None else datetime.now(timezone.utc)
    created_dt = now + timedelta(seconds=device_offset_s)
    created = created_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return WSSE_HEADER.format(user=user, digest=password_digest(nonce, created, password),
                              nonce=base64.b64encode(nonce).decode(), created=created)


def soap_call(url, body_inner, user=None, password=None, device_offset_s=0.0, timeout=5.0):
    """POST one SOAP request. Returns (http_status|None, text).

    http_status None means a transport error; the text then holds the
    error description prefixed with 'ERROR: '."""
    header = ""
    if user is not None:
        header = build_wsse_header(user, password or "", device_offset_s)
    env = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
           + header + "<s:Body>" + body_inner + "</s:Body></s:Envelope>").encode()
    req = urllib.request.Request(
        url, data=env, headers={"Content-Type": "application/soap+xml; charset=utf-8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "ignore")
        except Exception:
            return e.code, ""
    except Exception as e:  # timeout, refused, DNS, ...
        return None, "ERROR: %s" % e


def is_fault(text):
    return "<Fault" in text or ":Fault>" in text


def fault_kind(text):
    if "NotAuthorized" in text:
        return "NotAuthorized"
    if is_fault(text):
        if "ActionNotSupported" in text or "OptionalActionNotImplemented" in text:
            return "NotSupported"
        return "Fault"
    return None
