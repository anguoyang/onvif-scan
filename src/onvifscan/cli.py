"""Command line: onvifscan scan ...

Only scan networks you own or are authorized to manage. The tool is
read-only and never tries default credentials; see SPEC/README.
"""
import argparse
import getpass
import json
import os
import sys
import time
from urllib.parse import urlparse

from . import __version__
from .discovery import DISCOVERY_PORT, discover, iface_ipv4
from .report import build_report, render_html, scrub_secrets, terminal_lines, write_json
from .scan import scan_device

ZERO_RESULT_HINT = (
    "No ONVIF responses. That does NOT prove there are no cameras: ONVIF is "
    "disabled by default on much current firmware, and Wi-Fi APs often filter "
    "multicast. Try a wired interface, check the cameras' ONVIF setting, or "
    "use --host for a known address.")


def _load_creds(path):
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    out = {}
    for key, val in raw.items():
        if isinstance(val, dict) and "user" in val and "password" in val:
            out[key.lower()] = {"user": val["user"], "password": val["password"]}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="onvifscan",
        description="Discover ONVIF cameras on your LAN and inventory them "
                    "(read-only). Only scan networks you are authorized to manage.")
    ap.add_argument("--version", action="version", version="onvifscan " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="discover + inventory")
    sc.add_argument("--iface", action="append",
                    help="interface name to scan from (repeatable; default: all non-loopback)")
    sc.add_argument("--timeout", type=float, default=5.0,
                    help="discovery listen window in seconds (default 5)")
    sc.add_argument("--user", help="ONVIF user for every device (user-supplied credential)")
    sc.add_argument("--password",
                    help="password; prefer ONVIFSCAN_PASSWORD env or the prompt "
                         "(command line can leak into shell history)")
    sc.add_argument("--creds", help="JSON file mapping IP/MAC/endpoint -> {user, password}")
    sc.add_argument("--host", action="append",
                    help="directed probe target host[:discovery-port] (repeatable); "
                         "for cross-VLAN or multicast-filtered networks")
    sc.add_argument("--hosts",
                    help="text file containing one directed probe host[:port] per line")
    sc.add_argument("--device-url", action="append",
                    help="skip discovery for this device service URL (repeatable)")
    sc.add_argument("--discovery-port", type=int, default=DISCOVERY_PORT)
    sc.add_argument("--json", default="onvif-inventory.json")
    sc.add_argument("--html", default="onvif-inventory.html")
    sc.add_argument("--no-html", action="store_true")
    sc.add_argument("--quiet", action="store_true",
                    help="print only the summary line and report paths (for cron)")
    args = ap.parse_args(argv)

    single_cred = None
    password = args.password or os.environ.get("ONVIFSCAN_PASSWORD")
    if args.user:
        if not password:
            if sys.stdin.isatty():
                password = getpass.getpass("ONVIF password for %s: " % args.user)
            else:
                print("error: --user given but no password (use --password, "
                      "ONVIFSCAN_PASSWORD, or a terminal prompt)", file=sys.stderr)
                return 2
        single_cred = {"user": args.user, "password": password}
    creds_map = _load_creds(args.creds) if args.creds else {}

    def cred_resolver(ip, endpoint, mac):
        for key in (ip, endpoint, mac):
            if key and key.lower() in creds_map:
                return creds_map[key.lower()]
        return single_cred

    secrets = [c["password"] for c in creds_map.values() if c["password"]]
    if single_cred:
        secrets.append(single_cred["password"])

    ifaces = None
    if args.iface:
        known = dict(iface_ipv4())
        ifaces = []
        for name in args.iface:
            if name not in known:
                print("error: unknown interface %s (have: %s)" % (name, ", ".join(known)),
                      file=sys.stderr)
                return 2
            ifaces.append((name, known[name]))

    host_targets = list(args.host or [])
    if args.hosts:
        with open(args.hosts, encoding="utf-8") as f:
            host_targets.extend(line.split("#", 1)[0].strip() for line in f)
        host_targets = [h for h in host_targets if h]
    directed = []
    for h in host_targets:
        host, _, p = h.rpartition(":")
        if host and p.isdigit():
            directed.append((host, int(p)))
        else:
            directed.append((h, args.discovery_port))

    started = time.time()
    devices_raw, meta = discover(ifaces=ifaces, timeout=args.timeout,
                                  port=args.discovery_port, directed=directed or None)
    mode = "discovery"
    if args.device_url:
        mode = "directed"
        for url in args.device_url:
            devices_raw.append({"endpoint": None, "types": None, "scopes": "",
                                "xaddrs": [url],
                                "source_ips": [urlparse(url).hostname]})
    if directed and not args.device_url:
        mode = "discovery+directed"
    meta.update({"mode": mode,
                 "auth_mode": "file" if creds_map else ("single" if single_cred else "none")})

    records = [scan_device(entry, cred_resolver, timeout=5.0) for entry in devices_raw]
    duration = time.time() - started
    report = build_report(__version__, meta, records, duration)
    report = scrub_secrets(report, secrets)

    write_json(report, args.json)
    if not args.no_html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(report))
    lines = terminal_lines(report)
    for line in lines[-1:] if args.quiet else lines:
        print(line)
    if not devices_raw and not args.quiet:
        print(ZERO_RESULT_HINT)
    print("reports: %s%s" % (args.json, "" if args.no_html else " + " + args.html))
    return 0


if __name__ == "__main__":
    sys.exit(main())
