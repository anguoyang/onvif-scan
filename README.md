# onvif-scan

[中文说明](README.zh-CN.md)

**Find every ONVIF camera on your LAN and turn it into an asset inventory —
in one command.**

```sh
PYTHONPATH=src python3 -m onvifscan scan
# or, once installed (pip install .):
onvifscan scan --user onvif_user
```

![CI](https://github.com/anguoyang/onvif-scan/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

You get a JSON + single-file HTML report: for every camera — manufacturer,
model, firmware, serial, channels, per-profile codec / resolution / frame
rate, PTZ presence, clock health, and the (password-masked) RTSP stream URI
for each profile, ready to hand to a stream checker.

The v0.2 work also reports profile-visible source associations, Media1/Media2
encoder option declarations, PTZ node declarations and preset counts/names.
The revised D1 Media2 request shape is implemented and tested end to end with
the strict simulator, including fractional frame rates. See the
[field contract and limitations](docs/v0.2-capabilities.md).

## Why

Commissioning and maintaining camera fleets means answering boring but
expensive questions: *What is actually on this network? Which firmware is
that one running? Why won't this camera authenticate? Which of these 40
cameras have no PTZ?* Vendor tools answer them one camera at a time, and
only for their own brand. `onvif-scan` answers them for the whole LAN at
once, for any ONVIF device, and writes the answer down as a report an
integrator can file or hand to a customer.

## What it does

1. **Discovery** — WS-Discovery probes on every local interface (plus
   directed probes for cross-VLAN or multicast-filtered networks).
2. **Inventory** — per device, read-only ONVIF queries:
   `GetSystemDateAndTime` (clock offset — the #1 cause of ONVIF auth
   failures is a skewed camera clock, so every authenticated request is
   signed against *device* time), `GetCapabilities` / `GetServices`,
   `GetDeviceInformation`, `GetHostname`, `GetNetworkInterfaces`,
   Media/Media2 `GetProfiles`, `GetStreamUri`, `GetSnapshotUri`.
3. **Findings, not just fields** — clock skew, information disclosed
   without authentication (loose legacy firmware), XAddr mismatch,
   Media2-only vs legacy-Media devices, rejected credentials, malformed
   SOAP — each with a stable ID and a plain-language hint.
4. **Hand-off** — every profile with a stream URI gets a ready-to-paste
   next step: `rkdoctor rtsp rtsp://user:***@…` for stream acceptance
   testing with [RK Edge Doctor](https://github.com/anguoyang/rk-edge-doctor).
   Discovery → acceptance is one chain.

## Safety and credential rules (hard rules, not options)

- **Read-only.** Only `Get*` queries. No configuration changes, no PTZ
  movement, ever.
- **No default-password attempts. No dictionary. No brute force.** The
  tool authenticates only with credentials *you* supply (`--user`,
  `ONVIFSCAN_PASSWORD`, or a `--creds` file mapping IP/MAC → user/pass),
  tries each exactly once per device, and stops on rejection — some
  vendors lock accounts after repeated failures, and a scanner must never
  lock you out of your own cameras.
- **Passwords never reach the output.** Stream URIs are stored masked
  (`rtsp://user:***@host/…`) and the finished report is scrubbed of any
  password used during the scan.
- **Only scan networks you own or are authorized to manage.**
- **Offline.** No telemetry, no uploads; multicast TTL is fixed at 1
  (link-local segment only).

## Quickstart

```sh
git clone https://github.com/anguoyang/onvif-scan && cd onvif-scan

# no credentials: discovery + whatever each device discloses openly
PYTHONPATH=src python3 -m onvifscan scan

# one ONVIF user for all devices (prompted password; note: on many
# cameras the ONVIF user is separate from the web UI user)
ONVIFSCAN_PASSWORD=... PYTHONPATH=src python3 -m onvifscan scan --user onvif_user

# different users per device
PYTHONPATH=src python3 -m onvifscan scan --creds creds.json
# creds.json: {"192.168.1.64": {"user": "onvif_user", "password": "..."},
#              "aa:bb:cc:dd:ee:ff": {"user": "op", "password": "..."}}

# multicast filtered / camera on another VLAN segment you manage
PYTHONPATH=src python3 -m onvifscan scan --host 192.168.3.64

# many directed targets: one host[:discovery-port] per line in a text
# file (# comments and blank lines ignored; combines with --host)
PYTHONPATH=src python3 -m onvifscan scan --hosts cameras.txt
```

Outputs `onvif-inventory.json` and `onvif-inventory.html` in the current
directory (paths configurable). Example reports — generated against
simulated devices, clearly labelled — are in [`examples/`](examples/).

For cron-driven inventory, add `--quiet` to print only the summary and report
paths; the JSON and HTML reports are generated the same way:

```sh
PYTHONPATH=src python3 -m onvifscan scan --quiet
```

## Reading the results

Each device gets a level: **FULL** (identity + profiles), **PARTIAL**
(identity or capabilities only), **DISCOVERED_ONLY** (nothing answered —
usually ONVIF disabled or auth required with no credentials supplied),
**UNREACHABLE**. A zero-camera result is printed with a hint, not a
conclusion: ONVIF is off by default on much current firmware (Hikvision
≥ 5.5.0, Axis ≥ 5.40 both ship it disabled, with a separate ONVIF user to
create), and Wi-Fi APs often filter multicast. See
[`docs/vendor-notes.md`](docs/vendor-notes.md) for the per-vendor quirks
this tool is built around — clock-skew digest failures, minimal Scopes,
wrong XAddrs, Media2-only devices, and more.

## Status and verification honesty

v0.1. The full discovery → inventory chain is verified end-to-end
against simulated devices modelling strict / standard / legacy vendor
behaviours (the simulator ships in `tests/` and runs in CI), including
the clock-skew authentication case both ways. Real-camera reports are
being collected — if you run it on a real fleet, a device report issue
(see CONTRIBUTING) is the single most valuable contribution. Until the
first real-camera reports land, treat vendor *behaviour coverage* as
simulation-verified, not field-verified.

## Relationship to RK Edge Doctor

`onvif-scan` answers *what is on the network*; `rkdoctor rtsp` (from
[RK Edge Doctor](https://github.com/anguoyang/rk-edge-doctor)) answers
*whether a given stream is healthy*. Together they cover a camera
acceptance workflow: inventory the fleet, then acceptance-test each
stream. A [Site AI Gateway](https://site-ai-gateway.com) open-source tool
for security and parking integrators.

## License

Apache-2.0.
