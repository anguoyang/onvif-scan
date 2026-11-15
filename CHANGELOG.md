# Changelog

## v0.5.0 — 2026-11-15

Final feature release; the project enters maintenance mode after this
version (external pull requests and real-device reports still welcome).

- Add per-source imaging inventory: `GetImagingSettings` + `GetOptions`
  against the Imaging service for every known video source token
  (enumerated sources union profile source tokens), each query
  status-bearing like encoder options. Settings are present-only flat
  values (brightness/contrast/sharpness/saturation, exposure and
  white-balance modes, IR cut filter, wide dynamic range, backlight
  compensation, auto-focus mode); options carry {min, max} ranges for
  the numeric fields. Request shapes verified against the official
  imaging WSDL (single `VideoSourceToken` child, as with D1/T3).
- Add event capability declarations: one `GetEventProperties` call
  (bare element; no subscription is ever created) reporting topic
  namespaces, the fixed-topic-set flag and declared TopicSet topics.
- Add recording inventory: `GetRecordingJobs` on the Recording service
  (job count and states only — job/recording tokens are never exported)
  and `GetRecordingSummary` on the Search service (time range and
  recording counts). Both requests are bare elements per the official
  WSDLs at onvif.org/ver10/recording.wsdl and ver10/search.wsdl.
- Report JSON gains `imaging` / `events` / `recording` sections and the
  HTML report shows them after the sources section (English and
  zh-CN). CSV gains trailing device-level `event_topic_count` and
  `recording_count` columns. GetServices routing now also recognises
  the Search and Replay namespaces. Schema stays 1, diff field classes
  and findings are unchanged. See
  [capability field contract](docs/v0.2-capabilities.md).

## v0.4.0 — 2026-11-13

- Add independent video source enumeration (B3): after profile imaging, query
  `GetVideoSources` + `GetVideoSourceConfigurations` (Media1) or
  `GetVideoSourceConfigurations` only (Media2 has no `GetVideoSources`).
  Both list-all requests are bare operation elements; the Media2 type
  `tr2:GetConfiguration` only adds optional ConfigurationToken/ProfileToken
  children (T3, verified against the official Media2 WSDL, as with D1).
- Report `sources` per device (token, name, name origin, bound-to-profile flag,
  source configuration tokens) with per-query states
  (`ok` / `unsupported` / `auth_blocked` / `failed` / `unqueried`); sources
  with no profile are listed and marked unbound. Evidence only: no NVR or
  device-type classification. `channel_count` is unchanged (profile-visible
  source tokens only). CSV gains trailing device-level `source_count` and
  `unbound_source_count` columns; diff compares a seventh field class,
  `sources` token sets. See [capability field contract](docs/v0.2-capabilities.md).

## v0.3.0 — 2026-11-11

- Add opt-in `scan --csv PATH`: fixed UTF-8+BOM device × Profile rows, empty
  cells for unknown values, finding code sets without details, and the same
  scrubbed report used by JSON/HTML. Compatible with `--quiet`/`--no-html`.
- Add offline `diff OLD.json NEW.json [--json OUT] [--quiet]`. Match lowercase
  MAC first, falling back to IP; compare firmware, level, Profile token/media
  generation sets, channel count, finding codes and declared service namespaces.
  Ignore metadata noise and warn on tool version differences. Write JSON only
  when requested; terminal summary is `diff: +A -R ~C =U`.
- Diff exits 0 for no changes, 1 for changes and 2 for invalid arguments/inputs.
  Keep schema 1 and the existing scan/authentication behavior unchanged.
- Add 25 standard-library unittest cases (9 CSV, 16 diff), including HTTP-only
  simulation of all three fictional personas and offline/credential isolation.

## v0.2.0 — 2026-11-08

Capability inventory release. All additions are additive; JSON schema
remains 1. Verified against the three simulated personas (86 tests:
loopback suite plus full discovery end-to-end on a LAN host). Real-camera
reports are still being collected; see the release notes.

- Add per-profile source configuration names and provenance to JSON/HTML;
  show actual source tokens alongside the legacy configuration tokens.
- Collect Media1/Media2 encoder options for every profile with an encoder token,
  preserving declaration ranges, per-codec resolutions and profiles. Parse
  Media2 fractional frame-rate lists. Resolve D1 with a direct ConfigurationToken
  child in the Media2 operation element, without a GetConfiguration wrapper.
  Validate the request shape and authentication rejection gate end to end with
  the strict simulator.
- Query PTZ GetNodes, supplement missing/incomplete nodes with GetNode once
  per token, and query GetPresets per associated profile. Keep node capacity
  separate from actual preset counts/names; never export preset coordinates
  or sum counts across profiles sharing a node.
- Add explicit optional-query states (`ok`, `unsupported`, `auth_blocked`,
  `failed`, `unqueried`) with null data for unknown results. Reuse the credential
  gate and report scrub/escaping; schema remains 1. See
  [capability field contract](docs/v0.2-capabilities.md) for fields and D1 evidence.

- Stop all credentialed calls after a credential rejection, including bare
  HTTP 401; a later rejection takes precedence over earlier auth success.
- Parse actual Media2 Configurations and retain source, encoder and PTZ
  configuration tokens plus PTZ NodeToken.
- Schema remains 1 (the existing JSON `schema` field). `source_token` still
  means the source **configuration** token; additive `video_source_token`
  holds the actual SourceToken (attribute or child element). `channel_count`
  now deduplicates actual source tokens when available, otherwise counts
  Profiles; additive `channel_count_basis` is `video_source` or `profiles`.

- Query GetServices even when capabilities are available. Add `services_declared`
  to device records and HTML: every declared namespace/XAddr/version, including
  unknown services, duplicates and missing/invalid fields. A failed or unparsed
  query yields null; a successful empty response yields []. Capability routes
  retain priority and declarations fill only missing service classes.
- Add `service_sources` for selected routes, distinguishing GetCapabilities,
  GetServices, the device URL and conventional paths. PTZ evidence uses
  `service_xaddr` when its endpoint comes only from GetServices.

## v0.1.0 — 2026-11-02

First release.

- WS-Discovery inventory of a LAN: multicast probes on all interfaces
  (two probe shapes, 5 s window, TTL 1) plus directed `--host` probes
  and `--device-url` entries for multicast-filtered networks.
- Per-device read-only inventory: device clock offset (measured before
  any authentication), capabilities/services, device information,
  hostname, network interfaces, Media + Media2 profiles with encoder
  details, stream/snapshot URIs (password-masked), PTZ presence.
- WS-Security UsernameToken authentication signed against *device*
  time; one attempt per supplied credential per device; credentials
  from `--user`/`ONVIFSCAN_PASSWORD`/prompt or a `--creds` JSON map.
- Levels (FULL/PARTIAL/DISCOVERED_ONLY/UNREACHABLE) and findings with
  stable IDs: CLOCK_SKEW, UNAUTH_INFO_DISCLOSURE, UNAUTH_CAPS_DISCLOSURE,
  AUTH_FAILED, XADDR_MISMATCH, SCOPES_MINIMAL, MEDIA2_ONLY,
  LEGACY_MEDIA_ONLY, NO_PTZ, STREAM_URI_MISSING, RESPONSE_MALFORMED,
  CAPS_FALLBACK, NO_XADDR.
- JSON (schema 1) + single-file HTML reports; terminal summary;
  per-profile `rkdoctor rtsp …` next steps (RK Edge Doctor hand-off).
- Verified end-to-end against simulated strict/standard/legacy devices
  (in `tests/`); real-camera reports being collected.
