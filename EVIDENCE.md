# Verified behavior and remaining limits

Evidence date: October 25, 2026. The target was one purchased Bardi 12W RGBWW
E27 Wi-Fi/Bluetooth bulb with a Tuya P4.8 BLE profile. Exact silicon and board
revision remain unknown. No firmware was flashed.

These are summaries of privately retained experiments, not a public raw-capture
dataset. Device identities, credentials, host identifiers, and internal run IDs
are intentionally omitted. Readers can reproduce the synthetic tests; verifying
behavior on their own bulb requires a separate, explicitly authorized experiment.

## Standalone runtime results

Independent discovery decoded a fresh unbound advertisement and matched the
known target in a private local comparison. One generated-key setup attempt
ended with a Bluetooth error. Configuration was not retried. A fresh connection
then validated generated-prefix mode-4 information, bound=true, and a new nonce.
The assigned virtual-ID field remained zero.

A mode-5 identity handshake and full lighting query succeeded. Explicit
read-only setup reconciliation recorded working access without replaying setup.
Separate fresh connections established the following reported behavior:

| Operation | Observation | Limit |
| --- | --- | --- |
| Green, blue, red, dim red, warm/cool white, logical Off/On | Correlated application ACKs and newer matching reports | No independent visible-output verification |
| Restore saved color and white settings | New full DP20..24 snapshot matched baseline | A state report is not a light measurement |
| Scene cycle and restoration | Matching scene text and mode reports | Scene timing and physical transitions were not recorded |
| 15-second countdown | Timer accepted; later reconnect reported Off and timer zero; On restored | Not independently timed at the physical output |
| Initial/remember startup memory | Matching version-0 raw records; original value restored | Startup output was not verified |
| Do-not-disturb true/false | Matching Boolean reports; original value restored | Physical switching/recovery sequence remains unverified |

All listed operations confirmed disconnect. The standalone runtime used direct
BLE and local credentials, not a Bardi/Tuya account, vendor API, emulator, or
supply-plug action. Dependency installation required package access. No
network-wide air gap was established, and unrelated host traffic was not audited.

Reports were sparse: the bulb reported changed color but sometimes omitted an
unchanged mode. The controller filters unchanged fields before writing and
requires fresh reports for every field it actually writes. It does not treat
GATT write acknowledgements as application success.

## Post-power-cycle reconnect

Earlier failed reconnects reached GATT but received no application information
notifications. They did not establish that Bluetooth was disabled. A controlled
four-probe comparison found a change in the responding key prefix:

| State | Generated six-byte prefix | Six-NUL default prefix |
| --- | --- | --- |
| Before one ordinary supply cycle | Valid bound information and a fresh nonce | GATT ACKs, no information notifications |
| After that cycle | GATT ACKs, no information notifications | Valid bound information and a fresh nonce |

Each probe sent one information request and confirmed disconnect. The research
supply cycle used an app-assisted plug action with reported Off/On transitions,
not independent electrical measurement. That tool is excluded from this repo.
The subsequent standalone default-prefix handshake, state query, and full demo
worked without reset, reconfiguration, or a supply-tool runtime dependency.

The isolated source tree's interpreter repeated the demo. A separate fresh
status connection verified all nine observed fields restored to baseline.
The controller exposes this route as explicit `--boot-default`, not automatic
fallback. The default is public and does not provide strong authentication.

This establishes one post-power-restoration control path for one unit. It does
not establish the firmware storage mechanism, generated-key persistence, every
reboot condition, or compatibility with another revision.

## Unverified behavior

- No recording or direct human observation verifies the physical output of
  these runs. `optical_output_verified` remains false.
- Full localKey/secKey acceptance, assigned-ID persistence, and vendor-cloud
  activation are not established. The working mode-4/5 paths use six-byte prefixes.
- Custom startup targets have synthetic wire tests, not live startup-output tests.
- Music mode and unreported datapoints are not implemented or claimed as supported.
- Linux, Windows, other bulb revisions, and automatic uncertain-write recovery
  are not supported by this implementation.
- No exact chip, module, GPIO map, safe replacement firmware, or independent
  programming recovery route has been identified. None is needed to study BLE.

## Offline verification

The prepared isolated tree passed 42 synthetic tests. The private research tree
passed 218 broader tests, some using excluded reference harnesses. Only the
isolated suite is distributed and reproducible here. Run it on macOS:

```sh
python3 -m unittest discover -p 'test_*.py'
python3 check_release.py
```

The tests check literal wire values, type/range boundaries, sparse reports,
ACK/report order, freshness, terminal uncertainty, durable intents, setup and
reconnect conversations, no-op suppression, and demo restoration. Synthetic
fixtures contain no real identities or credentials and do not access Bluetooth.

The release checker verifies an explicit file allowlist, source hashes, local
import closure, and selected privacy patterns. It is a disclosure guard, not a
complete secret detector or a legal audit. See [SECURITY.md](SECURITY.md).
