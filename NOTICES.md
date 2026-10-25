# Provenance and distribution boundary

The project-owned Python implementation, tests, and documentation are licensed
under Apache-2.0. See `LICENSE`. Applicable third-party notices remain below.
This license does not grant rights to unrelated research inputs or trademarks.

This tree contains the Python host implementation, synthetic tests and rewritten
documentation. It is not a firmware distribution and makes no clean-room claim.
It excludes APKs, proprietary decompiled source, reference C files, vendor
libraries, firmware images, real identifiers, generated credentials, radio/UI
captures, and Android/emulator tooling. Do not add a private state directory.

The host implementation was developed during protocol research using public
SDK references, proprietary-app analysis, synthetic wire tests and observed
device responses. Wire-format facts are documented separately from runtime
behavior. A Python rewrite does not itself eliminate attribution obligations.

Conservatively retain the Apache-2.0 license and these applicable notices for
protocol implementation informed by the older BLE reference:

> Copyright (C) 2014-2019, Tuya Inc., All Rights Reserved
>
> SPDX-License-Identifier: Apache-2.0

Upstream is `hjytry/tuya-ble-sdk`, revision
`815c07120e96372e8746e9d01a21381a8fdd8655`. No upstream NOTICE file was found
at that revision. This controller modifies the implementation substantially:
Python codecs, macOS crypto calls, asyncio transport, bounded state machines,
typed commands, private durable storage and synthetic test peers replace the
reference C runtime. No reference binary or C source is bundled.

Scene and memory format research also used Tuya's MIT-licensed panel SDK,
revision `b574ca61ff6ca9ff5b777a9372af8293f7cd8bf2`. Its copyright and full
permission notice are retained in `LICENSE-TUYA-PANEL.txt`.

`LICENSE-APACHE-2.0.txt` is the upstream grant for applicable reference-derived
material. It is not an assertion that every research input carries that grant.
No redistribution grant was verified for the separate seven-file lighting SDK
snapshot; those files are excluded. Protocol facts from that investigation are
not a license to copy its implementation. No third-party firmware identity or
trademark endorsement is claimed.

Bleak and PyObjC are separately installed dependencies and retain their own
licenses. CommonCrypto is supplied by macOS, not bundled. This provenance
summary is not a clean-room certification or a claim of legal clearance for
other material. Do not add proprietary excerpts, firmware, or unlicensed
reference implementations to this repository.
