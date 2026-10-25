# Protocol and implementation notes

## Ownership

`bardi.py` owns user selection, private state, process exclusion and commands.
`activation_transport.BleSession` owns the only BLE client, notification queue,
fragment assembler, sender and disconnect. `lighting_state.LightingState`
owns serial allocation, replay checks, sparse reports and pending-command
correlation. `lighting_control.ControlSession` adds typed-control policy.
The historical `DemoSession` shares this state machine rather than implementing
a second receiver or transaction path. `lighting_demo.py` owns the fixed recipe.

No runtime module imports Android tooling, emulator code, APK analysis, private
capture files, or a reference binary. `activation_*` names retain research
history; local setup does not mean vendor-cloud activation was established.

## Wire format

Service FD50 uses write characteristic `00000001-0000-1001-8001-00805f9b07d0`
and notification characteristic `00000002-0000-1001-8001-00805f9b07d0`.
The transport uses ordered varint-indexed fragments, with total length and
version/sequence in the first fragment. Writes use 20-byte GATT packets.

The application body has big-endian serial:u32, acknowledgement:u32,
opcode:u16, payload-length:u16, payload, and CRC-16/MODBUS:u16. Encrypted
envelopes have a mode byte, 16-byte IV and AES-CBC body with bounded padding.
Mode 4 uses MD5 of the first six ASCII local-key characters. Mode 5 adds the
fresh six-byte device nonce before hashing. This verifies prefix-key behavior,
not acceptance of the entire generated localKey/secKey pair.

After the tested ordinary power cycle, the responding prefix became six NUL
bytes while bound=true remained. `--boot-default` explicitly selects that
mode-4 key and the corresponding mode-5 nonce-derived key for all operations.
There is no implicit fallback, setup replay or stored-credential replacement.
The default-prefix route is not evidence of generated-key persistence and is
not strong authentication.

Information is opcode 0, identity handshake 1, state query 3, local
configuration 27 decimal, and datapoint writes 0x27, which is 39 decimal.
Do not confuse the last two. Unsolicited reports use 0x8006.

Datapoint-write payloads start with zero:u8 and command-sequence:u32. Each
record is id:u8, type:u8, length:u16, data. Report headers have a separate
sequence and acknowledgement flags. An acknowledgement at GATT level is
not application success. A correlated command ACK plus newer matching
reports is required for `reported_confirmed`.

## Observed lighting fields

| ID | Type | Typed command / range |
| --- | --- | --- |
| 20 | Boolean | `Power`, strict Boolean |
| 21 | Enum | Mode 0 white, 1 color, 2 scene; 3 is a standard music candidate, unverified here |
| 22 | Value | White brightness 10..1000 |
| 23 | Value | White temperature 0..1000, not kelvin |
| 24 | String | HSV, three four-digit ASCII hex integers; H 0..360, S 0..1000, V 10..1000 |
| 25 | String | Scene slot 0 plus 1..8 units, 28..210 ASCII hex bytes |
| 26 | Value | Countdown seconds 0..86400; zero cancels; expiry toggles power |
| 33 | Raw | Version-0 startup memory, exactly 12 binary bytes |
| 34 | Boolean | Do-not-disturb preference |

Value fields use four-byte big-endian integers, enums/Booleans one byte.
Strings contain transmitted text; raw diagnostic hex is decoded to bytes
before transmission. There is no arbitrary-datapoint-write command.

Scene text is `II` plus units `TT SS MM HHHH SSSS VVVV BBBB CCCC`.
`MM` is static=0, jump=1, fade=2. Timing bytes are 0..100, not literal seconds.
The API permits one static frame or 2..8 dynamic frames, with separate typed
white/RGB frames to avoid unverified mixed-channel behavior. Data precedes mode.
`000e0d0000000000000000c80000` is the observed default static white scene.

Memory bytes are version:u8, mode:u8, then five big-endian u16 channels
H,S,V,white-brightness,temperature. Modes are initial=0, remember=1, custom=2.
The observed baseline is `000100000000000000000000`.

## Confirmation and uncertainty

Reports are sparse. The bulb echoes changed fields but can omit an unchanged
mode. The controller filters unchanged values before encoding. Confirmation
requires fresh reports for every field actually written, not for fields it
did not write. A fresh full snapshot remains a separate property.

Intents are durable before transmission. Once a write is uncertain or rejected,
the session sends no subsequent controls. The CLI retains a persistent block
across process restarts. Only uncertain initial setup has a dedicated read-only
reconciliation path. There is no automatic lighting-command retry.

Connections are bounded to 180 seconds, 512 writes, 512 notification fragments,
65536 received bytes, 256 unique decoded responses and 128 report ACKs.
Individual command confirmation is limited to eight seconds; state refreshes
to twelve. The implementation checks lifetime before writes as well as reads.

## Source references

Wire research used the Apache-2.0 BLE SDK at
`hjytry/tuya-ble-sdk@815c07120e96372e8746e9d01a21381a8fdd8655`.
Scene/memory layouts were cross-checked with the MIT-licensed
`tuya/tuya-panel-sdk@b574ca61ff6ca9ff5b777a9372af8293f7cd8bf2`, including
`SceneFormatter` and `PowerMemoryFormatter`, and Tuya's public
[lighting function definitions](https://developer.tuya.com/en/docs/iot/product-function-definition?id=K9s9rhj576ypf).

Unlicensed lighting-reference source files and proprietary application
decompilation were research inputs only and are excluded from this tree.
Public reference behavior is not proof of this bulb's exact firmware identity.
