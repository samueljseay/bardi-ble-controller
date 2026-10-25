# Bardi direct BLE controller

An experimental Python controller and research guide for direct Bluetooth
control of a Bardi 12W RGBWW E27 bulb. The tested controller runs on macOS
without a Bardi/Tuya app, account, Wi-Fi credentials, or vendor-cloud enrollment.

**This worked with one purchased bulb. It is not guaranteed to work with yours,
even if the packaging has the same name.** The observed profile is Tuya P4.8;
the chip and board revision are unknown. This project does not flash firmware.

For an LLM-assisted adaptation, start with [ADAPTING.md](ADAPTING.md).
[AGENTS.md](AGENTS.md) sets the boundaries for agents working in this repository.
You can study the protocol and run synthetic tests without touching a device.
Do not run setup on an unverified model merely to see whether it works.

This is an experimental controller for one observed Tuya P4.8 profile, not a
replacement firmware or a compatibility claim for every Bardi bulb revision.
Power, RGB, white brightness/temperature, scenes, countdown, initial/remembered
startup preference, and do-not-disturb have live command acknowledgements and
matching reports. Those reports do not independently prove visible output.
Custom startup targets have synthetic wire tests but no live boot-behavior
verification. Read [the evidence and limitations](EVIDENCE.md) first.

Reconnect works both while powered and after one tested ordinary supply Off/On
cycle. That cycle changed the responding login prefix from the generated prefix
to six NUL bytes. Select `--boot-default` explicitly after physical power loss.
The full demo then worked without reconfiguration. This does not prove that
generated keys persist, or that every hardware revision behaves the same way.

## Install on macOS

Use Python 3.11 or later, a Bluetooth-capable Mac, and normal macOS Bluetooth
permission for your terminal/Python process. AES uses macOS CommonCrypto.
Windows and Linux are not supported by this implementation.

```sh
git clone https://github.com/samueljseay/bardi-ble-controller.git
cd bardi-ble-controller
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -p 'test_*.py'
.venv/bin/python bardi.py --help
```

Installing dependencies needs package access. Device operations themselves
make no vendor-cloud requests. Tests use synthetic devices and never scan or
connect. They require no Tuya libraries, captures, APKs, emulator, or account.

## First setup

Keep private state outside this source repository. Back it up privately.
Each state directory belongs to one bulb and one setup attempt.
Setup changes device configuration and can disrupt existing pairing. It is
not a read-only compatibility test. Establish ownership, device identity,
protocol compatibility, and a practical recovery plan before running it.

Place the known bulb in its documented pairing state. If it is already paired,
a physical reset changes its configuration. Plan that explicitly, do not reset
it merely because a scan misses it. Do not open or electrically probe a bulb.

```sh
STATE="$HOME/.bardi-bulb"
.venv/bin/python bardi.py --state "$STATE" discover
.venv/bin/python bardi.py --state "$STATE" select --candidate 1
.venv/bin/python bardi.py --state "$STATE" setup --accept-local-configuration
.venv/bin/python bardi.py --state "$STATE" status
```

Discovery listens for 15 seconds and writes private `discovery.json`. It does
not connect. Only the tested unbound advertisement format is accepted. Select
the known bulb, not an arbitrary nearby device. If multiple candidates appear,
establish which is yours before selecting. Candidate numbers start at one.
The product name or distance alone does not establish hardware compatibility.

Setup generates local credentials and sends one configuration message. It
does not supply real Wi-Fi credentials or perform cloud enrollment. Setup
cannot be repeated in the same state directory. Never delete its reservation
or intent to retry a possibly delivered message.

Standalone setup ended with a Bluetooth error. A subsequent connection verified
the generated key prefix. If setup fails, `status` is a safe read-only next check.
When that establishes fresh prefix-key access and a complete lighting snapshot,
explicitly reconcile setup without sending configuration again:

```sh
.venv/bin/python bardi.py --state "$STATE" confirm-setup-access
```

This command can reconcile only setup, not an uncertain lighting command.
It does not claim acceptance of the full key, assigned virtual ID, or reboot
persistence. An unsuccessful status check is not permission to reconfigure.

## Run the real-bulb demo

Start with the bulb logically On, in white mode, with countdown zero. Observe
or record the physical bulb separately if you need proof of visible output.

```sh
.venv/bin/python bardi.py --state "$STATE" demo
```

Recipe v1 displays green, blue, red, dim red, warm white, cool white, logical
Off and On, with two-second dwells. It restores the saved color, then the
saved white settings, and refreshes all five basic fields to check restoration.
It does not change startup memory or do-not-disturb. Scene and timer controls
have separate commands below. No reset or supply switching occurs in the demo.

A failed or uncertain write stops the sequence and blocks subsequent writes.
It does not blindly retry or claim restoration. The current public controller
has no automatic recovery from an uncertain lighting operation. Preserve the
records and investigate before any further changes.

## Reconnect after physical power loss

The tested bulb remains bound after the supply cycle but responds to a default
login prefix instead of the generated one. The controller does not automatically
try other keys or reconfigure on failure. Use the explicit post-boot route:

```sh
.venv/bin/python bardi.py --state "$STATE" --boot-default status
.venv/bin/python bardi.py --state "$STATE" --boot-default demo
.venv/bin/python bardi.py --state "$STATE" --boot-default color --hue 240 --saturation 1000 --value 100
```

Keep the flag on later commands in that boot state. It affects information,
handshake, reports, acknowledgements and controls consistently. It never changes
the stored generated credentials, retries setup or sends a factory reset.
Six NUL bytes are a public default, not a private authentication secret. This
route provides functionality, not strong access control against nearby peers.

## Individual controls

Values are protocol-scale integers, not percent or kelvin:

```sh
.venv/bin/python bardi.py --state "$STATE" on
.venv/bin/python bardi.py --state "$STATE" color --hue 240 --saturation 1000 --value 100
.venv/bin/python bardi.py --state "$STATE" white --brightness 250 --temperature 400
.venv/bin/python bardi.py --state "$STATE" off
.venv/bin/python bardi.py --state "$STATE" countdown --seconds 60
.venv/bin/python bardi.py --state "$STATE" countdown --seconds 0
.venv/bin/python bardi.py --state "$STATE" on
.venv/bin/python bardi.py --state "$STATE" scene --preset cycle
.venv/bin/python bardi.py --state "$STATE" scene --preset default-white
.venv/bin/python bardi.py --state "$STATE" white --brightness 1000 --temperature 1000
```

The countdown toggles the then-current logical power at expiry. It is not
necessarily an off timer. Zero cancels it. Power writes require an observed
zero timer so they cannot silently cancel a running timer. Color/white/scene
commands do not implicitly turn the bulb On. Changing scene data does not
select white mode; use a white command to leave scene mode.

An already-observed request returns `already_observed` without a write or an
invented acknowledgement. Each command establishes a fresh connection and
refreshes basic state. Optional controls require fresh matching datapoint types.

## Persistent startup preferences

These commands require separate explicit consent. They are not firmware
writes, but they can change what happens after physical power restoration.
Do not use do-not-disturb while investigating physical-power recovery.

```sh
.venv/bin/python bardi.py --state "$STATE" memory --initial --accept-persistent-setting
.venv/bin/python bardi.py --state "$STATE" memory --remember --accept-persistent-setting
.venv/bin/python bardi.py --state "$STATE" memory --white 250 400 --accept-persistent-setting
.venv/bin/python bardi.py --state "$STATE" memory --color 240 1000 100 --accept-persistent-setting
.venv/bin/python bardi.py --state "$STATE" dnd --enabled yes --accept-persistent-setting
.venv/bin/python bardi.py --state "$STATE" dnd --enabled no --accept-persistent-setting
```

Initial/remember modes preserve the existing custom-parameter tail. Custom
white/color replaces it. Custom-channel startup behavior remains unverified on
this bulb. Do-not-disturb standard semantics suppress ordinary power-return
illumination after software Off. Its physical switching sequence is unverified.

## Troubleshooting and privacy

- `status` never falls back to setup or reset. A missing peripheral may mean
  range, advertising state, host permission, device state, or a boot limitation.
  A timeout alone does not diagnose a lost key or prove a cloud requirement.
- `pending-write.json` means a prior operation might have written. Do not
  delete it to bypass the block. Read the corresponding run's private records.
- Private directories must have mode 0700, files 0600, and belong to the user.
  Symlinked state roots and competing CLI writers are rejected.
- `private-error.json` retains backend details; `private-radio.json` retains
  notifications. Both can contain device data. Never publish the state tree.
- `state` in a command result is its refreshed pre-command snapshot.
  `observed_points` includes later reports received while confirming that
  command. `fresh_written_fields` is not a full-snapshot recheck.
- BLE mode 4/5 uses only the first six ASCII local-key characters. CRC is not
  a modern message-authentication code. This is not a strong-security claim.
  Do not use these paths to transmit secrets or real network credentials.

See [PROTOCOL.md](PROTOCOL.md) for formats and code ownership, and
[NOTICES.md](NOTICES.md) for provenance. Read [SECURITY.md](SECURITY.md) before
sharing diagnostics. The project is licensed under [Apache-2.0](LICENSE), with
the third-party notices retained separately.
