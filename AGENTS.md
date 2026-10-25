# Working on this controller

Read README.md, ADAPTING.md, PROTOCOL.md, EVIDENCE.md, and SECURITY.md before
changing protocol behavior. This repository is a starting point for one observed
Bardi 12W RGBWW E27 Tuya P4.8 profile, not a universal Tuya controller.

## Authority and device safety

- Default to offline work. Permission to edit or test code is not permission to
  scan, connect, configure, reset, power-cycle, or command any device.
- Before a live step, state its exact target, expected writes, limits, recovery
  plan, and uncertainty. Obtain the owner's explicit scope for that step.
- Never retry setup or a possibly delivered write by deleting its reservation,
  intent, or state directory. An uncertain outcome is evidence to preserve.
- Do not add automatic key fallback, guessed datapoint writes, firmware/OTA
  operations, factory commands, or automatic resets.
- Do not operate other nearby devices. An advertised name or signal strength
  does not establish ownership or exact identity.
- Do not disassemble mains equipment or connect a programmer under this guide.

## Privacy

- Keep all per-device state outside the checkout. Never commit captures, keys,
  real identities, account data, Wi-Fi credentials, personal paths, or host UUIDs.
- Do not send private identifiers to searches, vendor APIs, issue trackers, or
  model prompts. Use newly constructed synthetic fixtures and redacted summaries.
- Do not publish backend error messages or run directories without inspecting
  them. Exclude private data before the first commit, not in a later cleanup.

## Implementation and verification

- Keep one BLE owner in BleSession and one transaction model in LightingState.
  Extend typed controls rather than adding a raw write escape hatch.
- Validate incoming data at boundaries. Preserve CRC, length, serial, ACK,
  replay, budget, timeout, and durable-intent checks.
- Distinguish GATT ACKs, application ACKs, fresh matching reports, complete
  snapshot restoration, visible output, and power-cycle persistence.
- Test new behavior with asymmetric synthetic inputs and literal expectations.
  A new profile needs its own evidence; do not loosen this profile to accept it.
- Run `python3 -m unittest discover -p 'test_*.py'` on macOS. Tests are offline.
  Run `python3 check_release.py` before proposing publication. After intentional
  source changes, review them before using `--write-manifest` to update hashes.
- Retain third-party notices. Do not copy proprietary or unlicensed research
  implementations into the public tree.

Report what you observed, what you inferred, what remains unverified, and which
device operations actually ran. Do not claim physical output from reports alone.
