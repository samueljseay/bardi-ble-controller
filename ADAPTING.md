# Adapt the controller to your own bulb

Use this guide with a human or an LLM to investigate a bulb you own. The goal is
a bounded local controller with evidence for its behavior, not a guessed chip
identification or a promise of compatibility. Matching retail names are not
enough: different production runs can use different firmware and datapoints.

## Start without a device

1. Read [the evidence limits](EVIDENCE.md) and [wire formats](PROTOCOL.md).
2. Install Python on macOS and run the synthetic tests from README.md.
3. Trace `bardi.py` through `BleSession`, `ControlSession`, and `LightingState`.
   Follow one color command from typed input to confirmation and restoration.
4. Write down what differs about your product and what is still unknown. Keep
   identifiers and credentials in private files outside this repository.

The reusable method is to establish framing and read-only state first, model
commands offline, and add a live control only after its contract is understood.
Exact silicon is not a prerequisite for BLE control. This guide does not cover
firmware replacement, OTA probing, decompilation, or cloud-account extraction.

## Give an LLM a bounded task

Use a prompt like this before any radio work:

```text
Read AGENTS.md and the linked project documents. Work offline only.
I own a bulb sold as <public retail model>. Do not assume it matches the tested
Bardi unit. Explain the current discovery filter and wire contracts, identify
the evidence a new profile needs, and propose one bounded read-only experiment.
Do not scan, connect, configure, reset, power-cycle, or command anything yet.
Do not ask for credentials or private identifiers in chat. Use synthetic tests.
Separate observed behavior from public-reference semantics and hypotheses.
```

Review the proposed operation yourself. LLM instructions do not replace a
device owner's permission or a recovery plan. Never provide broad unattended
permission to try commands until something works.

## Establish a profile before setup

For separately approved live research, proceed through these gates in order:

1. **Identity and ownership.** Use locally saved observations to establish which
   device is yours. Names, proximity, and a macOS UUID alone are not sufficient
   proof of compatibility. Keep identity checks local.
2. **Advertisement and services.** Compare service/manufacturer data and GATT
   discovery to the exact filter in `bardi.candidate`. That filter accepts one
   unbound profile. Do not relax its length or prefix checks to force a match.
3. **Information framing.** Validate fragment order, complete lengths, CRC,
   opcode, request association, protocol flags, and extensions. A timeout or
   opaque frame does not diagnose a chip, cloud requirement, or key state.
4. **Session and state.** Validate a fresh nonce, handshake, report format,
   datapoint types, and read-only state. Do not infer numeric ranges or meaning
   from datapoint IDs alone. Unknown fields remain opaque and read-only.
5. **Local configuration.** Only after compatibility is established, consider
   the one-shot setup path. It writes credentials and can change pairing.
   Plan recovery with the owner first. A transport failure may still mean the
   write reached the device. Preserve the state directory and stop.

The CLI supplies the tested flow, not a generic discovery tool for arbitrary
Tuya products. If a gate fails, stop device work and investigate saved evidence
offline. A new layout belongs in a separately validated profile, not in weaker
checks that accept several incompatible layouts.

## Model one control offline

Start with a single known control, not scenes or startup preferences. For a
color adaptation, establish hue/saturation/value encoding and mode selection
before sending anything. Use different values for every channel so swapped
fields cannot pass the same test.

- Put literal expected bytes in synthetic tests. Do not derive the expectation
  from the same encoder under test.
- Exercise both range boundaries, invalid types, sparse reports, stale reports,
  wrong serials, rejection, and lost acknowledgements.
- Reserve durable intent before transmission. A crash or timeout must block a
  second write, including after restarting the CLI.
- Keep application confirmation separate from a complete snapshot recheck.
  Do not require an unchanged mode to be echoed when only color was written.
- Test restoration of a nontrivial baseline. Do not assume the lamp started at
  a default value or that a power command leaves a countdown intact.

Reuse the existing synthetic peers. Do not turn actual captured identities or
credentials into public fixtures. Preserve notices for any source you adapt.

## Verify one live change, then stop

Agree on the exact command, baseline, bounds, and restoration before the owner
authorizes it. Verify the target again within the session. Send once and require
a correlated application ACK plus newer matching reports for all written fields.
If delivery is uncertain, preserve evidence and stop. Do not retry under a new
action ID or silently run setup, reset, or another key candidate.

Observe or record the physical bulb separately. An ACK proves less than a
matching state report, and a matching state report proves less than visible
light. Reconnect and startup behavior need their own evidence. The six-NUL
`--boot-default` behavior is an observation about one unit, not a recommended
universal fallback or a secure authentication mechanism.

Do not use do-not-disturb, startup memory, scenes, timers, or supply switching
as your first test. Those controls can complicate recovery or change persistent
behavior. The distributed demo is for the established profile and restores its
baseline only when the sequence remains confirmed.

## Contribute a sanitized compatibility result

Publish only a summary with the retail model, host OS/Python versions, observed
protocol version, datapoint IDs/types, commands tested, confirmation level,
restoration result, and remaining uncertainty. State whether physical output
and reconnect after power loss were independently checked.

Omit serial numbers, radio addresses, factory IDs, firmware keys, account data,
host paths, raw logs, and run directories. Synthetic tests and public source
links are better review material than private captures. A result for one unit
does not certify every product bearing that name.
