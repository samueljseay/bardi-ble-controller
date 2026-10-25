# Security and private diagnostics

This is experimental local-control software, not a secure pairing replacement.
Use it only with devices you own or have explicit permission to investigate.
There is no guarantee of compatibility, uninterrupted lighting, or recovery.
Do not use it for safety-critical lighting.

## Known protocol limits

Mode 4/5 derives keys from a six-byte prefix, not the complete generated key.
The tested post-boot route uses a public six-NUL default prefix. CRC detects
corruption but is not a modern authentication tag. Do not treat these features
as strong protection against nearby peers, and never send real network or
account credentials through the setup payload.

Local state protection does not encrypt files against the logged-in user,
privileged software, backups, or a compromised host. The controller uses private
file modes and locks to reduce accidental exposure and competing writers.
It does not strengthen the bulb's firmware security or disable other interfaces.

## Keep state private

Store state outside the checkout. The state directory can contain credentials,
factory identities, host peripheral identifiers, raw radio notifications, and
backend error details. Keep its directories at 0700 and files at 0600. Protect
backups and do not sync them to a public service.

The ignore rules are a second line of defense, not a redaction tool. Never add
the state tree with `git add -f`. Review the staged diff and staged filenames
before every publication. Run `python3 check_release.py`, but do not mistake a
passing pattern scan for proof that arbitrary new data is safe to publish.

If a credential reaches a public commit, deleting the file in the next commit
does not remove it from history. Treat it as exposed. Stop publication, assess
what was disclosed, and plan credential replacement with the owner. This
controller has no generic safe key-rotation or automatic recovery command.

## Share a diagnostic safely

Report the command name, exception type, protocol version, datapoint IDs/types,
and whether ACKs, fresh reports, restoration, and disconnect were confirmed.
Do not upload `private-radio.json`, `private-error.json`, discovery data,
enrollment files, or screenshots containing identifiers. Replace private values
with synthetic examples before sharing anything with an LLM or issue tracker.

Use GitHub's private vulnerability reporting channel if it is enabled on this
repository. If no private channel is available, open only a minimal issue asking
for a private contact route. Do not post exploit details, secrets, or identifying
captures in a public issue. No response-time guarantee is offered.
