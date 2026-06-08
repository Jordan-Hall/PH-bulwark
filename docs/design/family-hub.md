# Family Account Hub

This file intentionally replaces the older exploratory "family hub" concept.
The product plan is transparent content safety, not remote administration.

## In Scope

- Guardian/adult accounts.
- Child records linked to supervised device ids.
- Short-lived pairing codes for enrolling child devices.
- Server selection: UK/London cloud, US cloud, or self-hosted `bulwark-server`.
- Redacted alerts and guardian approve/deny review.
- Protection heartbeat and tamper/status alerts.
- Honest coverage and platform-limit reporting.

## Out of Scope

- Covert monitoring.
- Remote device control.
- Screen capture.
- Hidden location tracking.
- Remote lock/wipe.
- Reading private messages outside the transparent, platform-sanctioned child
  safety mechanisms already documented in the platform notes.

The canonical implementation plan is now
[`app-pairing-and-regions.md`](app-pairing-and-regions.md).
