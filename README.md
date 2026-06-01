# Aegis

Free/open-source, Rust **client/server** child-safety filtering VPN. Blocks non-child-safe
content in real time, detects grooming signals in text, and emails a guardian on every
intervention. Thin device clients; clusterable analysis backend.

- **Plan & architecture:** [`PLAN.md`](PLAN.md)
- **Build/agent workflow:** [`docs/agent-workflow.md`](docs/agent-workflow.md)

**Design principles:** rules-first & small dedicated models (minimal AI), conventional OCR
(not vision-LLMs), per-install CA, mTLS between all nodes, never persist explicit media.

> ⚠️ For guardians monitoring their own minor children on devices they own/control.
> Some content (E2E-encrypted chats, cert-pinned apps) is only reachable via the on-device
> agent, never the network. See `PLAN.md` §0 for honest coverage limits.

Status: scaffolding. Not yet functional.
