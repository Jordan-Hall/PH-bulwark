# PH Bulwark labeling (workstream A)

Trusted-volunteer labeling for the grooming model. Volunteers label conversation
windows on their phones; the labels feed the rom **retrain loop** (workstream B,
`models/pipeline/retrain.py`).

```
aegis-labeling-app (Dioxus 0.8, native)        aegis-labeling-server (axum)
  fetch next task ───────────────────────────▶  GET  /tasks/next   (most-uncertain first)
  submit label ──────────────────────────────▶  POST /labels       (writes corrections.jsonl)
                                                       │
                                          corrections.jsonl ──▶ rom pipeline/retrain.py ──▶ new ONNX
```

## Two pieces

### `apps/labeling-server` — the API (built + tested ✅)
Pure-Rust file-backed store (`src/store.rs`, unit-tested) + axum HTTP/JSON
(`src/main.rs`). No SQLite (host constraint) — plain JSONL, like the server's
`persist` module. Detached crate (doesn't touch the engine workspace build).

- `GET /tasks/next?labeler=<id>` → next unlabeled window, **most-uncertain first**
  (model score closest to 0.5 = active learning) · `204` when done
- `POST /labels` `{task_id,labeler,label,stages}` → appends a correction line
- `GET /stats` → `{labeled,total}` · `GET /healthz`
- Auth: shared bearer token (`LABELING_TOKEN`) — Phase 1, trusted volunteers

Run:
```bash
cd apps/labeling-server
LABELING_TASKS=tasks.jsonl LABELING_CORRECTIONS=corrections.jsonl \
  LABELING_TOKEN=secret cargo run
```
`tasks.jsonl` lines: `{"id","messages":[{"role","text"}],"model_score":0.49,"label":0}`
(produce this from the corpus + model predictions — the active-learning queue).

### `apps/labeling` — the Dioxus 0.8 client (scaffold, build-validate next ⏳)
One codebase → desktop (dev) + Android/iOS (the "native first" volunteer app) + web.
```bash
dx serve                       # desktop preview
dx build --platform android    # the volunteer app
```
> The Rust is written against Dioxus 0.8-alpha; the on-device build needs the
> mobile toolchain (Android SDK/NDK) and a 0.8-alpha `dx` (installed with
> `--locked`). That build pass is the next step — the API it talks to is done.

## The loop
1. Build `tasks.jsonl` from the corpus + current model predictions (uncertain first)
2. Volunteers label in the app → server writes `corrections.jsonl`
3. Commit `corrections.jsonl` to rom → `retrain.yml` retrains sklearn + ships ONNX
   (DistilBERT via Colab/Kaggle) — see `models/pipeline/RETRAIN.md`

## Responsible-labeling notes (trusted volunteers, Phase 1)
- **Consent + content warning** shown in-app (real grooming transcripts)
- **Text only** — never illegal imagery; the corpus is public Perverted-Justice text
- **Audit**: every correction carries the `labeler` id
- Consensus / gold-standard QA / reputation = Phase 2 (only needed for an open crowd)
