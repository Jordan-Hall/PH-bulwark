# Wave A — A2 Model & OCR Research

> Principle: **use AI sparingly** — small dedicated models + deterministic rules + conventional OCR.
> Findings from research agent A2 (2026-06). Verify licenses/sizes at integration time.

## Model registry

| Detector | Artifact | License | Size | Format | INT8? | Redist? |
|---|---|---|---|---|---|---|
| NSFW image/frame | **NudeNet v3 320n** | MIT | ~7 MB | ONNX | – | ✅ |
| NSFW image/frame | NudeNet v3 640m | MIT | ~25 MB | ONNX | – | ✅ |
| NSFW image/frame | Falconsai/nsfw_image_detection (ViT) | Apache-2.0 | ~340 MB | safetensors | quantizable | ✅ |
| NSFW image/frame | AdamCodd/vit-base-nsfw-detector | MIT | ~346 MB | ONNX | ✅ | ✅ |
| NSFW image/frame | OpenNSFW-Standalone | MIT | ~25 MB | ONNX | ✅ | ✅ |
| Explicit audio (backbone) | YAMNet | Apache-2.0 | ~21 MB | TFLite/SavedModel | ✅ | ✅ |
| Explicit audio (backbone) | PANNs | MIT | ~19–50 MB | PyTorch→ONNX | conv. | ✅ |
| Grooming text | DistilBERT (fine-tune) | Apache-2.0 | ~268 MB | safetensors | ✅ | ✅ |
| Grooming text | MiniLM (all-MiniLM-L6-v2) | Apache-2.0 | ~80 MB | ONNX | ✅ | ✅ |
| OCR | Tesseract (`leptess`) | Apache-2.0 | ~5 MB | binary | n/a | ✅ |
| OCR | PaddleOCR | Apache-2.0 | 5–50 MB | ONNX | ✅ native | ✅ |
| OCR (OS-native) | Windows.Media.Ocr / Android ML Kit / macOS Vision | OS / Apache | 0 / ~10-30MB | native | – | on-device |

## Per-device tier
- **Mobile:** NudeNet 320n (NNAPI/CoreML via `ort`); YAMNet/PANNs INT8 first-pass; grooming **rules local**, classifier **offloaded**; OCR = OS-native. Offload to cluster when RAM<512MB / battery<20%.
- **CPU box/gateway:** NudeNet 640m or Falconsai FP32; PANNs+head; rules+DistilBERT; Tesseract/PaddleOCR.
- **GPU worker:** Falconsai/NudeNet batched (CUDA/TensorRT); PANNs batched; DistilBERT/BERT-base.

## Grooming rule + lexicon starter spec (deterministic first; classifier backs it up)

Eight indicator categories with example triggers and weights:

| Category | Weight | Example triggers |
|---|---|---|
| Secrecy / "don't tell" | +0.5 | "don't tell your parents", "our little secret", "keep this between us" |
| Platform switching / isolation | +0.5 | "let's move to Telegram/Discord/Snapchat", "download this app", "I'll text you there" |
| Personal-info & age probing | +0.4 | "how old are you?", "what's your address/school?", "are your parents home?", "when are you alone?" |
| Sexualization of a minor | +0.6 | "do you have a bf/gf?", "ever kissed?", "you're sexy for [age]", "send a pic" |
| Gifts / bribery | +0.4 | "I'll buy you…", "gift card", "if you do this for me…" |
| Emotional manipulation / isolation | +0.5 | "your parents don't understand you, I do", "you're the only one I can talk to" |
| Boundary testing | +0.3 | "just this once", "prove you like me", "it's no big deal" |
| **Image requests (CSAM risk)** | **+5.0** | "send a picture", "selfie", "without clothes", "in your room" |

Scoring: sum weights per message + context multipliers (secrecy×platform-switch +2.0; info+age probing +1.5;
sexualization+(gifts|isolation) +2.0; image-request +5.0; rapid escalation <7d ×1.5). Normalize `/10`, cap 1.0.
Thresholds: **≥0.7 immediate alert + human review · ≥0.5 flag+log · ≥0.3 log · <0.3 pass**. Per-language lexicon files.

Backup classifier: DistilBERT/MiniLM fine-tuned on **PAN2012 Sexual Predator Identification**
(zenodo 3713280) + PJ-derived corpora; stratify by conversation (not speaker) to avoid leakage.
LLM = **opt-in manual review UI only**, never hot-path, never on-device, never automated decisions.

## ⚠️ Must train ourselves / cannot ship as-is
| Task | Why | Approach |
|---|---|---|
| Explicit-audio head | No open explicit-sound classifier; YAMNet/PANNs are general taggers | Train 2–4 layer head on PANNs/YAMNet embeddings + domain/synthetic audio |
| Grooming text classifier | PAN12 small & dated; predators adapt | Fine-tune DistilBERT on PAN12 + PJ + synthetic negatives; retrain quarterly |
| Per-language lexicon | English-only triggers | Localize categories per language with native review |
| **CSAM hash matching** | **PhotoDNA is proprietary (NCMEC-licensed), not redistributable** | Use **Google CSAI Match API** for known hashes; perceptual-hash for unknown; **legal review required** |

## Notes
- `ort` exec providers: CPU/oneDNN, CUDA/TensorRT, DirectML, NNAPI, CoreML — request best, auto-fallback to CPU.
- **Checksum-pin every model** (SHA256 in `aegis-core`); reject mismatches on load. Use ONNX in production.
