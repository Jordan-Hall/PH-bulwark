# On-device safety agent — the AccessibilityService does it all (no VPN)

Status: **DESIGN / spec.** Today the on-device agent is a documented gap
(`docs/production-readiness.md`: "on-device OCR/agent … not yet functional");
the AccessibilityService is wired for view-tree text only. This doc is the
spec to build the full agent. It pairs with [apps.md](apps.md),
[realtime-filtering-and-attribution.md](realtime-filtering-and-attribution.md),
and [FOSS.md](../FOSS.md).

## Why the AccessibilityService (and not the VPN, not MediaProjection)

The **AccessibilityService is the single on-device engine** — it does it all,
**with no VPN and no MediaProjection prompt**:

- it already has the guardian's **consent**, granted once at setup (no
  per-session capture prompt like MediaProjection forces);
- it reads the **view-tree text** directly (the wired path today);
- on **API 30+ (Android 11+)** it can `takeScreenshot()` for image frames;
- it can draw **`TYPE_ACCESSIBILITY_OVERLAY`** windows to cover/blur regions.

This is the path that protects **E2E / pinned apps and any rendered content the
network filter can never see** — it is complementary to, and independent of,
the VPN TLS-inspection path. When the VPN is off, the agent still protects.

## What it does — one capture, two detectors, localized action

On a throttled tick (and on accessibility events of interest), the service
takes one screen frame + the current node tree and runs the **same engines the
network path uses** — never a new model, never an LLM, all FOSS:

### 1. Text → grooming (`bulwark-text`)
- **View-tree text** (TextView/EditText nodes) → straight into the
  `bulwark-text` grooming detector (already wired via `analyzeText` JNI).
- **Text the tree can't expose** (drawn as bitmaps/canvas — some games, image
  captions, stylised chat) → **Tesseract** OCR (`tesseract4android`,
  Apache-2.0) on the `takeScreenshot()` frame → the extracted text feeds the
  **SAME `bulwark-text` grooming detector**. OCR is conventional — never a
  vision-LLM. One grooming engine, two text sources.

### 2. Imagery → NSFW (ONNX ViT classifier), with LOCALIZED cover-up
- The frame is scored by the **same FOSS ONNX ViT NSFW classifier**
  (`bulwark-vision`, MIT runtime + Apache-2.0 model) the Camera app and the VPN
  proxy use. A vision **classifier**, not an LLM.
- The model is **whole-image** (one probability, no bounding boxes), so
  localization is done by **tiling**: split the frame into an N×N grid, score
  each tile, and mark tiles above the NSFW threshold. The **blocked region is
  the bounding box of the flagged tiles, expanded by a margin** (a tile or so
  on each side) — never the full screen.
- Cover the flagged region with a **`TYPE_ACCESSIBILITY_OVERLAY`** (opaque or
  blurred) so **the rest of the screen stays visible and usable**. The overlay
  tracks the region; it lifts when the content scrolls away / the next clean
  frame scores safe.
- **CSAM-suspected** stays the hard path: detect → block (cover) → NCMEC report,
  **never stored/served**. No frame is persisted; only redacted evidence
  (hashes / a SAFE cropped-and-blurred thumbnail) per the no-media invariant.

## Honest constraints

- `takeScreenshot()` is **API 30+** and OS-rate-limited (~1/s); pre-30 devices
  fall back to view-tree text only (no image NSFW from the agent — the VPN/proxy
  still covers network images). Throttle hard: battery + CPU (each tick = OCR +
  N² classifier inferences). Tile count N is a perf/accuracy knob.
- Tiling gives **coarse, grid-granularity** localization (+ margin), not pixel
  masks — good enough to cover an offending image while leaving the page
  usable; not a precise segmentation.
- The overlay **cannot cover secure/system surfaces** (other secure windows),
  and can't act inside another app's `FLAG_SECURE` window — documented gap.
- Everything is **in-memory + FOSS + on-device**; nothing leaves the device from
  this path (the network reporting path is separate and still detect/block/report).

## Increment plan

1. **Text-OCR → grooming:** add `tesseract4android` + an `Ocr` engine; on a
   throttled `takeScreenshot()`, OCR → existing `analyzeText` grooming path.
   (View-tree text path already lives.)
2. **Image NSFW (full-frame):** score the screenshot with the ONNX classifier;
   on a hit, cover with a single full-frame-region overlay (coarse) + alert.
3. **Localized tiled cover-up:** N×N tiling, flagged-tile bounding box + margin,
   tracking accessibility overlay (the spec above).
4. **Tuning + device validation** on the Pixel: thresholds, tile count, tick
   cadence, battery, overlay UX; CSAM path end-to-end.

All four reuse the shipped FOSS engines (`bulwark-text`, `bulwark-vision`,
Tesseract) — no new models, no proprietary SDK, no VPN dependency.
