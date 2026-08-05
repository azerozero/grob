# media

> Bounded media decoding, perceptual fingerprinting, and an append-only observation journal (feature `media`).

## Purpose

First slice of the image/video DLP and provenance work. It answers three questions safely: *is this payload something we are willing to look at*, *what is its perceptual fingerprint*, and *what did we see and when*. It renders no verdicts, blocks no traffic, and marks no media; those arrive in later slices.

The slice is compiled out unless `--features media` is passed, and inert unless `mode` is set away from `off`.

## Public API

| Item | Location | Used by |
|------|----------|---------|
| `MediaRef`, `MediaRef::from_image_source` | `mod.rs` | callers holding a `ContentBlock::Image` |
| `MediaError` | `mod.rs` | all fallible entry points |
| `MediaConfig`, `MediaMode` | `config.rs` | config loading |
| `probe`, `probe_bytes`, `sniff` | `decode.rs` | ingestion |
| `MediaFormat`, `MediaProbe` | `decode.rs` | ingestion, journal |
| `GrayImage`, `PerceptualHash`, `gradient_hash`, `MATCH_THRESHOLD` | `phash.rs` | fingerprinting, lookup |
| `MediaEvent`, `MediaJournal`, `current_month` | `registry.rs` | observation journal |
| `scan`, `ScanReport`, `Finding`, `Severity` | `scan/` | cheap detectors |

## Owns

- The pre-decode safety budget: allow-listed formats, byte ceiling, pixel ceiling.
- Header-only dimension parsing for PNG, JPEG, GIF and WebP.
- The 64-bit gradient perceptual hash and its measured match threshold.
- The `~/.grob/media/YYYY-MM.jsonl` observation journal.
- Cheap detectors: shape heuristics, EXIF/GPS presence, appended payloads.

## Depends on

- `base64` for inline payloads, `serde`/`serde_json` for the journal, `chrono` for timestamps, `anyhow` for journal I/O.
- `crate::models::ImageSource` to build a `MediaRef`.

No image decoding library, no network, no async.

## Design notes

**Bounds precede decoding.** Every limit is checked against headers before a pixel buffer exists. A 33-byte PNG can declare 2.5 billion pixels; the only safe moment to refuse it is before a decoder allocates for it. This is why dimensions are parsed here instead of delegated.

**Formats are allow-listed and sniffed.** The declared `media_type` is treated as a hint, never as proof: a caller that lies about it is exactly the caller worth catching.

**Remote media is never fetched.** Pulling a client-supplied URL from inside the proxy is an SSRF primitive. Whether to do it is a policy decision, and this slice does not make policy.

**The hash is written here rather than imported.** `img_hash` would add roughly fifty transitive crates and pin an older `image` release for about sixty lines of arithmetic. Cost measured, not assumed.

**The journal records shape, never content.** Fingerprint, format, dimensions, size. A forensic journal that leaks the thing it was built to protect defeats itself.

## Measured behaviour

Gradient hashing compares relative brightness between neighbouring cells, which is what makes it survive rescaling, recompression and exposure changes. Measured on this implementation against the synthetic screenshot corpus in `tests.rs`:

| Transform | Hamming distance /64 |
|---|---|
| Resize 75 % / 50 % / 25 % | 2 / 2 / 3 |
| Crop 5 % / 10 % / 25 % | 3 / 4 / 7 |
| Brighten +2 / +12 | 0 / 0 |
| Chained resize + brighten + crop | 5 |
| **Mirror** | **17** |
| Closest genuinely different image | 16 |

Worst same-image distance is 7 and the closest different image is 16, so `MATCH_THRESHOLD = 10` sits inside the gap with margin on both sides. Both edges are asserted by tests, so an erosion of the separation fails in CI instead of degrading into false matches.

**Known limitation:** mirroring and rotation defeat this layer, structurally rather than as a tuning problem, because the hash reads left-to-right. Recovering provenance from a flipped image needs the manifest or watermark layers. There is a test that documents this rather than a comment that hopes for it.

## Detectors

`scan()` runs every cheap detector over an already-probed payload and returns findings, never decisions. Nothing decodes pixels.

| Rule | Severity | Signal |
|---|---|---|
| `exif_gps` | Suspicious | Image carries GPS tags; location leaves with the image |
| `appended_payload` | Suspicious | Data follows the container's end marker |
| `appended_text` | Suspicious | That appended data contains a long printable run |
| `extreme_aspect_ratio` | Notice | Ratio beyond 20:1 |
| `tiny_image` | Notice | 64 pixels or fewer, typically a tracking pixel |
| `exif_present` | Info | EXIF block present without GPS |

Two properties are enforced by tests rather than convention. Findings **never quote the payload they found**, because a finding that echoed a secret would copy the leak into every log line recording it. And detection is **total**: every prefix of a malformed input yields findings or nothing, never a panic.

**Known limitation:** this catches carelessness, not craft. LSB steganography from a competent tool is statistically indistinguishable without a decoder and a model. Claiming to detect it would be worse than not looking, because it would manufacture confidence.

## Non-goals

- Verdicts, redaction or blocking (detectors report; policy decides, later).
- Real steganalysis.
- Watermarking, C2PA manifests, OCR.
- Object or face recognition.
- Video.

## Tests

`scan/tests.rs` covers each detector, the no-payload-in-findings property, totality over truncated inputs, and an ignored cross-check against real system JPEGs (`--ignored`). `tests.rs` covers the decompression-bomb refusal, budget boundaries, lying MIME types, truncated-header totality across all four formats, SSRF refusal, the full perceptual-hash matrix above, the separation gap, and journal append/replay including a torn tail.

## Mutation coverage

Every file in the slice has been checked with `cargo-mutants`, because a passing
test suite says nothing about whether the tests would notice a bug:

| File | Survivors |
|---|---|
| `decode.rs` | 0 |
| `scan/heuristics.rs`, `scan/stego.rs` | 0 |
| `phash.rs` | 1, provably equivalent (`\|` and `^` are identical after a left shift) |
| `registry.rs` | 0 |

Two survivors could not be killed by adding tests, and both indicated a design
problem rather than a coverage gap: a duplicated bounds check in `decode.rs` made
the pre-decode guard unobservable, and a shift-then-set in `phash.rs` was
indistinguishable from its xor equivalent. Both were fixed in the code.

The lesson generalises to the rest of the media work: on byte-level parsing,
asserting the outcome asserts almost nothing. The arithmetic has to be pinned.

## Related design docs

- [`001-image-dlp-provenance.md`](../../../docs/design/001-image-dlp-provenance.md) — layered provenance model and the measurements behind it.
- [`002-media-agents-delivery-plan.md`](../../../docs/design/002-media-agents-delivery-plan.md) — this slice is PR 1.
