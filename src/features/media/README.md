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
| `SidecarClient`, `SidecarConfig`, `Endpoint`, `Capability` | `sidecar/` | out-of-process capabilities |
| `observe_request`, `collect_inline_media` | `observe.rs` | async request-path entry point |
| `inspect_blocking`, `Verdict`, `DenyReason` | `blocking.rs` | pre-dispatch verdict |
| `TraceId`, `TraceRecord`, `TraceRegistry` | `trace.rs` | provenance handles |
| `OnFailure` | `config.rs` | fail-closed policy |
| `scan_ocr_text`, `TextFindings` | `scan/text.rs` | OCR text into the DLP engine |
| `fold_confusions`, `scan_variants` | `scan/normalize.rs` | OCR error repair |

## Owns

- The pre-decode safety budget: allow-listed formats, byte ceiling, pixel ceiling.
- Header-only dimension parsing for PNG, JPEG, GIF and WebP.
- The 64-bit gradient perceptual hash and its measured match threshold.
- The `~/.grob/media/YYYY-MM.jsonl` observation journal.
- Cheap detectors: shape heuristics, EXIF/GPS presence, appended payloads.
- The stateless sidecar protocol for OCR, watermarking and provenance signing.

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

## Observing a request

`observe_request` is the entry point from the request path, and it **returns `()`**. That is the guarantee rather than a convention: a caller cannot await a verdict that does not exist, so no later refactor can quietly make inspection blocking. It lifts the inline images out of the request, hands them to a detached task, and returns. A test asserts the call itself completes in under 20 ms while the journal entry appears afterwards.

Remote (URL) blocks are skipped rather than recorded. This slice never fetches them, and journaling an unfetched URL would claim knowledge of bytes nobody has seen.

One image being refused does not stop the others from being inspected, which a test pins with a lying MIME type and a decompression bomb sitting in front of a valid PNG.

Fingerprints are currently recorded as **absent** rather than faked: reaching pixels needs an image decoder, this slice links none on purpose, and that capability arrives over the sidecar protocol alongside OCR. A placeholder fingerprint would collide with every other undecodable image, which is worse than admitting there is none. Shape, format and findings are journaled meanwhile, and they are what an operator asks for first.

## Provenance handles

A `TraceId` is the only thing that will ever be written into an image. Never a tenant, a session or a model: whatever is embedded travels with the file forever, so putting business data there would turn the provenance marker into the exfiltration channel it exists to detect. The identifier is a random handle; the mapping from handle to context stays here.

**61 bits, and the number is not arbitrary.** It is the usable payload of the watermark that has to carry it: `TrustMark`'s Bch5 variant reports `data_bits() == 61` and rejects any other length, measured rather than assumed. Choosing 64 or 128 would produce identifiers that fit the manifest layer and silently fail the watermark layer.

Handles are issued for every inspected image and recorded in `~/.grob/media/trace/YYYY-MM.jsonl` alongside the perceptual fingerprint. The fingerprint is what allows an image whose handle was stripped to still be traced, since it is computed from pixels rather than read from the file.

## Control surface

Three read-only RPC methods, split across two roles on purpose:

| Method | Role | Answers |
|---|---|---|
| `grob/media/verify` | Observer | is this handle known here |
| `grob/media/trace` | Operator | who produced this image |
| `grob/media/fingerprint` | Operator | same, when the handle was stripped |

`verify` names nobody, so it is safe to expose widely. `trace` returns the tenant, which is exactly the fact the opaque handle keeps out of the file, so it costs a rung. Putting both at the same level would undo the reason the identifier is opaque in the first place.

`verify` reports **which layer answered** rather than a bare boolean: a handle read from a signed manifest and one recovered from a fingerprint are both useful and not equally strong, and collapsing that into `true` would hide the difference.

Because these go through `ControlEngine`, they reach CLI, JSON-RPC and the MCP bridge at once.

## Blocking mode

`mode = "blocking"` inspects images before dispatch and can refuse. That raises a question the async path never faces: what happens when the inspection itself fails, through a timeout, an unreachable sidecar, or an open circuit. All three mean the same thing, that the image was never examined.

**The default is to refuse** (`on_failure = "deny"`). An operator who turned on blocking asked for images to be examined before they leave; forwarding the ones we failed to examine would answer a different question than the one they asked, and would do it exactly when something is already wrong.

`on_failure = "allow"` is available for deployments where a stalled sidecar must not become an outage. The trade is explicit, which is why it lives in configuration rather than in a default.

Two refusal reasons are reported distinctly, because they send an operator to different places: `Findings` means the request must change, `NotInspected` means the sidecar must be fixed. Refusals name the rules that fired but never quote the matched values, since those are the secrets themselves.

A missing OCR sidecar is **reduced capability, not failure**: the cheap detectors still run, text simply cannot be read, so a deployment that has not installed OCR is not refusing every image.

## OCR into DLP

The image path adds **no rules**. Extracted text goes through the existing `DlpEngine`, so a screenshot containing an AWS key trips the same rule as a chat message, operators maintain one rule set, and every future DLP improvement reaches images for free.

Normalisation exists because of a measurement, not a hunch. Repairing real OCR errors one at a time showed that a single wrong character defeats a rule, and that survival depends on the *shape* of the pattern: `AKIA[0-9A-Z]{16}` survived `AKIAI` being read as `AKIAT` because the error landed in a character class, while `sk_live_` did not survive `sk_Live_` because a literal prefix forgives nothing. The useful lever is therefore folding the confusions engines actually make, not buying a better engine.

The repairs must **compose**. `ocrs` renders `sk_live_` as `sk Live_`: a dropped underscore *and* a case error in the same literal, where fixing either alone leaves the rule silent.

| Engine | Raw OCR | After normalisation |
|---|---|---|
| macOS Vision | 3/4 secrets | **4/4** |
| ocrs | 3/4 secrets | **4/4** |

Both engines fail differently and normalisation closes both gaps, so the engine choice stays a deployment preference instead of leaking into the security properties.

Normalisation applies to the image path **only**. Loosening the text path would manufacture false positives for every request that never involved an image. Findings carry rule identifiers, never the OCR text, which contains the very secrets that triggered them.

## Sidecars

Three capabilities need machine-learning runtimes or large cryptographic stacks. Linking them in was measured: `c2pa` adds 7.0 MB and `trustmark` 11.9 MB to a 17.3 MB binary, and a vision-language OCR model wants 9-50 GB of RAM. Out-of-process is therefore the default, and one versioned protocol serves all three so they cannot drift apart.

**Stateless by contract.** A request carries no tenant, session, policy or trace field, so a sidecar cannot correlate calls even if it wanted to; a test asserts the serialised request has no such field. Everything stateful stays here, under `~/.grob/media/`. That keeps sidecars hot-swappable, replicable behind any load balancer, and outside the blast radius: a component retaining payloads would be a second copy of the data this slice exists to protect.

**Absent means off.** An unconfigured capability is disabled, not broken. Grob starts and serves with no sidecar installed, and a failing one trips a breaker instead of being retried forever.

Transport is newline-delimited JSON over a unix socket (loopback TCP where unix sockets are unavailable), one request per connection. Endpoints reachable beyond the host are reported by `externally_reachable()` so an operator is warned rather than silently exposed.

A reference implementation lives at [`ocr_sidecar.py`](../../../docs/design/assets/ocr_sidecar.py), about 130 lines, and it really performs OCR: it pipes the image to `GROB_OCR_CMD` (default `ocrs`) on stdin and reads text from stdout, so nothing touches the disk. Any engine with its own calling convention fits by setting that variable, `deepseek-ocr.rs` included via its OpenAI endpoint.

An ignored test drives the Rust client against it end to end, asserting that a planted AWS key survives the whole chain: client, unix socket, JSON framing, sidecar, engine, and back. A protocol is only real once a second, independently written implementation speaks it, and a reference implementation that cannot do the thing is not a reference.

## Non-goals

- Verdicts, redaction or blocking (detectors report; policy decides, later).
- Real steganalysis.
- Watermarking, C2PA manifests, OCR.
- Object or face recognition.
- Video.

## Tests

`scan/tests.rs` covers each detector, the no-payload-in-findings property, totality over truncated inputs, and an ignored cross-check against real system JPEGs (`--ignored`). `tests.rs` covers the decompression-bomb refusal, budget boundaries, lying MIME types, truncated-header totality across all four formats, SSRF refusal, the full perceptual-hash matrix above, the separation gap, and journal append/replay including a torn tail.

## Reachability

Three times in this slice's history, working and fully tested code shipped while nothing called it: the config in #516, the observation entry point in #518, the OCR bridge in #523. Unit tests cannot catch that, because every piece passes in isolation.

`every_entry_point_has_a_caller_outside_its_own_file` reads the source at test time and asserts each entry point still has its caller: `observe_request` in the dispatch path, `scan_ocr_text` in the observation path, `MediaConfig` in the top-level config. Deleting any of those wirings fails the test instead of silently disabling the feature.

## Mutation coverage

Every file in the slice has been checked with `cargo-mutants`, because a passing
test suite says nothing about whether the tests would notice a bug:

| File | Survivors |
|---|---|
| `decode.rs` | 0 |
| `scan/heuristics.rs`, `scan/stego.rs` | 0 |
| `phash.rs` | 1, provably equivalent (`\|` and `^` are identical after a left shift) |
| `registry.rs` | 0 |
| `sidecar/proto.rs`, `sidecar/config.rs` | 0 |
| `blocking.rs` | 0 |
| `trace.rs` | 0 |

Two survivors could not be killed by adding tests, and both indicated a design
problem rather than a coverage gap: a duplicated bounds check in `decode.rs` made
the pre-decode guard unobservable, and a shift-then-set in `phash.rs` was
indistinguishable from its xor equivalent. Both were fixed in the code.

The lesson generalises to the rest of the media work: on byte-level parsing,
asserting the outcome asserts almost nothing. The arithmetic has to be pinned.

## Related design docs

- [`001-image-dlp-provenance.md`](../../../docs/design/001-image-dlp-provenance.md) — layered provenance model and the measurements behind it.
- [`002-media-agents-delivery-plan.md`](../../../docs/design/002-media-agents-delivery-plan.md) — this slice is PR 1.
