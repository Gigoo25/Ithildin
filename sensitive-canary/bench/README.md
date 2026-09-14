# Synthetic detection checks

## Historical report is not a before/after baseline

`baseline.json` is retained unchanged for provenance. It was captured after
implementation and fixture edits. It cannot substantiate improvement over the
pre-implementation working tree. `corpus.ts` remains the historical comparison
set; its incomplete expectations/support classifications are not acceptance
criteria. Version 2 reports it separately rather than silently repairing its
results or comparing incompatible metrics.

`review-corpus.ts` is a separate, newly authored acceptance set. It covers the
review's credential/header, cookie, identity, home/host, financial checksum,
code/hash/version/lockfile, actual window-seam, JSON and assignment regressions.
`review.test.ts` enforces exact authored ranges and preservation expectations.
It also proves the metrics catch deliberately missing, excessive, partial and
whole-document-omission transformations. This is not an exhaustive credential
corpus or evidence about real model task performance.

## Metrics and gates

The real hooks emit optional synchronous, value-free source-range audit data to
the local harness. No observer is installed during normal operation. Cookie
coordinate changes are mapped back to original source ranges.

- Detection misses count authored sensitive occurrences not fully covered by
  direct detections; repeated-value rendering is not itself a new detector hit.
- Exposure counts original sensitive source characters outside replacement and
  omission ranges, including partial fragments. It is not an entropy estimate
  or a character-by-character comparison with coincidentally similar fake data.
- False redactions count explicitly harmless source occurrences intersecting an
  edit or omission. Equal snippets elsewhere cannot hide collateral damage.
- Omissions, omitted character counts and document syntax failures are separate.
- Unsupported/limitation fixtures and unavailable coordinate measurements never
  count as successful detections.

Run with an isolated HOME and no personal configuration, using runtime-resolved
executables. `node bench/run.ts --check` exits nonzero on any new acceptance-set
miss, exposure, false redaction, omission, syntax error or unavailable measurement.
Nix runs this gate plus Bun and the production Node budget/safety tests.

`--timing` adds one cold scan per fixture in a fresh Node process (module imports
excluded) and five warm scans per fixture in the parent process. Each scan uses
an independent session and resets extension caches; JIT may remain warm. Reports
contain per-fixture sample counts and min/p50/p95/max, runtime and fingerprints.
One cold sample is not a statistically robust latency distribution. Timing is
observational, not a machine-independent threshold. No network/model calls run.

## Intentional policy changes

- Direct findings retain their locations; unique-value dedupe is ledger-only.
- Propagated occurrences participate in the same overlap/omission union as direct
  findings. Secrets win, union replacements use the full original union slice.
- PII repetitions embedded in larger Unicode identifiers remain unchanged;
  path, dotted and hyphen-separated occurrences remain protected. This is an
  explicit tradeoff, not universal recognition of private names.
- JSON edits expand to scalar envelopes and rendered JSON is validated. Unsafe
  unions, parser/resource failures and exhausted deadlines omit the text.
- Explicit numeric document fields become quoted synthetic strings. Their numeric
  equality does not classify unrelated counters or quoted strings as PII. Tool
  output notices disclose this type-change policy; provider numeric primitives
  are not rewritten by document scanning.
- Nonempty explicit credential fields no longer exempt weak example-like words.
  Empty/null/boolean sentinels remain intact. Shape synthesis falls back to a
  secret label if it would otherwise leave the value unchanged.
- Bearer matching retains the same credential pattern but captures only the
  token, preserving the header prefix (a measured collateral-redaction fix).

The existing 65,536-character structured-document ceiling is retained. Oversized
JSON or oversized recognized assignments now omit explicitly; long ordinary text
still uses windowed scanning. Parsing/rendering share the existing deadline.
No global entropy threshold or scan-time allowance was increased.

Pi core and network routing are unchanged. This extension remains defense in
depth: unexpected errors elsewhere and request routes outside its hooks are not
made into a mandatory transmission boundary.
