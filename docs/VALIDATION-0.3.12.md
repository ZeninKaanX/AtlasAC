# AtlasAC 0.3.12 validation

## Behavior and scope

- Actual native Qt scan: a real on-disk JAR fixture produces a live finding before the worker finishes. A mouse double-click opens a nonmodal detail snapshot while the worker is still running; later table changes do not replace the open record. Growing/rolling models preserve a persistent selected record. A manual native preview also exercised live details, background and fish/shark drawing.
- Concurrent discovery uses a bounded archive-priority queue and an anonymous private disk spool for other pending paths; it contains no findings/clean verdicts. Candidate bytes are still freshly opened. No directory-name trust or additional extension exclusions were introduced. A 1,106-candidate spool test covers multiple buffers, priority and Unicode paths without lost/duplicate candidates.
- Percentages are based on processed candidates only after their discovered total is fixed. ETA waits for measured throughput and is withheld when stale. The parent validates these counters/percentages; unknown discovery totals cannot be reported as a definite percentage. This is candidate-file progress, not a promise of complete device coverage or precise collector duration.
- Metadata index now stores recognized formats and candidates with read/inspection issues. Other candidates are still probed; the fixture test checks 601 processed candidates including a renamed JAR while only one recognized file is indexed. Persistent results are never trusted. Index write failure retains the actual live finding and marks the report partial.
- Low CPU default is preserved. Balanced/fast explicitly increase the shared CPU target. A real spawned-worker test verifies the selected target reaches the scanner. A synthetic slow-open measurement test exercises increasing the reader count; it is not a real slow-disk performance benchmark.

## Performance evidence

[Paired development measurements](speed-0312.json) use 20,001 generated files actually written to disk, including 15,001 candidates and 5,000 skipped PNG files, with one controlled Meteor metadata fixture. These are not 20,001 genuine cheat samples. Both low-CPU versions use 0.4 cores, no GUI/collectors and separate fresh indexes. The host had other workloads; timing varies.

Baseline passes: 28.07 / 25.74 seconds; new low-CPU passes: 24.29 / 24.72 seconds (about 9% lower mean wall time in this comparison). Detection, content-file, processed-candidate, skipped-image and issue counts match. The focused index writes 5,001 records rather than 15,001. An earlier per-file-task prototype regressed and was replaced with batched reader loops before release.

New fast mode: 8.90 seconds with a **1.2-core** target rather than 0.4; approximately 9.44 CPU seconds. This speed improvement spends more CPU per second and must not be described as equal-CPU performance. No one-hour/850k-file scan or Windows hardware speed guarantee was established. Final index maintenance/ETA/UI refinements are also covered by tests; the measurements document development behavior, not a universal final-release benchmark.

Final platform CI and build provenance are recorded before publication.
