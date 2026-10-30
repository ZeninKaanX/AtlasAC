# AtlasAC 0.3.8 validation

Final application source: `5093503` (core changes `3935bf8`, malformed receipt handling `0b00362`).
[Windows / Ubuntu CI](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41046678887).

- 92 tests: Windows all passed; Linux 91 passed / one Windows-only DACL test skipped. Tests include actual spawned workers and native Qt flows.
- A real on-disk JAR fixture was inspected, its SQLite cached result was replaced with a false empty result, and the next scan still detected it. Direct `probe(cached=forged)` also reinspected the original bytes. No persistent result cache was accepted.
- Modified/empty rules are rejected; formatting-only changes retain the same canonical digest. Duplicate JSON keys are rejected. Native Linux CLI rules gate and source GUI rejection were exercised.
- A worker fixture published a live match then omitted it from its final report; the parent retained it and marked the result partial. Malformed progress after a live match retained the match. Wrong sessions/sequences, regressing counters, changed roots and removed partial-coverage records are rejected. These are consistency tests, not proof against a compromised process/host.
- Edited reports fail checksum comparison. Removing the receipt does not fall back to a verified legacy report. The history writer does not silently reseal an existing invalid receipt. A deliberately recomputed checksum passes self-consistency but fails against the separately retained original digest; no digital-signature/host-authenticity claim is made.
- Frozen Windows and Linux report verifier: three cases each — original accepted; removed findings rejected against original digest; player-recomputed checksum rejected against original digest. Output flags explicitly state no signature and no host verification.
- Local Linux full pinned cohort: [66 checks](linux-ghost-real-038.json), 20 positive files plus benign controls; native CLI over the same cohort retained 20 matches / two expected malformed-metadata issues / partial status. Samples were not executed.
- Final CI [Windows](windows-ghost-real-038.json) and [Ubuntu](ubuntu-ghost-real-038.json): 60 checks each, over the re-downloadable 18-positive / four-benign cohort. Both system passes reread candidate content; `cache_hits` remains zero. The historical `cached-system` result label is retained only for comparison with earlier manifests; it now means a second scan without persistent results.
- A full local repeat using a fixed `ScanControl(cores=0.1)` passed all [60 checks](lowcpu-ghost-real-038.json) in approximately 64 seconds for this small fixture workload, including static variants and two small system scans. This is not a full-PC benchmark or a guarantee for other hardware/load.
- Local frozen module/assets match current source via `tools/verify_bundle.py`. The final Windows PE/resources were checked against the CI checkout; Python-version-dependent bytecode is not compared across Python 3.13/3.14.

## Earlier failed run retained in the record

[Earlier run](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41045538607) passed Windows but its Ubuntu real-sample step reported `all_passed:false` after 60 checks. That revision did not print per-check failures or upload the JSON on failure, so the individual failure and its cause could not be recovered. The final revision adds failed-check output and `always()` report upload; it does **not** relax match/issue expectations or production time/CPU limits. Subsequent final CI and the explicit low-CPU repeat passed. The earlier failure must not be described as diagnosed or as proof of universal reliability.

Production still has 590 seconds total scan time, per-reader limits, a shared CPU target and partial results when coverage is incomplete. Persistent cache removal can increase repeated-scan work. SHA-256 receipts are unsigned; same-user/admin code patching, OS hooks, fake screenshots and jointly forged report/digest remain outside a local-only trust guarantee. See [LOCAL-INTEGRITY.md](LOCAL-INTEGRITY.md).
