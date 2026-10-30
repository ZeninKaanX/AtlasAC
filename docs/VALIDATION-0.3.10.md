# AtlasAC 0.3.10 validation

The 0.3.9 draft remains unpublished after [run 41049045759](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41049045759) passed all individual probes but failed both Ubuntu system passes (16/17 of 18 expected findings, 14 issues each). A diagnostic revision adds complete archive issues, missing/unexpected paths, CPU target and wall/CPU timing to the cohort artifact; expectations and reader limits remain unchanged.

## CPU pacing defect

The old pacing loop woke every 50 ms and waited only until CPU credit reached zero. On a slow scheduler the CPU cost of waking can consume that credit, repeatedly deferring productive reads. A deterministic clock/cost regression reproduces this starvation on old code and passes after the fix. Readers now wait for a work burst; Event.wait remains immediately interruptible by cancellation. CPU targets and wall-clock archive/scan limits are unchanged. This establishes a pacing defect, but does not by itself prove the exact cause of every previous remote failure.

A local development comparison held the same 22 pinned files, two readers and 0.1-core target: old system passes took 50.24 / 43.63 seconds and 5.06 / 4.40 CPU seconds; fixed passes took 6.04 / 7.18 seconds and 0.62 / 0.75 CPU seconds. Both versions found all 18 expected matches in this local comparison. The fixed [60-check report](lowcpu-ghost-real-0310.json) preserves two expected malformed-metadata issues, live findings and zero persistent cache hits. Samples were inspected statically, never executed. These small-fixture measurements are not a full-computer benchmark or a general speed guarantee.

The local development suite passed 93 tests (one Windows-only case skipped), including shared CPU pacing and prompt concurrent cancellation. Final platform CI and package provenance will be recorded before publishing.
