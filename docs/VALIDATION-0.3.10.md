# AtlasAC 0.3.10 validation

The 0.3.9 draft remains unpublished after [run 41049045759](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41049045759) passed all individual probes but failed both Ubuntu system passes (16/17 of 18 expected findings, 14 issues each). A diagnostic revision adds complete archive issues, missing/unexpected paths, CPU target and wall/CPU timing to the cohort artifact; expectations and reader limits remain unchanged.

## CPU pacing defect

The old pacing loop woke every 50 ms and waited only until CPU credit reached zero. On a slow scheduler the CPU cost of waking can consume that credit, repeatedly deferring productive reads. A deterministic clock/cost regression reproduces this starvation on old code and passes after the fix. Readers now wait for a work burst; Event.wait remains immediately interruptible by cancellation. CPU targets and wall-clock archive/scan limits are unchanged. This establishes a pacing defect, but does not by itself prove the exact cause of every previous remote failure.

A local development comparison held the same 22 pinned files, two readers and 0.1-core target: old system passes took 50.24 / 43.63 seconds and 5.06 / 4.40 CPU seconds; fixed passes took 6.04 / 7.18 seconds and 0.62 / 0.75 CPU seconds. Both versions found all 18 expected matches in this local comparison. The fixed [60-check report](lowcpu-ghost-real-0310.json) preserves two expected malformed-metadata issues, live findings and zero persistent cache hits. Samples were inspected statically, never executed. These small-fixture measurements are not a full-computer benchmark or a general speed guarantee.

The local development suite passed 93 tests (one Windows-only case skipped), including shared CPU pacing and prompt concurrent cancellation. Final platform results and package provenance are recorded below.

## Remote diagnostic and fixed cohort

The diagnostic [old-code Ubuntu run](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41054816040) retained [full failure details](ubuntu-ghost-diagnostic-039.json): at a 0.2-core target both system passes found 18 matches but took 137.03 / 144.29 seconds, consuming 27.43 / 28.89 CPU seconds and reporting 7 / 6 issues, including archive timeouts. The original 0.3.9 run had also lost matches; this diagnostic repeat demonstrates the failure varies with timing.

The fixed [CI cohort](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41055401738) passed all 60 checks on both [Linux](linux-ghost-real-0310.json) and [Windows](windows-ghost-real-0310.json). At the same 0.2-core target, Linux system passes took 3.68 / 3.52 seconds and 0.76 / 0.71 CPU seconds; Windows took 5.04 / 4.66 seconds. Both platforms retained all expected final/live matches and exactly the two expected malformed-metadata issues; no extra archive timeouts. No expected match/issue or time/CPU limit was relaxed. Runner timing is variable and these are small-fixture measurements.

## Final release build

Final application/build-workflow source: `e8e28718d6b894ce2c1da92cfaa071ee261a294a`. [CI 41055401738](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41055401738) completed successfully on both platforms: Windows 93 tests passed; Linux 92 passed and one Windows-only DACL test skipped. Both frozen packages passed same-interpreter code/asset comparison and all three report-receipt cases. The published executables come from that exact CI run. Linux was built on Ubuntu 24.04 / glibc 2.39; compatibility with older distributions was not tested.

The old-code diagnostic failure is preserved; it is not hidden by increasing deadlines or changing expected findings. Consistency checks remain local and unsigned; privileged host manipulation and unknown cheat families are outside guarantees.
