# AtlasAC 0.3.11 validation

Application source: `2a5ffbc9cc635b62ddd092833ed3533c868245a3`.

- An actual spawned worker scans a real on-disk Meteor JAR, publishes a live match and waits at a controlled gate. The parent clock then advances by 7,201 seconds; the default scan continues and accepts the complete result with the match preserved. This uses accelerated elapsed time, not a claim that the test waited two hours.
- The same worker scenario with an explicit 7,200-second budget and a 601-second clock advance completes, proving the opt-in limit is not silently reduced to the old 590-second cap.
- Without a total deadline, cancelling a stalled worker still terminates it promptly and retains the observed snapshot. The existing explicit 1.5-second deadline test still terminates a stalled worker and preserves partial coverage.
- Nonpositive, NaN and infinite explicit budgets fail before creating a worker.
- The native Qt flow scans a real JAR and reports `time_budget_seconds: null`, covering the desktop-to-worker default. Existing live-result, refusal and result-display tests remain included.
- Local suite: 96 tests run; 95 passed and one Windows-only DACL case skipped. CPU pacing, per-file/archive bounds, privacy and report integrity behavior are preserved.

[CI run 41087831930](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41087831930) completed successfully on both platforms: Windows 96 tests passed; Linux 95 passed and one Windows-only DACL test skipped. Each platform passed the unchanged 60-check pinned static sample cohort, same-interpreter frozen module/assets comparison, and all three report-receipt verification cases. Published binaries come from this exact CI source. Linux was built on Ubuntu 24.04 / glibc 2.39; older distributions were not tested.
