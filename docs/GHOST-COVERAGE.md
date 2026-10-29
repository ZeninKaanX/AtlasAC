# Ghost client coverage — 0.3.5

AtlasAC performs static file inspection. A match identifies a known file or archive structure; it does not prove execution, injection, server use, or detect a payload that only remains in memory. This is a first expansion, not completion of the all-client goal.

| Client | Verified builds | Detection | Limits |
| --- | --- | --- | --- |
| DoomsDay | Two official loader downloads, previous 0.3.4 samples | Two member SHA-256 values together | Different internals and memory-only remnants not covered |
| Argon | Developer releases `JAR`, `Bugfix` | Three specific main/combat class paths together | Metadata falsely says ImmediatelyFast; benign ImmediatelyFast is not flagged; renamed classes can evade |
| Marlow | Developer releases `v4`, `v5` | Three specific client/combat class paths together | Different class layouts not covered |
| MBTH Ghost Client | Developer release `v0.1.0` DLL | Exact SHA-256 and byte size, including archive members | Only these exact DLL bytes; altered/other builds not covered |
| Vape / Vape Lite | No verified sample | Not supported by a dedicated rule | Official download requires an account; no fabricated signature |
| Whiteout / Entropy / Dream / Drip / Slinky / Raven | No verified sample added | Not supported by a dedicated rule | No guessed filename, URL, generic `ghost` string or client-name rule |

Published sample provenance and exact digests: [ghost-samples-035.json](ghost-samples-035.json). Raw samples are kept outside the repository, not redistributed, and never executed. Five new positive sample files represent **three additional client families**, not five distinct families. The two old DoomsDay files bring this ghost-specific sample set to seven positive files across four named groups. The larger historical general-client corpus is separate.

Linux evidence: [linux-ghost-real-035.json](linux-ghost-real-035.json), 24 checks. Each positive is checked after renaming and nesting; Java positives are also repacked with all metadata removed. Two genuine normal mods (ImmediatelyFast, Sodium) produce no findings. Cold and cached whole-scope runs both publish all seven expected live/final findings. These are static tests of real published files, not tests of injected/self-destructed clients in a running game.

Reproduce against the exact sample files named in the manifest:

```sh
python tools/validate_ghost_samples.py --samples-dir /private/samples --output ghost-validation.json
```

The new five positives and two benign controls can be downloaded and checked explicitly:

```sh
python tools/validate_ghost_samples.py --expansion-only --download --samples-dir /private/samples --output ghost-validation.json
```

Download validation rejects changed bytes and never runs downloaded code. CI executes this second command on Windows and Linux and saves a separate validation artifact. The old randomized DoomsDay URL cannot reproduce an identical whole-file digest; the existing pinned file must be supplied for the full test. Future tested builds need a new manifest entry rather than quietly replacing old evidence.

Rules do not add a running-process memory reader. Existing directory exclusions, candidate extensions, CPU budget, ten-minute deadline and partial-result reporting still apply; a matching file can remain outside reached scope. No claim of 200 different verified cheat families or universal detection is made.

Developer sources: [Argon releases](https://github.com/LvStrnggg/argon/releases), [Marlow releases](https://github.com/nxghtCry0/marlowwwclient/releases), [MBTH v0.1.0](https://github.com/mbth-studios/MBTH-GHOST-CLIENT/releases/tag/v0.1.0), [Vape installation documentation](https://docs.vape.gg/intro/install).
