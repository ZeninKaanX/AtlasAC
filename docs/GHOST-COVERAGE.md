# Ghost client coverage — 0.3.6

AtlasAC performs static file inspection. A match identifies a known file or archive structure; it does not prove execution, injection or server use. Memory-only or deleted payloads are not covered. This expansion does not complete the all-client goal.

| Named project/group | Verified published builds | Detection |
| --- | --- | --- |
| DoomsDay | Two official 0.3.4 loader samples | Two member SHA-256 values together |
| Argon | `JAR`, `Bugfix` | Three specific main/combat class paths |
| Marlow | `v4`, `v5` | Three specific client/combat class paths |
| MBTH Ghost Client | `v0.1.0` DLL | Exact SHA-256 and byte size |
| Hydrogen ghost client (zPeanut) | `1.12.5`, `1.12.4` | Three specific combat class paths |
| Nemui | `v1.5-forge`, `v1.5` Weave | Three specific client/ghost class paths |
| VOX | `0.1.1` | Three specific client/combat class paths |
| Lumina | `lumina-client-alpha-2.6.1`, `2.4.8` | Three specific client/combat class paths |
| Zyklon | `4.1`, `4.0` published ZIP packages and inner payloads | Three specific combat class paths inside `bin/cloud/public/client.jar` |
| Fusion+ | `v0.0.4`, `v0.0.3` DLL | Exact SHA-256 and byte size |
| Wraith | Linux `v1.0.0`, `v1.0a` | Exact SHA-256 and byte size; `.AppImage` is now eligible |

This is **20 positive sample files across 11 named projects/groups**, including **13 newly added files across seven projects**. Releases, repackings, related projects and derivatives are not counted as independent cheat architectures. The historical general-client corpus is separate. Native hash rules cover only the exact pinned bytes, not all variants. Java class paths can be renamed or copied; three paths together reduce weak name-only matches but do not provide an unforgeable identity.

## Real sample checks

[ghost-samples-036.json](ghost-samples-036.json) pins download URLs, byte sizes and SHA-256 values. Raw samples are outside the repository, never redistributed and never executed.

[linux-ghost-real-036.json](linux-ghost-real-036.json) contains **66 checks** over the full set:

- Real positives after renaming and placing inside an archive.
- Java positives repacked with all metadata removed.
- Zyklon's extracted client payload tested separately from its distribution ZIP.
- Cold and cached whole-scope scans, with every expected finding present in live updates and the final report. The real Wraith files use `.AppImage` filenames in this path, rather than only calling the per-file inspector directly.
- Four benign distribution files: ImmediatelyFast, Sodium, CaffeineMC's **normal Hydrogen optimization mod**, and Microsoft's Sigcheck ZIP. The three Sigcheck EXE members are also checked separately. All produce no findings. Matching the generic `hydrogen` mod ID alone would wrongly accuse the normal CaffeineMC mod; that rule is deliberately absent.

The two real Hydrogen ghost releases contain malformed JSON metadata (a literal newline inside a JSON string). Their specific class signatures still match. The scan explicitly retains the metadata read issue and **partial status** on both cold and cached passes; partial metadata inspections are not reused as completed cache results. The manifest lists the exact expected issue reasons. An unrelated issue still fails validation. Twenty detections do not mean twenty fully readable metadata records.

CI validates the 0.3.6 expansion cohort on both Windows and Ubuntu using `--expansion-only`: 18 positive files, four benign distributions, **60 checks**. The two previously pinned DoomsDay samples are excluded from automated re-download because the randomized endpoint cannot reproduce the same outer bytes. Earlier Windows evidence is retained in [windows-doomsday-real-034.json](windows-doomsday-real-034.json). The Windows report is retained in [windows-ghost-real-036.json](windows-ghost-real-036.json); CI reports are also uploaded as separate workflow artifacts. Both platforms passed 69 automated tests. [CI run](https://github.com/ZeninKaanX/AtlasAC/actions/runs/40964517596).

## Important distinctions

Argon's genuine tested files claim the benign ImmediatelyFast identity. Their normal metadata ID is never itself a cheat rule; specific Argon classes are required, and its misleading benign icon is suppressed. Nemui and Lumina have original embedded branding icons with provenance in [CLIENT-ICONS.json](CLIENT-ICONS.json); there are 20 bundled client icons in total. Atlas remains the fallback where no suitable icon is available.

Only the actual Fusion+ client DLLs are pinned. A generic injector executable is not automatically equated with the cheat it could load. Wraith is a Linux payload; recognizing its static bytes when inspecting files on Windows does not mean that Wraith itself runs on Windows. `.AppImage` coverage is exact-file detection, not a general SquashFS/embedded filesystem scanner.

Vape/Vape Lite, Whiteout, Entropy, Dream, Drip, Slinky and Raven still have **no verified dedicated rule**. Slinky's official download requires a license key, Entropy directs to account login, and Vape's official installation requires account access. No account/license bypass or guessed brand-string signature is used. Local authorized samples are needed before claiming detection of these builds.

## Reproduce

Download exact sample files separately under the manifest's `file` names, then run:

```sh
python tools/validate_ghost_samples.py --samples-dir /private/samples --output ghost-validation.json
```

Fetch and validate the re-downloadable cohort explicitly:

```sh
python tools/validate_ghost_samples.py --expansion-only --download --samples-dir /private/samples --output ghost-validation.json
```

The downloader rejects changed bytes and never executes a sample. To reproduce the older 0.3.5 cohort, add `--manifest docs/ghost-samples-035.json`. Downloaded native binaries should remain non-executable data files in the test directory. No Defender, audit, game, or protection setting is changed.

Existing candidate extensions, directory exclusions, CPU budget, ten-minute deadline and partial-result reporting still apply. Known game/SDK caches remain archives-only; a matching native file can remain outside reached scope. There is no claim of universal detection, process-memory scanning, injected/self-destructed client recovery, or 200 independent verified cheat families.

Developer sources: [Hydrogen ghost](https://github.com/zPeanut/Hydrogen/releases), [Nemui](https://github.com/SleepyFish-YT/Nemui/releases), [VOX](https://github.com/ShimadaNanaki/vox-client/releases), [Lumina](https://github.com/stormcoph/LuminaClient/releases), [Zyklon](https://github.com/jeopardization/Zyklon/releases), [Fusion+](https://github.com/h1meji/fusion-plus/releases), [Wraith](https://github.com/decryller/wraith/releases), [normal Hydrogen](https://github.com/CaffeineMC/hydrogen-fabric/releases), [Slinky download](https://slinky.gg/download/), [Entropy login](https://entropy.club/dashboard/login), [Vape installation](https://docs.vape.gg/intro/install).
