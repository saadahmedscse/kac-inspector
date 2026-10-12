# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-12

First public release.

### Added

- Detection of 43 known kernel anti-cheat drivers from the kernel module list, the Service
  Control Manager and the driver store, plus a name heuristic for unlisted ones.
- Live state for each driver: running, loaded, pending, stopped, orphaned or stale, with
  companion user-mode services.
- Answer-first report: verdict, a card per detection, and a coverage strip of every
  signature.
- Animated progress bar while scanning, and an arrow-key menu to scan again or exit.
- Automatic elevation through UAC, with a standard-user fallback.
- `NO_COLOR` and `KAC_ASCII` support; plain output when piped.

[1.0.0]: https://github.com/saadahmedscse/kac-inspector/releases/tag/v1.0.0
