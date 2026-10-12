# Contributing to KAC Inspector

Thanks for helping. Contributions of every size are welcome, and the most useful one is
usually the smallest: a missing or misnamed anti-cheat driver.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Adding or fixing a signature

Every known anti-cheat is one entry in [`src/signatures.rs`](src/signatures.rs):

```rust
sig!(
    "Riot Vanguard",
    "Riot Games",
    "VALORANT, League of Legends, TFT, 2XKO",
    ["vgk.sys"],
    ["vgk"],
    ["vgc"]
),
```

The fields are, in order: name, vendor, notable games, driver file patterns, kernel
service-name patterns, and companion user-mode service patterns. Patterns are
case-insensitive and support `*` and `?`.

In the pull request, say where the driver name comes from: a vendor page, a game's install
folder, `sc query type= driver` output, LOLDrivers, or similar. Signatures without a source
are hard to verify.

If you would rather not write code, open a
[new signature issue](https://github.com/saadahmedscse/kac-inspector/issues/new/choose)
with the same information.

## Reporting a bug

Open an [issue](https://github.com/saadahmedscse/kac-inspector/issues/new/choose) with your
Windows version, the KAC Inspector version, whether it ran as administrator, and what you
expected to see. Security problems go through [SECURITY.md](SECURITY.md) instead.

## Working on the code

You need Windows and [Rust](https://rustup.rs) 1.89 or newer.

```bat
cargo build
cargo test
cargo clippy
```

Before opening a pull request:

- `cargo test` passes and `cargo clippy` shows no warnings (the crate enables
  `clippy::pedantic`).
- `cargo fmt` has been run.
- All Windows API calls stay in `src/sys.rs`, which is the only place `unsafe` is allowed.
- The output keeps to the existing palette in `src/style.rs`, and every Unicode glyph has an
  ASCII fallback.

### Layout

| File | What it holds |
|---|---|
| `src/main.rs` | Elevation, the scan loop, and the order of the steps |
| `src/sys.rs` | Every Windows API call |
| `src/signatures.rs` | The anti-cheat database |
| `src/scan.rs` | Matching collected data against the database |
| `src/render.rs` | The report layout |
| `src/loader.rs` | The progress bar |
| `src/menu.rs` | The end-of-scan menu |
| `src/style.rs` | Colours and glyphs |

## Releases

Releases are cut from `master`: bump the version in `Cargo.toml`, add an entry to
[CHANGELOG.md](CHANGELOG.md), tag `vX.Y.Z`, and attach the release build of the executable.
