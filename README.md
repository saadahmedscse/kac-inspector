# KAC Inspector

**Kernel anti-cheat inspector for Windows.** One command tells you which kernel-mode anti-cheat
drivers are on your machine, which of them are live in the kernel right now, and which are
leftovers from games you uninstalled long ago.

It reads the answer straight from Windows. It does not install anything, change anything, or
talk to the network.

## What it reports

For each of the 43 known kernel anti-cheats, KAC Inspector checks three places:

- **The kernel module list** (`EnumDeviceDrivers`): what is actually mapped in kernel memory.
- **The Service Control Manager**: every registered kernel driver service and its companion
  user-mode service, with start type and state.
- **The driver store** (`%SystemRoot%\System32\drivers`): the `.sys` files on disk.

Each driver it finds gets one of these states:

| State | Meaning |
|---|---|
| `running` | Loaded in the kernel, and its service is running |
| `loaded` | In kernel memory, with no running service entry |
| `pending` | Its service is starting or stopping |
| `stopped` | Installed and idle |
| `orphaned` | The service is registered but its `.sys` file is gone |
| `stale` | A `.sys` file left on disk with no service |

Drivers that are not in the database but describe themselves as an anti-cheat (for example
"game guard" or "anti-cheat" in their name or description) are reported too, marked as
matched by name.

The report leads with the verdict (**kernel clean**, or how many anti-cheats are live), then a
card per detection, then a coverage strip showing all 43 signatures at a glance.

## Download

Grab `kac-inspector-v1.0.0-windows-x64.exe` from the
[latest release](https://github.com/saadahmedscse/kac-inspector/releases/latest) and run it.
It asks for administrator rights through UAC; recent Windows builds only reveal the kernel
module list to an elevated process. If you decline, it still runs and reports what it can
see from the Service Control Manager.

When the scan finishes, use <kbd>↑</kbd> <kbd>↓</kbd> and <kbd>Enter</kbd> to scan again or
exit (<kbd>Esc</kbd> also exits).

**Requirements:** Windows 10 or 11, x64.

## Build from source

You need [Rust](https://rustup.rs) 1.89 or newer.

```bat
build.bat
```

That runs `cargo build --release` and copies the result next to the script as
`KAC Inspector.exe`. Or build it yourself:

```bat
cargo build --release
```

The binary lands in `target\release\kac-inspector.exe`.

## Options

| Environment variable | Effect |
|---|---|
| `NO_COLOR` | Plain text, no colour |
| `KAC_ASCII` | ASCII glyphs instead of Unicode, for consoles without a font that has them |

Output that is piped or redirected is written without colour or animation, and the program
exits after one scan instead of showing the menu.

## Supported anti-cheats

| Anti-cheat | Vendor | Notable games | Driver |
|---|---|---|---|
| Riot Vanguard | Riot Games | VALORANT, League of Legends, TFT, 2XKO | `vgk.sys` |
| BattlEye | BattlEye Innovations | PUBG, R6 Siege, Tarkov, DayZ, Destiny 2, GTA V | `BEDaisy*.sys` |
| Easy Anti-Cheat (EOS) | Epic Games | Fortnite, Elden Ring, Rust, Dead by Daylight | `EasyAntiCheat_EOS*.sys` |
| Easy Anti-Cheat (Legacy) | Kamu / Epic Games | Older EAC titles (pre-EOS builds) | `EasyAntiCheat.sys`, `EasyAntiCheat_x64.sys`, `EasyAntiCheat_x86.sys` |
| EA Javelin Anticheat | Electronic Arts | Battlefield 6, BF2042, EA SPORTS FC, Apex Legends | `EAAntiCheat*.sys` |
| RICOCHET Anti-Cheat | Activision | Call of Duty: BO6 / BO7, MW III, Warzone | `*randgrid*.sys` |
| Denuvo Anti-Cheat | Irdeto | THE FINALS, ARC Raiders, R6 Extraction | `denuvo-anti-cheat*.sys`, `denuvo*anticheat*.sys` |
| FACEIT Anti-Cheat | FACEIT | CS2, Dota 2 (FACEIT platform) | `faceit*.sys` |
| ESEA Anti-Cheat | ESEA | CS2 (ESEA platform) | `ESEADriver*.sys` |
| EQU8 | EQU8 / 1047 Games | Splitgate, KovaaK's, Aimlabs | `EQU8*.sys` |
| RedKard | 1047 Games | Splitgate 2 | `RedKard*.sys` |
| PunkBuster | Even Balance | Battlefield 3 / 4 / 1, legacy titles | `PnkBstrK*.sys` |
| Anti-Cheat Expert (ACE) | Tencent | Delta Force, Wuthering Waves, Arena Breakout, NIKKE | `ACE-*.sys` |
| TenProtect (TP) | Tencent | Ring of Elysium, CrossFire, legacy Tencent titles | `TesSafe*.sys`, `TP3Helper*.sys`, `TenSafe*.sys` |
| TerSafe Game Protect (legacy) | Tencent (attributed) | Legacy Tencent titles | `GameTerSafe*.sys`, `TerSafe*.sys` |
| NetEase Anti-Cheat (NEAC) | NetEase | Marvel Rivals, Naraka, Once Human, FragPunk | `*NeacSafe*.sys`, `Neac*.sys` |
| Seasun Protect | Kingsoft Seasun | Mecha BREAK, Snowbreak: Containment Zone | `SeasunProtect*.sys` |
| KSophon | Hotta / Perfect World | Tower of Fantasy, Neverness to Everness | `KSophon*.sys`, `GameDriverX64*.sys` |
| miHoYo Protect (mhyprot) | miHoYo / HoYoverse | Genshin Impact, Honkai: Star Rail, Honkai 3rd | `mhyprot*.sys` |
| HoYoKProtect | HoYoverse | Zenless Zone Zero, newer HoYoverse titles | `HoYoKProtect*.sys`, `HoYoProtect*.sys` |
| Perfect World Arena AC | Perfect World | CS2 (Perfect World esports platform) | `MessageTransfer*.sys` |
| YY Protect | YY Inc. | YY game / voice platform titles | `yyprotect*.sys` |
| KGameProtect | Unattributed | Unknown (listed on LOLDrivers) | `kgameprotect*.sys` |
| Zakynthos | KRAFTON | PUBG: Battlegrounds, PUBG: Black Budget | `navagio*.sys`, `zakynthos*.sys` |
| UNCHEATER | Uncheater | PUBG, Eternal Return, PUBG Lite | `uncheater*.sys` |
| XIGNCODE3 | Wellbia | Trove, Ragnarok, Knight Online, DJMAX | `xhunter*.sys` |
| nProtect GameGuard | INCA Internet | Helldivers 2, Lineage II, Star Stable | `dump_wmimmc.sys`, `npptNT*.sys` |
| nProtect KeyCrypt | INCA Internet | MapleStory and other Nexon titles | `npkc*.sys` |
| AhnLab HackShield | AhnLab | Dungeon Fighter, Mabinogi, War Rock (legacy) | `EagleNT*.sys`, `EagleXNt*.sys` |
| X-Trap | WiseLogic | NosTale, GrandChase, Knight Online, Metin2 | `XDva*.sys` |
| Nexon Game Security (BlackCipher) | Nexon | MapleStory, The First Descendant, Vindictus | `BlackCat*.sys`, `BlackCipher*.sys` |
| WFSDrv | Wright Flyer Studios | ANOTHER EDEN, Heaven Burns Red | `wfsdrv*.sys` |
| IronShield (Tavern) | Ironmace | Dark and Darker | `Tavern*.sys`, `IronShield*.sys` |
| MRAC (Mail.Ru Anti-Cheat) | Mail.Ru / MY.GAMES | Warface, Allods, Conqueror's Blade, War Robots | `mracdrv*.sys` |
| MY.GAMES Anti-Cheat | MY.GAMES | War Robots: Frontiers, Warface: Clutch, HAWKED | `myacdrv*.sys` |
| 4game Guard / Frost | Innova / 4game | Lineage II, AION (EU), Ragnarok Online Prime | `frost.sys`, `frost64.sys`, `frost_x64.sys`, `frostdrv*.sys` |
| SARD Anti-Cheat | SARD | APB Reloaded, AION, Blade & Soul, TDU Solar Crown | `SARD*.sys` |
| Akros Anti-Cheat | Akros AntiCheat LLC | ChallengerMode (CS2, Dota 2, LoL, PUBG) | `Akros*.sys` |
| EMAC Anti-Cheat | EMAC LAB / Gamers Club | CS2 (Gamers Club platform) | `EMAC-Driver*.sys`, `EMAC*.sys` |
| Gamers Club Anti-Cheat (legacy) | Gamers Club | CS2 / CS:GO (Gamers Club platform) | `GCSYS*.sys` |
| Esportal Anti-Cheat | Esportal AB | CS2, Dota 2 (Esportal platform) | `EspoDriver*.sys` |
| FastCup myAC | FastCup | CS2 (FastCup platform) | `acdev*.sys` |
| GamersFirst Anti-Cheat (GFAC) | Little Orbit | APB Reloaded (legacy) | `GFAC*.sys` |

Driver names are case-insensitive wildcard patterns. Sources: AreWeAntiCheatYet, SteamDB
detection rules, LOLDrivers, vendor support pages, CVE records and community reports.

**Out of scope:** user-mode anti-cheats (VAC, Hyperion/Byfron, Warden) have no kernel driver,
and server-side or AI anti-cheats (FairFight, AnyBrain, Kaspersky AC, NetEase Yidun) leave no
kernel footprint.

## Contributing

Found an anti-cheat driver that is missing or misnamed? See
[CONTRIBUTING.md](CONTRIBUTING.md); a new signature is usually a one-line change.

## Disclaimer

KAC Inspector is an independent project. It is not affiliated with or endorsed by any of the
companies whose products it detects. All product names are trademarks of their respective
owners. It only reads system state; it does not disable, remove or tamper with any driver.

## License

[MIT](LICENSE) © Saad Ahmed · [saadahmedev.com](https://saadahmedev.com)
