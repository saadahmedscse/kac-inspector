//! The signature database: kernel anti-cheat drivers documented publicly, sourced from
//! `AreWeAntiCheatYet`, `SteamDB` detection rules, `LOLDrivers`, vendor support pages, CVE records
//! and community reports.
//!
//! Patterns are case-insensitive wildcards (`*` and `?`), matched the way PowerShell's
//! `-like` matches them.

/// One known kernel anti-cheat.
#[derive(Debug)]
pub struct Signature {
    /// The anti-cheat's name.
    pub name: &'static str,
    pub vendor: &'static str,
    /// Notable games that ship it.
    pub games: &'static str,
    /// Driver file patterns.
    pub drivers: &'static [&'static str],
    /// Kernel service-name patterns.
    pub services: &'static [&'static str],
    /// Companion user-mode service patterns.
    pub companions: &'static [&'static str],
}

macro_rules! sig {
    ($name:expr, $vendor:expr, $games:expr, [$($d:expr),*], [$($s:expr),*], [$($c:expr),*]) => {
        Signature {
            name: $name,
            vendor: $vendor,
            games: $games,
            drivers: &[$($d),*],
            services: &[$($s),*],
            companions: &[$($c),*],
        }
    };
}

pub const DB: &[Signature] = &[
    // ---- Global / Western -------------------------------------------------------------------
    sig!(
        "Riot Vanguard",
        "Riot Games",
        "VALORANT, League of Legends, TFT, 2XKO",
        ["vgk.sys"],
        ["vgk"],
        ["vgc"]
    ),
    sig!(
        "BattlEye",
        "BattlEye Innovations",
        "PUBG, R6 Siege, Tarkov, DayZ, Destiny 2, GTA V",
        ["BEDaisy*.sys"],
        ["BEDaisy*"],
        ["BEService*"]
    ),
    sig!(
        "Easy Anti-Cheat (EOS)",
        "Epic Games",
        "Fortnite, Elden Ring, Rust, Dead by Daylight",
        ["EasyAntiCheat_EOS*.sys"],
        ["EasyAntiCheat_EOS*"],
        ["EasyAntiCheat_EOS"]
    ),
    sig!(
        "Easy Anti-Cheat (Legacy)",
        "Kamu / Epic Games",
        "Older EAC titles (pre-EOS builds)",
        [
            "EasyAntiCheat.sys",
            "EasyAntiCheat_x64.sys",
            "EasyAntiCheat_x86.sys"
        ],
        ["EasyAntiCheat", "EasyAntiCheatSys"],
        ["EasyAntiCheat"]
    ),
    sig!(
        "EA Javelin Anticheat",
        "Electronic Arts",
        "Battlefield 6, BF2042, EA SPORTS FC, Apex Legends",
        ["EAAntiCheat*.sys"],
        ["EAAntiCheat*"],
        ["EAAntiCheatService"]
    ),
    sig!(
        "RICOCHET Anti-Cheat",
        "Activision",
        "Call of Duty: BO6 / BO7, MW III, Warzone",
        ["*randgrid*.sys"],
        ["atvi-randgrid*", "randgrid*"],
        []
    ),
    sig!(
        "Denuvo Anti-Cheat",
        "Irdeto",
        "THE FINALS, ARC Raiders, R6 Extraction",
        ["denuvo-anti-cheat*.sys", "denuvo*anticheat*.sys"],
        [
            "Denuvo Anti-Cheat*",
            "denuvo-anti-cheat*",
            "denuvo*anticheat*"
        ],
        ["denuvo*update*"]
    ),
    sig!(
        "FACEIT Anti-Cheat",
        "FACEIT",
        "CS2, Dota 2 (FACEIT platform)",
        ["faceit*.sys"],
        ["FACEIT*"],
        ["FACEITService", "FACEIT"]
    ),
    sig!(
        "ESEA Anti-Cheat",
        "ESEA",
        "CS2 (ESEA platform)",
        ["ESEADriver*.sys"],
        ["ESEADriver*"],
        ["ESEA*"]
    ),
    sig!(
        "EQU8",
        "EQU8 / 1047 Games",
        "Splitgate, KovaaK's, Aimlabs",
        ["EQU8*.sys"],
        ["EQU8*"],
        []
    ),
    sig!(
        "RedKard",
        "1047 Games",
        "Splitgate 2",
        ["RedKard*.sys"],
        ["RedKard*"],
        ["RedKard*"]
    ),
    sig!(
        "PunkBuster",
        "Even Balance",
        "Battlefield 3 / 4 / 1, legacy titles",
        ["PnkBstrK*.sys"],
        ["PnkBstrK*"],
        ["PnkBstrA", "PnkBstrB"]
    ),
    // ---- China -------------------------------------------------------------------------------
    sig!(
        "Anti-Cheat Expert (ACE)",
        "Tencent",
        "Delta Force, Wuthering Waves, Arena Breakout, NIKKE",
        ["ACE-*.sys"],
        ["ACE-*"],
        ["AntiCheatExpert*", "ACE-*", "SGuard*"]
    ),
    sig!(
        "TenProtect (TP)",
        "Tencent",
        "Ring of Elysium, CrossFire, legacy Tencent titles",
        ["TesSafe*.sys", "TP3Helper*.sys", "TenSafe*.sys"],
        ["TesSafe*", "TP3Helper*", "TenSafe*"],
        ["TPSvc*"]
    ),
    sig!(
        "TerSafe Game Protect (legacy)",
        "Tencent (attributed)",
        "Legacy Tencent titles",
        ["GameTerSafe*.sys", "TerSafe*.sys"],
        ["GameTerSafe*", "TerSafe*"],
        []
    ),
    sig!(
        "NetEase Anti-Cheat (NEAC)",
        "NetEase",
        "Marvel Rivals, Naraka, Once Human, FragPunk",
        ["*NeacSafe*.sys", "Neac*.sys"],
        ["*Neac*"],
        []
    ),
    sig!(
        "Seasun Protect",
        "Kingsoft Seasun",
        "Mecha BREAK, Snowbreak: Containment Zone",
        ["SeasunProtect*.sys"],
        ["SeasunProtect*"],
        []
    ),
    sig!(
        "KSophon",
        "Hotta / Perfect World",
        "Tower of Fantasy, Neverness to Everness",
        ["KSophon*.sys", "GameDriverX64*.sys"],
        ["KSophon*", "GameDriverX64*"],
        []
    ),
    sig!(
        "miHoYo Protect (mhyprot)",
        "miHoYo / HoYoverse",
        "Genshin Impact, Honkai: Star Rail, Honkai 3rd",
        ["mhyprot*.sys"],
        ["mhyprot*"],
        []
    ),
    sig!(
        "HoYoKProtect",
        "HoYoverse",
        "Zenless Zone Zero, newer HoYoverse titles",
        ["HoYoKProtect*.sys", "HoYoProtect*.sys"],
        ["HoYoKProtect*", "HoYoProtect*"],
        []
    ),
    sig!(
        "Perfect World Arena AC",
        "Perfect World",
        "CS2 (Perfect World esports platform)",
        ["MessageTransfer*.sys"],
        ["MessageTransfer*"],
        []
    ),
    sig!(
        "YY Protect",
        "YY Inc.",
        "YY game / voice platform titles",
        ["yyprotect*.sys"],
        ["yyprotect*"],
        []
    ),
    sig!(
        "KGameProtect",
        "Unattributed",
        "Unknown (listed on LOLDrivers)",
        ["kgameprotect*.sys"],
        ["kgameprotect*"],
        []
    ),
    // ---- Korea / Japan -----------------------------------------------------------------------
    sig!(
        "Zakynthos",
        "KRAFTON",
        "PUBG: Battlegrounds, PUBG: Black Budget",
        ["navagio*.sys", "zakynthos*.sys"],
        ["navagio*", "zakynthos*"],
        ["zakynthos*"]
    ),
    sig!(
        "UNCHEATER",
        "Uncheater",
        "PUBG, Eternal Return, PUBG Lite",
        ["uncheater*.sys"],
        ["uncheater*"],
        ["uncheater*"]
    ),
    sig!(
        "XIGNCODE3",
        "Wellbia",
        "Trove, Ragnarok, Knight Online, DJMAX",
        ["xhunter*.sys"],
        ["xhunter*"],
        []
    ),
    sig!(
        "nProtect GameGuard",
        "INCA Internet",
        "Helldivers 2, Lineage II, Star Stable",
        ["dump_wmimmc.sys", "npptNT*.sys"],
        ["npptNT*", "dump_wmimmc*"],
        ["npggsvc*"]
    ),
    sig!(
        "nProtect KeyCrypt",
        "INCA Internet",
        "MapleStory and other Nexon titles",
        ["npkc*.sys"],
        ["npkc*"],
        []
    ),
    sig!(
        "AhnLab HackShield",
        "AhnLab",
        "Dungeon Fighter, Mabinogi, War Rock (legacy)",
        ["EagleNT*.sys", "EagleXNt*.sys"],
        ["EagleNT*", "EagleXNt*"],
        []
    ),
    sig!(
        "X-Trap",
        "WiseLogic",
        "NosTale, GrandChase, Knight Online, Metin2",
        ["XDva*.sys"],
        ["XDva*"],
        []
    ),
    sig!(
        "Nexon Game Security (BlackCipher)",
        "Nexon",
        "MapleStory, The First Descendant, Vindictus",
        ["BlackCat*.sys", "BlackCipher*.sys"],
        ["BlackCat*", "BlackCipher*"],
        []
    ),
    sig!(
        "WFSDrv",
        "Wright Flyer Studios",
        "ANOTHER EDEN, Heaven Burns Red",
        ["wfsdrv*.sys"],
        ["wfsdrv*"],
        []
    ),
    sig!(
        "IronShield (Tavern)",
        "Ironmace",
        "Dark and Darker",
        ["Tavern*.sys", "IronShield*.sys"],
        ["Tavern*", "IronShield*"],
        ["Tavern*", "IronShield*"]
    ),
    // ---- Russia / CIS / EU / LATAM platforms -------------------------------------------------
    sig!(
        "MRAC (Mail.Ru Anti-Cheat)",
        "Mail.Ru / MY.GAMES",
        "Warface, Allods, Conqueror's Blade, War Robots",
        ["mracdrv*.sys"],
        ["mracdrv*"],
        ["mracsvc*"]
    ),
    sig!(
        "MY.GAMES Anti-Cheat",
        "MY.GAMES",
        "War Robots: Frontiers, Warface: Clutch, HAWKED",
        ["myacdrv*.sys"],
        ["myacdrv*"],
        ["myacsvc*"]
    ),
    sig!(
        "4game Guard / Frost",
        "Innova / 4game",
        "Lineage II, AION (EU), Ragnarok Online Prime",
        ["frost.sys", "frost64.sys", "frost_x64.sys", "frostdrv*.sys"],
        ["frost", "frost64", "frostdrv*"],
        []
    ),
    sig!(
        "SARD Anti-Cheat",
        "SARD",
        "APB Reloaded, AION, Blade & Soul, TDU Solar Crown",
        ["SARD*.sys"],
        ["SARD*"],
        ["SARD*"]
    ),
    sig!(
        "Akros Anti-Cheat",
        "Akros AntiCheat LLC",
        "ChallengerMode (CS2, Dota 2, LoL, PUBG)",
        ["Akros*.sys"],
        ["Akros*"],
        ["Akros*"]
    ),
    sig!(
        "EMAC Anti-Cheat",
        "EMAC LAB / Gamers Club",
        "CS2 (Gamers Club platform)",
        ["EMAC-Driver*.sys", "EMAC*.sys"],
        ["EMAC*"],
        []
    ),
    sig!(
        "Gamers Club Anti-Cheat (legacy)",
        "Gamers Club",
        "CS2 / CS:GO (Gamers Club platform)",
        ["GCSYS*.sys"],
        ["GCSYS*"],
        []
    ),
    sig!(
        "Esportal Anti-Cheat",
        "Esportal AB",
        "CS2, Dota 2 (Esportal platform)",
        ["EspoDriver*.sys"],
        ["EspoDriver*"],
        ["Esportal*"]
    ),
    sig!(
        "FastCup myAC",
        "FastCup",
        "CS2 (FastCup platform)",
        ["acdev*.sys"],
        ["acdev*"],
        []
    ),
    sig!(
        "GamersFirst Anti-Cheat (GFAC)",
        "Little Orbit",
        "APB Reloaded (legacy)",
        ["GFAC*.sys"],
        ["GFAC*"],
        []
    ),
];

/// Words that mark a driver as an anti-cheat even when it is not in [`DB`]. Compared against
/// the lowercased text with spaces, underscores and hyphens removed, which is how
/// `anti[\s_-]?cheat` and its siblings in the original script read.
pub const HEURISTIC: &[&str] = &[
    "anticheat",
    "cheatguard",
    "gameguard",
    "gameprotect",
    "gamesecurity",
    "zakynthos",
    "uncheater",
    "ironshield",
    "redkard",
    "wellbia",
    "wiselogic",
    "hackshield",
];

#[cfg(test)]
mod tests {
    use super::DB;

    #[test]
    fn every_signature_can_match_something() {
        for sig in DB {
            assert!(
                !sig.drivers.is_empty(),
                "{} has no driver pattern",
                sig.name
            );
            assert!(
                !sig.services.is_empty(),
                "{} has no service pattern",
                sig.name
            );
        }
    }

    #[test]
    fn names_are_unique() {
        for (index, sig) in DB.iter().enumerate() {
            for other in &DB[index + 1..] {
                assert_ne!(sig.name, other.name);
            }
        }
    }
}
