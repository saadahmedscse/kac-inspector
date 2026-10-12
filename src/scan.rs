//! Matching: the kernel module list, the driver services and the drivers folder against the
//! signature database, then a name heuristic for anything else that calls itself an
//! anti-cheat. A straight port of the matching block in `KAC_Query.bat`.

use std::path::Path;

use crate::signatures::{DB, HEURISTIC, Signature};
use crate::sys::{Driver, Module, Service};

/// The live state of one driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Loaded, and the service is running.
    Running,
    /// In kernel memory, with no running SCM entry.
    Loaded,
    /// The service is starting or stopping.
    Pending,
    /// Installed and idle.
    Stopped,
    /// The service is registered but its `.sys` is gone.
    Orphaned,
    /// A `.sys` left on disk with no service.
    Stale,
}

impl Status {
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Loaded => "loaded",
            Self::Pending => "pending",
            Self::Stopped => "stopped",
            Self::Orphaned => "orphaned",
            Self::Stale => "stale",
        }
    }

    /// Is it in the kernel (or on its way in) right now?
    #[must_use]
    pub const fn live(self) -> bool {
        matches!(self, Self::Running | Self::Loaded | Self::Pending)
    }
}

/// One anti-cheat driver found on this system.
#[derive(Debug)]
pub struct Finding {
    pub name: String,
    pub vendor: String,
    pub games: String,
    pub file: String,
    pub path: Option<String>,
    pub service: String,
    pub start: String,
    pub status: Status,
    pub companions: Vec<Service>,
    /// The signature it matched, as an index into [`DB`]; `None` for the heuristic.
    pub sig: Option<usize>,
}

/// Everything the scan turned up.
pub struct Report {
    pub findings: Vec<Finding>,
    pub absent: Vec<&'static Signature>,
}

/// Case-insensitive wildcard match, `*` and `?`, like PowerShell's `-like`.
#[must_use]
pub fn like(value: &str, pattern: &str) -> bool {
    let v: Vec<char> = value.to_lowercase().chars().collect();
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let (mut vi, mut pi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            vi += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, vi));
            pi += 1;
        } else if let Some((sp, sv)) = star {
            pi = sp + 1;
            vi = sv + 1;
            star = Some((sp, sv + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn like_any(value: &str, patterns: &[&str]) -> bool {
    !value.is_empty() && patterns.iter().any(|p| like(value, p))
}

/// Turn an SCM or kernel path into a normal file path.
#[must_use]
pub fn resolve_path(raw: &str, root: &str) -> Option<String> {
    let mut p = raw.trim().trim_matches('"').to_owned();
    if p.is_empty() {
        return None;
    }
    if let Some(rest) = p.strip_prefix(r"\??\") {
        p = String::from(rest);
    }
    let lower = p.to_lowercase();
    if lower.starts_with(r"\systemroot\") {
        p = format!(r"{root}\{}", &p[r"\systemroot\".len()..]);
    } else if lower.starts_with(r"%systemroot%\") {
        p = format!(r"{root}\{}", &p[r"%systemroot%\".len()..]);
    } else if lower.starts_with(r"system32\") {
        p = format!(r"{root}\{p}");
    }
    Some(p)
}

fn leaf(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn exists(path: Option<&String>) -> bool {
    path.is_some_and(|p| Path::new(p).exists())
}

fn heuristic(text: &str) -> bool {
    let squashed: String = text
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect();
    HEURISTIC.iter().any(|word| squashed.contains(word))
}

/// One driver instance being assembled for a signature.
struct Instance<'a> {
    key: String,
    file: String,
    path: Option<String>,
    svc: Option<&'a Driver>,
    loaded: bool,
    on_disk: bool,
}

impl Instance<'_> {
    fn status(&self) -> Status {
        let state = self.svc.map_or("", |d| d.state);
        if self.loaded && state == "Running" {
            Status::Running
        } else if self.loaded {
            Status::Loaded
        } else if state == "Running" {
            Status::Running
        } else if state.ends_with("Pending") {
            Status::Pending
        } else if self.svc.is_some() && self.on_disk {
            Status::Stopped
        } else if self.svc.is_some() {
            Status::Orphaned
        } else {
            Status::Stale
        }
    }
}

/// Match everything that was collected.
#[must_use]
pub fn run(
    modules: &[Module],
    drivers: &[Driver],
    services: &[Service],
    disk: &[String],
    disk_dir: &str,
    root: &str,
) -> Report {
    let mut claimed: Vec<String> = Vec::new();
    let mut findings = Vec::new();
    let mut absent = Vec::new();

    let driver_file = |d: &Driver| -> (Option<String>, String) {
        let path = resolve_path(&d.path, root);
        let base = path
            .as_deref()
            .map_or_else(|| format!("{}.sys", d.name), |p| leaf(p).to_owned());
        (path, base)
    };

    for (index, sig) in DB.iter().enumerate() {
        let mut inst: Vec<Instance> = Vec::new();

        for d in drivers {
            let (path, base) = driver_file(d);
            if like_any(&base, sig.drivers) || like_any(&d.name, sig.services) {
                let key = base.to_lowercase();
                let on_disk = exists(path.as_ref());
                let fresh = Instance {
                    key: key.clone(),
                    file: base,
                    path,
                    svc: Some(d),
                    loaded: false,
                    on_disk,
                };
                match inst.iter_mut().find(|i| i.key == key) {
                    Some(old) if old.svc.is_some_and(|s| s.state == "Running") => {}
                    Some(old) => *old = fresh,
                    None => inst.push(fresh),
                }
            }
        }

        for m in modules {
            let key = m.base.to_lowercase();
            let known = inst.iter().any(|i| i.key == key);
            if like_any(&m.base, sig.drivers) || known {
                if !known {
                    inst.push(Instance {
                        key: key.clone(),
                        file: m.base.clone(),
                        path: resolve_path(&m.path, root),
                        svc: None,
                        loaded: false,
                        on_disk: false,
                    });
                }
                if let Some(i) = inst.iter_mut().find(|i| i.key == key) {
                    i.loaded = true;
                    if i.path.is_none() {
                        i.path = resolve_path(&m.path, root);
                    }
                }
            }
        }

        for name in disk {
            if like_any(name, sig.drivers) {
                let key = name.to_lowercase();
                let full = format!(r"{disk_dir}\{name}");
                if let Some(i) = inst.iter_mut().find(|i| i.key == key) {
                    i.on_disk = true;
                    i.path.get_or_insert(full);
                } else {
                    inst.push(Instance {
                        key,
                        file: name.clone(),
                        path: Some(full),
                        svc: None,
                        loaded: false,
                        on_disk: true,
                    });
                }
            }
        }

        if inst.is_empty() {
            absent.push(sig);
            continue;
        }
        let companions: Vec<Service> = services
            .iter()
            .filter(|s| like_any(&s.name, sig.companions))
            .cloned()
            .collect();
        for i in inst {
            claimed.push(i.key.clone());
            if let Some(svc) = i.svc {
                claimed.push(format!("svc:{}", svc.name.to_lowercase()));
            }
            findings.push(Finding {
                name: sig.name.to_owned(),
                vendor: sig.vendor.to_owned(),
                games: sig.games.to_owned(),
                status: i.status(),
                file: i.file,
                path: i.path,
                service: i.svc.map_or_else(|| "-".to_owned(), |d| d.name.clone()),
                start: i.svc.map_or("-", |d| d.start).to_owned(),
                companions: companions.clone(),
                sig: Some(index),
            });
        }
    }

    // -- Heuristic sweep: anything else that calls itself an anti-cheat.
    let is_claimed = |claimed: &[String], key: &str| claimed.iter().any(|c| c == key);
    for d in drivers {
        if is_claimed(&claimed, &format!("svc:{}", d.name.to_lowercase())) {
            continue;
        }
        let (path, base) = driver_file(d);
        if is_claimed(&claimed, &base.to_lowercase()) {
            continue;
        }
        let text = format!(
            "{} {} {} {}",
            d.name,
            d.display,
            d.description,
            path.as_deref().unwrap_or("")
        );
        if heuristic(&text) {
            let i = Instance {
                key: base.to_lowercase(),
                on_disk: exists(path.as_ref()),
                loaded: modules.iter().any(|m| m.base.eq_ignore_ascii_case(&base)),
                file: base,
                path,
                svc: Some(d),
            };
            claimed.push(i.key.clone());
            findings.push(Finding {
                name: d.display.clone(),
                vendor: "Unknown".to_owned(),
                games: "Matched by name heuristic".to_owned(),
                status: i.status(),
                file: i.file,
                path: i.path,
                service: d.name.clone(),
                start: d.start.to_owned(),
                companions: Vec::new(),
                sig: None,
            });
        }
    }
    for m in modules {
        if is_claimed(&claimed, &m.base.to_lowercase()) {
            continue;
        }
        if heuristic(&format!("{} {}", m.base, m.path)) {
            findings.push(Finding {
                name: m.base.clone(),
                vendor: "Unknown".to_owned(),
                games: "Matched by name heuristic".to_owned(),
                file: m.base.clone(),
                path: resolve_path(&m.path, root),
                service: "-".to_owned(),
                start: "-".to_owned(),
                status: Status::Loaded,
                companions: Vec::new(),
                sig: None,
            });
        }
    }

    findings.sort_by(|a, b| a.status.cmp(&b.status).then_with(|| a.name.cmp(&b.name)));
    Report { findings, absent }
}

#[cfg(test)]
mod tests {
    use super::{heuristic, like, resolve_path};

    #[test]
    fn like_matches_the_way_powershell_does() {
        assert!(like("BEDaisy.sys", "bedaisy*.sys"));
        assert!(like("atvi-randgrid_sr.sys", "*randgrid*.sys"));
        assert!(like("vgk.sys", "vgk.sys"));
        assert!(!like("vgk2.sys", "vgk.sys"));
        assert!(like("EQU8_HELPER_36.sys", "EQU8*.sys"));
        assert!(!like("ACE.sys", "ACE-*.sys"));
    }

    #[test]
    fn scm_paths_resolve_to_real_paths() {
        let root = r"C:\Windows";
        assert_eq!(
            resolve_path(r"\SystemRoot\System32\drivers\vgk.sys", root).unwrap(),
            r"C:\Windows\System32\drivers\vgk.sys"
        );
        assert_eq!(
            resolve_path(r"system32\drivers\x.sys", root).unwrap(),
            r"C:\Windows\system32\drivers\x.sys"
        );
        assert_eq!(
            resolve_path(r"\??\D:\Games\BEDaisy.sys", root).unwrap(),
            r"D:\Games\BEDaisy.sys"
        );
        assert!(resolve_path("  ", root).is_none());
    }

    #[test]
    fn the_heuristic_reads_separators_loosely() {
        assert!(heuristic("Some Anti-Cheat Driver"));
        assert!(heuristic("game_guard"));
        assert!(!heuristic("Intel graphics"));
    }
}
