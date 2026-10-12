//! Everything printed around the scan, laid out answer-first: the header, the verdict, a card
//! per detection, the coverage strip and the footer.

use crate::scan::{Finding, Report, Status};
use crate::signatures::DB;
use crate::style::{Hue, bold, fit, g, paint};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "Saad Ahmed";
const SITE: &str = "https://saadahmedev.com";

/// Width of the label column inside a card.
const KEY: usize = 13;

/// Width of one name in the not-present list.
const NAME: usize = 34;

/// One printed line, built from coloured pieces while counting the columns they take.
#[derive(Default)]
struct Line {
    text: String,
    cols: usize,
}

impl Line {
    fn new() -> Self {
        Self {
            text: String::from("  "),
            cols: 0,
        }
    }
    fn put(mut self, hue: Hue, text: &str) -> Self {
        self.text.push_str(&paint(hue, text));
        self.cols += text.chars().count();
        self
    }
    fn strong(mut self, hue: Hue, text: &str) -> Self {
        self.text.push_str(&bold(hue, text));
        self.cols += text.chars().count();
        self
    }
    /// Push `right` to the far edge of a `width`-column line.
    fn right(mut self, width: usize, right: &Line) -> Self {
        let gap = width.saturating_sub(self.cols + right.cols).max(2);
        self.text.push_str(&" ".repeat(gap));
        self.text.push_str(right.text.trim_start_matches("  "));
        self.cols += gap + right.cols;
        self
    }
    fn print(self) {
        println!("{}", self.text);
    }
}

/// A right-hand piece, without the left margin.
fn piece() -> Line {
    Line {
        text: String::from("  "),
        cols: 0,
    }
}

fn sep() -> &'static str {
    "  \u{00b7}  "
}

/// `KERNEL CLEAN` → `K E R N E L   C L E A N`.
fn spaced(text: &str) -> String {
    text.split(' ')
        .map(|word| word.chars().map(String::from).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("   ")
}

fn status_hue(status: Status) -> Hue {
    if status.live() { Hue::Bad } else { Hue::Warn }
}

fn status_glyph(status: Status) -> &'static str {
    if status.live() { g::dot() } else { g::ring() }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The page, `width` columns from margin to margin.
pub struct Page {
    pub width: usize,
}

impl Page {
    fn rule(&self) {
        Line::new()
            .put(Hue::Faint, &g::hair().repeat(self.width))
            .print();
    }

    pub fn header(&self) {
        println!();
        Line::new()
            .strong(Hue::Brand, "KAC")
            .put(Hue::Dim, "  kernel anti-cheat inspector")
            .right(
                self.width,
                &piece()
                    .put(Hue::Dim, &format!("v{VERSION}{}{AUTHOR}{}", sep(), sep()))
                    .put(Hue::Brand, SITE),
            )
            .print();
        println!();
    }

    /// The findings, answer first.
    pub fn report(&self, report: &Report, kernel_ok: bool) {
        let live: Vec<&Finding> = report.findings.iter().filter(|f| f.status.live()).collect();
        let count = |pick: &dyn Fn(Status) -> bool| {
            report.findings.iter().filter(|f| pick(f.status)).count()
        };
        let stopped = count(&|s| s == Status::Stopped);
        let leftover = count(&|s| matches!(s, Status::Orphaned | Status::Stale));
        let heuristic = report.findings.iter().filter(|f| f.sig.is_none()).count();

        // -- The verdict
        let mut names: Vec<&str> = Vec::new();
        for f in &live {
            if !names.contains(&f.name.as_str()) {
                names.push(&f.name);
            }
        }
        let rail_hue = if live.is_empty() { Hue::Ok } else { Hue::Bad };
        let rail = || Line::new().put(rail_hue, g::rail());

        println!();
        rail().print();
        if live.is_empty() {
            rail()
                .strong(Hue::Ok, &format!("   {}", spaced("KERNEL CLEAN")))
                .print();
        } else {
            let what = if names.len() == 1 {
                "ANTI-CHEAT"
            } else {
                "ANTI-CHEATS"
            };
            let head = format!(
                "{}  {}",
                names.len(),
                spaced(&format!("{what} LIVE IN KERNEL"))
            );
            rail().strong(Hue::Bad, &format!("   {head}")).print();
        }
        rail().print();

        match live.as_slice() {
            [] => rail()
                .put(
                    Hue::Text,
                    "   No known anti-cheat driver is running or loaded.",
                )
                .print(),
            [only] => {
                let rest = match only.status {
                    Status::Running if only.service != "-" => {
                        " is loaded and its service is running."
                    }
                    Status::Running => " is running.",
                    Status::Pending => "'s service is starting or stopping.",
                    _ => " is loaded in kernel memory.",
                };
                rail()
                    .strong(Hue::Text, &format!("   {}", only.name))
                    .put(Hue::Text, rest)
                    .print();
            }
            _ => {
                let (last, first) = names.split_last().unwrap_or((&"", &[]));
                let joined = if first.is_empty() {
                    (*last).to_owned()
                } else {
                    format!("{} and {last}", first.join(", "))
                };
                rail()
                    .strong(Hue::Text, &format!("   {joined}"))
                    .put(Hue::Text, " are live in the kernel.")
                    .print();
            }
        }

        let mut facts = vec![
            format!("{stopped} installed but stopped"),
            format!("{} not present", report.absent.len()),
            plural(leftover, "leftover", "leftovers"),
        ];
        if heuristic > 0 {
            facts.push(format!("{heuristic} matched by name"));
        }
        rail()
            .put(Hue::Dim, &format!("   {}", facts.join(sep())))
            .print();
        if !kernel_ok {
            rail()
                .put(Hue::Warn, &format!("   {} ", g::warn()))
                .put(
                    Hue::Warn,
                    "Kernel module list unavailable; state taken from the Service Control Manager.",
                )
                .print();
        }
        rail().print();
        println!();
        println!();

        // -- One card per detection
        for f in &report.findings {
            self.card(f);
        }

        // -- Coverage
        Line::new()
            .strong(Hue::Text, "Coverage")
            .right(
                self.width,
                &piece().put(Hue::Dim, &format!("{} signatures checked", DB.len())),
            )
            .print();
        self.rule();

        let per_row = (self.width.saturating_sub(2) / 2).max(1);
        let cells: Vec<Hue> = (0..DB.len())
            .map(|index| {
                let mine = report.findings.iter().filter(|f| f.sig == Some(index));
                let mut hue = Hue::Faint;
                for f in mine {
                    hue = if f.status.live() {
                        Hue::Bad
                    } else if hue == Hue::Bad {
                        hue
                    } else {
                        Hue::Warn
                    };
                }
                hue
            })
            .collect();
        for row in cells.chunks(per_row) {
            let mut out = Line::new().put(Hue::Text, "  ");
            for &hue in row {
                out = out.put(hue, g::square()).put(Hue::Text, " ");
            }
            out.print();
        }
        Line::new()
            .put(Hue::Text, "  ")
            .put(Hue::Bad, g::square())
            .put(Hue::Dim, " live   ")
            .put(Hue::Warn, g::square())
            .put(Hue::Dim, " installed   ")
            .put(Hue::Faint, g::square())
            .put(Hue::Dim, " not present")
            .print();
        println!();

        let columns = (self.width.saturating_sub(2) / NAME).max(1);
        for row in report.absent.chunks(columns) {
            let mut out = Line::new().put(Hue::Text, "  ");
            for sig in row {
                out = out
                    .put(Hue::Dim, &fit(sig.name, NAME - 1))
                    .put(Hue::Text, " ");
            }
            println!("{}", out.text.trim_end());
        }
        println!();
        println!();
    }

    fn card(&self, f: &Finding) {
        let hue = status_hue(f.status);
        let name_hue = if f.sig.is_some() {
            Hue::Text
        } else {
            Hue::Warn
        };
        Line::new()
            .strong(name_hue, &f.name)
            .right(
                self.width,
                &piece().put(
                    hue,
                    &format!("{} {}", status_glyph(f.status), f.status.word()),
                ),
            )
            .print();
        self.rule();

        let row = |key: &str| Line::new().put(Hue::Dim, &fit(&format!("  {key}"), KEY + 2));
        row("driver").put(Hue::Brand, &f.file).print();
        if f.service == "-" {
            row("service").put(Hue::Dim, "none registered").print();
        } else {
            row("service")
                .put(Hue::Text, &f.service)
                .put(
                    Hue::Dim,
                    &format!(
                        "{}starts {}",
                        sep(),
                        if matches!(f.start.as_str(), "Boot" | "System") {
                            "at "
                        } else {
                            ""
                        }
                    ),
                )
                .put(Hue::Text, &f.start)
                .print();
        }
        row("path")
            .put(Hue::Text, f.path.as_deref().unwrap_or("unknown"))
            .print();
        row("vendor").put(Hue::Text, &f.vendor).print();
        row("games").put(Hue::Text, &f.games).print();
        for c in &f.companions {
            let (glyph, hue) = if c.state == "Running" {
                (g::dot(), Hue::Ok)
            } else {
                (g::ring(), Hue::Warn)
            };
            row("companion")
                .put(Hue::Text, &format!("{}  ", c.name))
                .put(hue, &format!("{glyph} {}", c.state.to_lowercase()))
                .print();
        }
        println!();
        println!();
    }

    pub fn footer(&self, host: &str, os: &str, admin: bool, time: &str) {
        self.rule();
        let (privilege, hue) = if admin {
            ("Administrator", Hue::Ok)
        } else {
            ("Standard user", Hue::Bad)
        };
        Line::new()
            .put(Hue::Text, host)
            .put(Hue::Dim, sep())
            .put(Hue::Text, os)
            .put(Hue::Dim, sep())
            .put(hue, privilege)
            .put(Hue::Dim, sep())
            .put(Hue::Text, time)
            .print();
    }
}

#[cfg(test)]
mod tests {
    use super::spaced;

    #[test]
    fn spaced_letters_keep_words_apart() {
        assert_eq!(spaced("KERNEL CLEAN"), "K E R N E L   C L E A N");
    }
}
