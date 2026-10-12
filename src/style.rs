//! The palette, the marks and the glyphs.
//!
//! **dbsloop's six colours, plus a faint grey for empty space.** Orange is the brand and the thing happening now,
//! green is a thing that is fine, amber is a thing to know about, red is a thing that is
//! wrong, grey is a label rather than the value it labels. A seventh hue would need a
//! seventh meaning.
//!
//! Colour is off when standard output is not a console or `NO_COLOR` is set, and the glyphs
//! fall back to ASCII when `KAC_ASCII` is set, so a redirected report stays readable.

use std::sync::OnceLock;

/// One of the six, by what it is for rather than by what it looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hue {
    /// The wordmark, headings, the thing happening now.
    Brand,
    /// Ordinary content.
    Text,
    /// A label, a path, a help line.
    Dim,
    /// Fine.
    Ok,
    /// Worth knowing about.
    Warn,
    /// Wrong, or live in the kernel.
    Bad,
    /// Barely there: an empty bar track, a signature that was not found.
    Faint,
}

impl Hue {
    /// The exact colour, dbsloop's twenty-four bits.
    const fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::Brand => (0xD9, 0x77, 0x57),
            Self::Text => (0xE0, 0xDC, 0xD6),
            Self::Dim => (0x8C, 0x84, 0x7C),
            Self::Ok => (0x6F, 0xBF, 0x8A),
            Self::Warn => (0xE0, 0xB2, 0x56),
            Self::Bad => (0xE8, 0x70, 0x6A),
            Self::Faint => (0x4A, 0x44, 0x40),
        }
    }

    /// The nearest colour in the 256-colour cube.
    const fn cube(self) -> u8 {
        match self {
            Self::Brand => 173,
            Self::Text => 253,
            Self::Dim => 245,
            Self::Ok => 72,
            Self::Warn => 179,
            Self::Bad => 167,
            Self::Faint => 238,
        }
    }
}

/// How this process may paint, decided once at startup.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub colour: bool,
    pub truecolor: bool,
    pub unicode: bool,
}

static CAPS: OnceLock<Caps> = OnceLock::new();

/// Fix the capabilities for the rest of the run. Later calls are ignored.
pub fn init(caps: Caps) {
    let _ = CAPS.set(caps);
}

fn caps() -> Caps {
    *CAPS.get_or_init(|| Caps {
        colour: false,
        truecolor: false,
        unicode: true,
    })
}

/// True when colour escapes are written at all.
#[must_use]
pub fn colour_on() -> bool {
    caps().colour
}

fn open(hue: Hue, bold: bool) -> String {
    let weight = if bold { "1;" } else { "" };
    if caps().truecolor {
        let (r, g, b) = hue.rgb();
        format!("\x1b[{weight}38;2;{r};{g};{b}m")
    } else {
        format!("\x1b[{weight}38;5;{}m", hue.cube())
    }
}

/// Wrap `text` in `hue` and close it again.
#[must_use]
pub fn paint(hue: Hue, text: &str) -> String {
    if !colour_on() || text.is_empty() {
        return text.to_owned();
    }
    format!("{}{text}\x1b[0m", open(hue, false))
}

/// Wrap `text` in `hue`, bold.
#[must_use]
pub fn bold(hue: Hue, text: &str) -> String {
    if !colour_on() || text.is_empty() {
        return text.to_owned();
    }
    format!("{}{text}\x1b[0m", open(hue, true))
}

/// Can this console draw the good glyphs?
#[must_use]
pub fn unicode() -> bool {
    caps().unicode
}

/// Pick the Unicode glyph or its ASCII twin.
#[must_use]
pub fn glyph(fancy: &'static str, plain: &'static str) -> &'static str {
    if unicode() { fancy } else { plain }
}

/// Glyphs used by the renderer, each with an ASCII twin.
pub mod g {
    use super::glyph;

    #[must_use]
    pub fn hair() -> &'static str {
        glyph("\u{2500}", "-")
    }
    #[must_use]
    pub fn rail() -> &'static str {
        glyph("\u{2503}", "|")
    }
    #[must_use]
    pub fn dot() -> &'static str {
        glyph("\u{25cf}", "*")
    }
    #[must_use]
    pub fn ring() -> &'static str {
        glyph("\u{25cb}", "o")
    }
    #[must_use]
    pub fn mid() -> &'static str {
        glyph("\u{00b7}", ".")
    }
    #[must_use]
    pub fn ellipsis() -> &'static str {
        glyph("\u{2026}", "~")
    }
    #[must_use]
    pub fn here() -> &'static str {
        glyph("\u{203a}", ">")
    }
    #[must_use]
    pub fn warn() -> &'static str {
        glyph("\u{25b2}", "!")
    }
    #[must_use]
    pub fn square() -> &'static str {
        glyph("\u{25a0}", "#")
    }
    #[must_use]
    pub fn arrows() -> &'static str {
        glyph("\u{2191}\u{2193}", "Up/Down")
    }
}

/// Fit `text` into exactly `width` columns: truncated with an ellipsis, or padded.
#[must_use]
pub fn fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count > width {
        let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
        cut.push_str(g::ellipsis());
        cut
    } else {
        format!("{text}{}", " ".repeat(width - count))
    }
}

#[cfg(test)]
mod tests {
    use super::{Hue, fit};

    #[test]
    fn no_two_of_the_six_are_the_same_colour() {
        let hues = [
            Hue::Brand,
            Hue::Text,
            Hue::Dim,
            Hue::Ok,
            Hue::Warn,
            Hue::Bad,
            Hue::Faint,
        ];
        for (index, hue) in hues.iter().enumerate() {
            for other in &hues[index + 1..] {
                assert_ne!(hue.rgb(), other.rgb());
                assert_ne!(hue.cube(), other.cube());
            }
        }
    }

    #[test]
    fn fit_is_always_exactly_as_wide_as_asked() {
        for text in ["", "vgk.sys", "a much longer name than the column holds"] {
            for width in [1_usize, 5, 12, 30] {
                assert_eq!(
                    fit(text, width).chars().count(),
                    width,
                    "{text:?} @ {width}"
                );
            }
        }
    }
}
