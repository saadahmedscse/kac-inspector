//! The loader: one progress bar for the whole scan, filling an eighth of a column at a time,
//! with dbsloop's travelling dot and the source being read beside it.
//!
//! **Each source is held on screen for at least [`MIN_VISIBLE`]** — the scan itself takes
//! milliseconds and would otherwise flash past as a single frame.

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::style::{self, Hue, paint};

/// How often the bar is redrawn.
const TICK: Duration = Duration::from_millis(30);

/// How long one spinner frame stays on screen (four ticks).
const FRAME_TICKS: usize = 4;

/// The shortest time a source stays on screen when animation is on.
const MIN_VISIBLE: Duration = Duration::from_millis(360);

/// Width of the bar between its caps.
pub const BAR: usize = 60;

fn frames() -> &'static [&'static str] {
    if style::unicode() {
        &[
            "\u{25cf}\u{2219}\u{2219}",
            "\u{2219}\u{25cf}\u{2219}",
            "\u{2219}\u{2219}\u{25cf}",
            "\u{2219}\u{25cf}\u{2219}",
        ]
    } else {
        &["o..", ".o.", "..o", ".o."]
    }
}

/// The bar `width` columns wide, filled to `fraction`: the filled part and the track.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn bar(fraction: f64, width: usize) -> (String, String) {
    let fraction = fraction.clamp(0.0, 1.0);
    if !style::unicode() {
        let full = ((fraction * width as f64).round() as usize).min(width);
        return ("#".repeat(full), ".".repeat(width - full));
    }
    // Eighths of a column across the whole bar, so the remainder picks a partial block.
    let eighths = (fraction * (width * 8) as f64).round() as usize;
    let full = (eighths / 8).min(width);
    let part = u32::try_from(eighths % 8).unwrap_or(0);
    let mut filled = "\u{2588}".repeat(full);
    let mut empty = width - full;
    if part > 0 && full < width {
        filled.push(char::from_u32(0x2588 - (8 - part)).unwrap_or('\u{2588}'));
        empty -= 1;
    }
    (filled, "\u{2591}".repeat(empty))
}

/// `Scan   ▕██████░░░░▏  ` — everything up to the text after the bar.
fn bar_line(fraction: f64) -> String {
    let (filled, track) = bar(fraction, BAR);
    format!(
        "  {}{}{}{}{}  ",
        paint(Hue::Dim, "Scan   "),
        paint(Hue::Dim, style::glyph("\u{2595}", "[")),
        paint(Hue::Brand, &filled),
        paint(Hue::Faint, &track),
        paint(Hue::Dim, style::glyph("\u{258f}", "]")),
    )
}

struct State {
    done: usize,
    label: String,
    stop: bool,
}

/// The scan's progress, drawn on one line rewritten in place.
pub struct Progress {
    total: usize,
    state: Arc<Mutex<State>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Progress {
    /// Start the bar for `total` sources. Without animation nothing is drawn until
    /// [`Progress::finish`].
    pub fn start(animate: bool, total: usize) -> Self {
        let state = Arc::new(Mutex::new(State {
            done: 0,
            label: String::new(),
            stop: false,
        }));
        let thread = animate.then(|| {
            let state = Arc::clone(&state);
            thread::spawn(move || ticker(&state, total))
        });
        Self {
            total,
            state,
            thread,
        }
    }

    /// Read one source under the bar.
    pub fn step<T>(&mut self, label: &str, work: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        if let Ok(mut s) = self.state.lock() {
            label.clone_into(&mut s.label);
        }
        let value = work();
        if self.thread.is_some()
            && let Some(rest) = MIN_VISIBLE.checked_sub(started.elapsed())
        {
            thread::sleep(rest);
        }
        if let Ok(mut s) = self.state.lock() {
            s.done += 1;
        }
        value
    }

    /// Settle into the full bar and how long it took.
    pub fn finish(mut self, seconds: f64) {
        // The ticker clears its own line on the way out, so there is nothing to erase here.
        if let Some(handle) = self.thread.take() {
            if let Ok(mut s) = self.state.lock() {
                s.stop = true;
            }
            let _ = handle.join();
        }
        println!(
            "{}{}",
            bar_line(1.0),
            paint(
                Hue::Dim,
                &format!("{0} of {0} sources  \u{00b7}  {seconds:.2} s", self.total)
            ),
        );
    }
}

#[allow(clippy::cast_precision_loss)]
fn ticker(state: &Mutex<State>, total: usize) {
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b[?25l");
    let mut shown = 0.0_f64;
    let mut tick = 0_usize;
    loop {
        let (done, label, stop) = match state.lock() {
            Ok(s) => (s.done, s.label.clone(), s.stop),
            Err(_) => return,
        };
        if stop {
            let _ = write!(out, "\r\x1b[2K\x1b[?25h");
            let _ = out.flush();
            return;
        }
        // Ease toward the next boundary so the bar keeps moving while a source is read.
        let target = (done as f64 + 0.8) / total as f64;
        shown += (target - shown) * 0.18;
        let frame = frames()[(tick / FRAME_TICKS) % frames().len()];
        let _ = write!(
            out,
            "\r{}{}{}\x1b[K",
            bar_line(shown),
            paint(
                Hue::Dim,
                &format!("{} of {total} sources  \u{00b7}  ", done.min(total))
            ),
            format_args!("{} {}", paint(Hue::Text, &label), paint(Hue::Brand, frame)),
        );
        let _ = out.flush();
        tick += 1;
        thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::{bar, frames};

    #[test]
    fn every_frame_is_three_columns() {
        for frame in frames() {
            assert_eq!(frame.chars().count(), 3);
        }
    }

    #[test]
    fn a_bar_is_always_exactly_as_wide_as_asked() {
        for width in [1_usize, 7, 20, 60] {
            for step in 0..=20 {
                let (filled, empty) = bar(f64::from(step) / 20.0, width);
                assert_eq!(filled.chars().count() + empty.chars().count(), width);
            }
        }
    }
}
