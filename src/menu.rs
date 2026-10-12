//! The question at the end of a scan, drawn the way dbsloop draws a list: an orange `›`
//! beside the highlighted item, the arrow keys to move it, Enter to choose.

use std::io::{Write as _, stdout};

use crossterm::cursor::{Hide, MoveToColumn, MoveUp, Show};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};

use crate::style::{Hue, bold, g, paint};

/// What the user picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    ScanAgain,
    Exit,
}

const ITEMS: [(Choice, &str); 2] = [(Choice::ScanAgain, "Scan again"), (Choice::Exit, "Exit")];

/// Lines the menu occupies below the question (the items and the help line), redrawn in
/// place on every key.
const HEIGHT: u16 = 3;

/// Puts the terminal back however the menu is left.
struct Raw;

impl Raw {
    fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        let _ = execute!(stdout(), Hide);
        Ok(Self)
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        let _ = execute!(stdout(), Show);
        let _ = disable_raw_mode();
    }
}

fn draw(here: usize) {
    let mut out = stdout();
    for (index, (_, label)) in ITEMS.iter().enumerate() {
        let line = if index == here {
            format!(
                "  {} {}",
                paint(Hue::Brand, g::here()),
                bold(Hue::Brand, label)
            )
        } else {
            format!("    {}", paint(Hue::Text, label))
        };
        let _ = write!(out, "{line}\x1b[K\r\n");
    }
    let help = format!(
        "{} move  {dot}  enter select  {dot}  esc quit",
        g::arrows(),
        dot = g::mid()
    );
    let _ = write!(out, "  {}\x1b[K\r\n", paint(Hue::Dim, &help));
    let _ = out.flush();
}

/// Ask what to do next. Anything that cannot be read is taken as Exit.
#[must_use]
pub fn ask() -> Choice {
    println!();
    println!(
        "  {} {}",
        paint(Hue::Brand, "?"),
        paint(Hue::Text, "What next?")
    );

    let Ok(raw) = Raw::enter() else {
        return Choice::Exit;
    };
    let mut here = 0;
    draw(here);

    let choice = loop {
        let Ok(event) = read() else {
            break Choice::Exit;
        };
        let Event::Key(key) = event else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Up => here = (here + ITEMS.len() - 1) % ITEMS.len(),
            KeyCode::Down | KeyCode::Tab => here = (here + 1) % ITEMS.len(),
            KeyCode::Char('1') => break Choice::ScanAgain,
            KeyCode::Enter => break ITEMS[here].0,
            KeyCode::Char('2') | KeyCode::Esc => break Choice::Exit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                break Choice::Exit;
            }
            _ => continue,
        }
        let _ = execute!(stdout(), MoveUp(HEIGHT), MoveToColumn(0));
        draw(here);
    };

    // Settle the list into the answer, the way an answered prompt reads in dbsloop.
    let _ = execute!(
        stdout(),
        MoveUp(HEIGHT),
        MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    );
    drop(raw);
    let label = ITEMS
        .iter()
        .find(|(c, _)| *c == choice)
        .map_or("Exit", |(_, l)| *l);
    println!("  {} {}", paint(Hue::Dim, g::mid()), paint(Hue::Ok, label));
    choice
}
