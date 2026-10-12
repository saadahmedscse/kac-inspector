//! KAC Inspector - Kernel Anti-Cheat Inspector.
//!
//! Detects known kernel-mode anti-cheat drivers and reports their live state
//! (RUNNING / LOADED / STOPPED / ORPHANED / STALE) straight from the kernel module list, the
//! Service Control Manager and the drivers folder. A Rust port of `KAC_Query.bat`.

#![cfg(windows)]

mod loader;
mod menu;
mod render;
mod scan;
mod signatures;
mod style;
mod sys;

use std::io::IsTerminal as _;
use std::time::Instant;

use loader::Progress;

/// Passed to the elevated copy so it never tries to elevate again.
const ELEVATED_FLAG: &str = "--elevated";

fn main() {
    let relaunched = std::env::args().any(|a| a == ELEVATED_FLAG);

    // ---- Self-elevate to Administrator, like the bat's `fltmc || runas` dance.
    let admin = sys::is_elevated();
    if !admin && !relaunched {
        println!("  Requesting administrator privileges...");
        if sys::relaunch_elevated(ELEVATED_FLAG) {
            return;
        }
    }

    let vt = sys::prepare_console("KAC Inspector - Kernel Anti-Cheat Inspector");
    let terminal = std::io::stdout().is_terminal();
    let colour = terminal && vt && std::env::var_os("NO_COLOR").is_none();
    style::init(style::Caps {
        colour,
        truecolor: colour,
        unicode: std::env::var_os("KAC_ASCII").is_none(),
    });
    let animate = colour;
    let interactive = terminal && std::io::stdin().is_terminal();

    loop {
        scan(animate, admin);
        // Not a console to ask in (piped, redirected): one scan and done, like a CLI tool.
        if !interactive || menu::ask() == menu::Choice::Exit {
            break;
        }
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::Purge),
            crossterm::cursor::MoveTo(0, 0),
        );
    }
}

/// One full pass: header, collection under the progress bar, matching, report.
fn scan(animate: bool, admin: bool) {
    let clock = Instant::now();
    let width = sys::console_width().map_or(104, |w| w.saturating_sub(4).clamp(80, 104));
    let page = render::Page { width };
    page.header();

    let mut progress = Progress::start(animate, 5);

    let modules = progress.step("Kernel modules", || {
        sys::enable_debug_privilege();
        sys::kernel_modules()
    });
    let kernel_ok = !modules.is_empty();
    let drivers = progress.step("Driver services", sys::driver_services);
    let services = progress.step("Companion services", sys::user_services);
    let disk_dir = sys::drivers_dir();
    let disk = progress.step("Driver store", || {
        std::fs::read_dir(&disk_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.to_lowercase().ends_with(".sys"))
            .collect::<Vec<_>>()
    });
    let report = progress.step("Signatures", || {
        scan::run(
            &modules,
            &drivers,
            &services,
            &disk,
            &disk_dir.to_string_lossy(),
            &sys::system_root(),
        )
    });
    progress.finish(clock.elapsed().as_secs_f64());

    page.report(&report, kernel_ok);
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    page.footer(&host, &sys::os_caption(), admin, &sys::local_time());
}
