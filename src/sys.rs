//! Every call into Windows, and the only `unsafe` in the program.
//!
//! The rest of the crate sees plain Rust values: a list of kernel modules, a list of driver
//! services, a list of user-mode services. Each function here owns its buffers and handles
//! and returns an empty list rather than an error when Windows refuses, because the scan
//! reports what it could see and says so.

use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, GetLastError, HANDLE, LUID, SYSTEMTIME,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
    GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
    SetConsoleMode, SetConsoleOutputCP, SetConsoleTitleW,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumDeviceDrivers, GetDeviceDriverBaseNameW, GetDeviceDriverFileNameW,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_DESCRIPTIONW, SERVICE_DRIVER, SERVICE_QUERY_CONFIG,
    SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// A module mapped in kernel memory, as `EnumDeviceDrivers` reports it.
#[derive(Debug, Clone)]
pub struct Module {
    pub base: String,
    pub path: String,
}

/// A kernel driver service registered with the Service Control Manager.
#[derive(Debug, Clone)]
pub struct Driver {
    pub name: String,
    pub display: String,
    pub description: String,
    /// The binary path exactly as the SCM stores it.
    pub path: String,
    pub start: &'static str,
    pub state: &'static str,
}

/// A user-mode service, for the companion launchers.
#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub state: &'static str,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 string. A null pointer reads as empty.
///
/// # Safety
/// `text` must be null or point at a NUL-terminated UTF-16 string.
unsafe fn from_wide(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the caller promises a terminator; we stop at it.
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    }
}

fn state_name(state: u32) -> &'static str {
    match state {
        1 => "Stopped",
        2 => "Start Pending",
        3 => "Stop Pending",
        4 => "Running",
        5 => "Continue Pending",
        6 => "Pause Pending",
        7 => "Paused",
        _ => "Unknown",
    }
}

fn start_name(start: u32) -> &'static str {
    match start {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "-",
    }
}

// ------------------------------------------------------------------- console

/// Turn on ANSI escapes and UTF-8 for this console, set its title, and make Ctrl+C give the
/// cursor back. Returns whether escapes will be honoured.
pub fn prepare_console(title: &str) -> bool {
    unsafe extern "system" fn on_break(_kind: u32) -> i32 {
        print!("\x1b[0m\x1b[?25h");
        0
    }

    let title = wide(title);
    // SAFETY: plain console calls on our own handles with valid buffers.
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleTitleW(title.as_ptr());
        SetConsoleCtrlHandler(Some(on_break), 1);
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: CONSOLE_MODE = 0;
        if GetConsoleMode(out, &raw mut mode) == 0 {
            return false;
        }
        SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// The visible width of the console window, if there is one.
#[must_use]
pub fn console_width() -> Option<usize> {
    // SAFETY: the struct is plain data and the handle is our own.
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &raw mut info) == 0 {
            return None;
        }
        usize::try_from(info.srWindow.Right - info.srWindow.Left + 1).ok()
    }
}

// ----------------------------------------------------------------- privilege

fn process_token(access: u32) -> Option<HANDLE> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the out pointer is a local.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut token) };
    (ok != 0).then_some(token)
}

/// Is this process running elevated?
#[must_use]
pub fn is_elevated() -> bool {
    let Some(token) = process_token(TOKEN_QUERY) else {
        return false;
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = 0;
    // SAFETY: the buffer is exactly a TOKEN_ELEVATION and the token is ours to close.
    unsafe {
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &raw mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Enable `SeDebugPrivilege`, which recent Windows builds require before
/// `EnumDeviceDrivers` will hand out kernel addresses.
pub fn enable_debug_privilege() -> bool {
    let Some(token) = process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) else {
        return false;
    };
    let name = wide("SeDebugPrivilege");
    // SAFETY: every pointer is to a local, and the token is closed on the way out.
    unsafe {
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let mut ok = LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &raw mut luid) != 0;
        if ok {
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            ok = AdjustTokenPrivileges(
                token,
                0,
                &raw const privileges,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            ) != 0
                && GetLastError() == 0;
        }
        CloseHandle(token);
        ok
    }
}

/// Relaunch this executable elevated through UAC with `args`. True when the new process
/// was started, false when the user declined or it could not be launched.
#[must_use]
pub fn relaunch_elevated(args: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(args);
    // SAFETY: all strings are NUL-terminated locals.
    let code = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    code as usize > 32
}

// ------------------------------------------------------------ kernel modules

/// Every module mapped in kernel memory.
#[must_use]
pub fn kernel_modules() -> Vec<Module> {
    let mut list = Vec::new();
    let mut addresses: Vec<*mut c_void> = vec![ptr::null_mut(); 4096];
    let mut needed = 0u32;

    // SAFETY: the buffer size passed is the buffer's size in bytes.
    unsafe {
        let bytes = |v: &Vec<*mut c_void>| {
            u32::try_from(v.len() * size_of::<*mut c_void>()).unwrap_or(u32::MAX)
        };
        if EnumDeviceDrivers(addresses.as_mut_ptr(), bytes(&addresses), &raw mut needed) == 0 {
            return list;
        }
        let mut count = needed as usize / size_of::<*mut c_void>();
        if count > addresses.len() {
            addresses = vec![ptr::null_mut(); count + 64];
            if EnumDeviceDrivers(addresses.as_mut_ptr(), bytes(&addresses), &raw mut needed) == 0 {
                return list;
            }
            count = (needed as usize / size_of::<*mut c_void>()).min(addresses.len());
        }

        let mut base = [0u16; 260];
        let mut file = [0u16; 1024];
        for &address in &addresses[..count] {
            if address.is_null() {
                continue;
            }
            let n = GetDeviceDriverBaseNameW(address, base.as_mut_ptr(), 260);
            if n == 0 {
                continue;
            }
            let f = GetDeviceDriverFileNameW(address, file.as_mut_ptr(), 1024);
            list.push(Module {
                base: String::from_utf16_lossy(&base[..n as usize]),
                path: String::from_utf16_lossy(&file[..f as usize]),
            });
        }
    }
    list
}

// ------------------------------------------------------- service control manager

struct Scm(SC_HANDLE);

impl Scm {
    fn open() -> Option<Self> {
        // SAFETY: null machine and database mean the local SCM.
        let handle = unsafe {
            OpenSCManagerW(
                ptr::null(),
                ptr::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
            )
        };
        (!handle.is_null()).then_some(Self(handle))
    }

    /// `(name, display name, current state)` for every service of `kind`.
    fn enumerate(&self, kind: u32) -> Vec<(String, String, u32)> {
        let mut out = Vec::new();
        // u64 storage keeps the entries aligned.
        let mut buffer: Vec<u64> = vec![0; 8 * 1024];
        let mut resume = 0u32;
        loop {
            let mut needed = 0u32;
            let mut returned = 0u32;
            // SAFETY: the buffer and its length agree; entries are read only up to `returned`.
            unsafe {
                let ok = EnumServicesStatusExW(
                    self.0,
                    SC_ENUM_PROCESS_INFO,
                    kind,
                    SERVICE_STATE_ALL,
                    buffer.as_mut_ptr().cast(),
                    u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX),
                    &raw mut needed,
                    &raw mut returned,
                    &raw mut resume,
                    ptr::null(),
                );
                let more = ok == 0 && GetLastError() == ERROR_MORE_DATA;
                if ok == 0 && !more {
                    break;
                }
                let entries = buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>();
                for i in 0..returned as usize {
                    let entry = &*entries.add(i);
                    out.push((
                        from_wide(entry.lpServiceName),
                        from_wide(entry.lpDisplayName),
                        entry.ServiceStatusProcess.dwCurrentState,
                    ));
                }
                if !more {
                    break;
                }
                if needed as usize > buffer.len() * 8 {
                    buffer = vec![0; (needed as usize).div_ceil(8)];
                }
            }
        }
        out
    }

    /// `(binary path, start type, description)` for one service.
    fn config(&self, name: &str) -> (String, u32, String) {
        let name = wide(name);
        // SAFETY: buffers are sized from the first call's answer and outlive every read.
        unsafe {
            let service = OpenServiceW(self.0, name.as_ptr(), SERVICE_QUERY_CONFIG);
            if service.is_null() {
                return (String::new(), u32::MAX, String::new());
            }
            let mut path = String::new();
            let mut start = u32::MAX;
            let mut description = String::new();

            let mut needed = 0u32;
            QueryServiceConfigW(service, ptr::null_mut(), 0, &raw mut needed);
            if GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > 0 {
                // u64 storage keeps the struct aligned.
                let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
                let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
                if QueryServiceConfigW(service, config, needed, &raw mut needed) != 0 {
                    path = from_wide((*config).lpBinaryPathName);
                    start = (*config).dwStartType;
                }
            }

            needed = 0;
            QueryServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                ptr::null_mut(),
                0,
                &raw mut needed,
            );
            if GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > 0 {
                let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
                let info = buffer.as_mut_ptr().cast::<SERVICE_DESCRIPTIONW>();
                if QueryServiceConfig2W(
                    service,
                    SERVICE_CONFIG_DESCRIPTION,
                    info.cast(),
                    needed,
                    &raw mut needed,
                ) != 0
                {
                    description = from_wide((*info).lpDescription);
                }
            }

            CloseServiceHandle(service);
            (path, start, description)
        }
    }
}

impl Drop for Scm {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW and is closed once.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// Every kernel and file-system driver service, the way `sc query type= driver` lists them.
#[must_use]
pub fn driver_services() -> Vec<Driver> {
    let Some(scm) = Scm::open() else {
        return Vec::new();
    };
    scm.enumerate(SERVICE_DRIVER)
        .into_iter()
        .map(|(name, display, state)| {
            let (path, start, description) = scm.config(&name);
            Driver {
                name,
                display,
                description,
                path,
                start: start_name(start),
                state: state_name(state),
            }
        })
        .collect()
}

/// Every user-mode service.
#[must_use]
pub fn user_services() -> Vec<Service> {
    let Some(scm) = Scm::open() else {
        return Vec::new();
    };
    scm.enumerate(SERVICE_WIN32)
        .into_iter()
        .map(|(name, _, state)| Service {
            name,
            state: state_name(state),
        })
        .collect()
}

// ---------------------------------------------------------------- the system

/// `%SystemRoot%`, normally `C:\Windows`.
#[must_use]
pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned())
}

/// The drivers folder.
#[must_use]
pub fn drivers_dir() -> PathBuf {
    PathBuf::from(system_root())
        .join("System32")
        .join("drivers")
}

fn registry_string(key: &str, value: &str) -> Option<String> {
    let key = wide(key);
    let value = wide(value);
    let mut buffer = [0u16; 256];
    let mut size = u32::try_from(size_of_val(&buffer)).unwrap_or(0);
    // SAFETY: the buffer and its size in bytes agree.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    if status != 0 {
        return None;
    }
    let chars = (size as usize / 2).saturating_sub(1).min(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..chars]))
}

/// "Windows 11 Enterprise (26200)".
#[must_use]
pub fn os_caption() -> String {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut product = registry_string(KEY, "ProductName").unwrap_or_else(|| "Windows".to_owned());
    let build = registry_string(KEY, "CurrentBuildNumber").unwrap_or_default();
    // Windows 11 still calls itself Windows 10 in ProductName; the build number does not lie.
    if build.parse::<u32>().is_ok_and(|b| b >= 22000) {
        product = product.replace("Windows 10", "Windows 11");
    }
    if build.is_empty() {
        product
    } else {
        format!("{product} {build}")
    }
}

/// The local wall-clock time, `yyyy-mm-dd hh:mm:ss`.
#[must_use]
pub fn local_time() -> String {
    // SAFETY: SYSTEMTIME is plain data filled in by the call.
    let t: SYSTEMTIME = unsafe {
        let mut t = std::mem::zeroed();
        GetLocalTime(&raw mut t);
        t
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    )
}
