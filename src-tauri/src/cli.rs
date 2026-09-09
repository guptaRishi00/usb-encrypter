//! Console mode: `VaultDrive.exe --unlock-folder <dir>` and `--lock-folder <dir>`.
//!
//! This is what `Unlock.cmd` and `Lock.cmd` run. It never starts Tauri, so it
//! needs no WebView2 and opens no window: on a machine that has never seen
//! VaultDrive, double-clicking the .cmd is enough.
//!
//! The executable is built as a GUI-subsystem program so the normal launch
//! shows no console. That means a console started by cmd.exe is not ours until
//! we attach to it, which is the first thing this module does on Windows.

use std::io::{self, BufRead, Write};
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::KdfParams;
use crate::error::VaultError;
use crate::vault::{
    folder_lock_state, lock_folder_in_place, unlock_folder_in_place, FolderLockState,
    ProgressSink, ProgressSnapshot,
};

/// Exit codes the launchers can act on.
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_FAILED: i32 = 1;

/// Handle `args` if they select console mode. Returns `None` when they do not,
/// so the caller falls through to the window.
pub fn maybe_run(args: &[String]) -> Option<i32> {
    let flag = args.get(1).map(String::as_str)?;
    let folder = args.get(2).map(String::as_str);
    match flag {
        "--unlock-folder" => Some(run(folder, Mode::Unlock)),
        "--lock-folder" => Some(run(folder, Mode::Lock)),
        "--help" | "-h" | "/?" => {
            console::attach();
            print_usage();
            Some(EXIT_OK)
        }
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unlock,
    Lock,
}

fn print_usage() {
    println!("VaultDrive console mode");
    println!();
    println!("  VaultDrive.exe --unlock-folder <folder>   restore a folder locked in place");
    println!("  VaultDrive.exe --lock-folder <folder>     lock a folder in place");
    println!();
    println!("Run with no arguments to open the window.");
}

fn run(folder: Option<&str>, mode: Mode) -> i32 {
    console::attach();

    let Some(folder) = folder else {
        eprintln!("A folder path is required.");
        print_usage();
        return EXIT_USAGE;
    };
    let folder = Path::new(folder);

    let state = folder_lock_state(folder);
    match (mode, state) {
        (_, FolderLockState::Unavailable) => {
            eprintln!("That folder cannot be read: {}", folder.display());
            return EXIT_FAILED;
        }
        (Mode::Unlock, FolderLockState::Locked) | (Mode::Lock, FolderLockState::Unlocked) => {}
        (Mode::Unlock, _) => {
            println!("This folder is not locked. There is nothing to do.");
            return EXIT_OK;
        }
        (Mode::Lock, FolderLockState::Locked) => {
            println!("This folder is already locked. Run Unlock.cmd to open it.");
            return EXIT_OK;
        }
        (Mode::Lock, FolderLockState::Empty) => {
            println!("This folder is empty. There is nothing to lock.");
            return EXIT_OK;
        }
    }

    let name = folder
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| folder.display().to_string());

    // A folder carrying the authenticator sidecar unlocks with a six-digit
    // code redeemed at the server, not with a password. Same engine underneath:
    // the released key is used exactly where the password would be.
    let remote = crate::remote::RemoteAuth::load(folder);

    let outcome = match mode {
        Mode::Unlock if remote.is_some() => {
            let auth = remote.expect("checked above");
            println!("Unlocking \"{name}\" with your authenticator app.");
            println!("This needs an internet connection.");
            let code = match read_password("Authenticator code: ") {
                Some(c) => c,
                None => return EXIT_FAILED,
            };
            println!("Checking the code with the server.");
            crate::remote::redeem(&auth.site, &auth.token, &code).and_then(|key| {
                println!("Deriving the key. This takes a moment on purpose.");
                unlock_folder_in_place(folder, &key, &Console::default()).map(|r| {
                    println!();
                    println!(
                        "Done. {} file(s) and {} folder(s) are back in \"{name}\".",
                        r.files, r.folders
                    );
                    println!("Run Lock.cmd when you want to lock it again.");
                })
            })
        }
        Mode::Lock if remote.is_some() => {
            let auth = remote.expect("checked above");
            println!("Locking \"{name}\" with your authenticator app.");
            println!("This needs an internet connection.");
            let code = match read_password("Authenticator code: ") {
                Some(c) => c,
                None => return EXIT_FAILED,
            };
            println!("Checking the code with the server.");
            crate::remote::redeem(&auth.site, &auth.token, &code).and_then(|key| {
                println!("Encrypting. The originals are deleted only after the vault is verified.");
                lock_folder_in_place(folder, &key, KdfParams::interactive(), true, &Console::default())
                    .map(|r| {
                        println!();
                        println!(
                            "Done. {} file(s) and {} folder(s) are now encrypted inside \"{name}\".",
                            r.files, r.folders
                        );
                    })
            })
        }
        Mode::Unlock => {
            println!("Unlocking \"{name}\".");
            let password = match read_password("Password: ") {
                Some(p) => p,
                None => return EXIT_FAILED,
            };
            println!("Deriving the key. This takes a moment on purpose.");
            unlock_folder_in_place(folder, password.as_bytes(), &Console::default()).map(|r| {
                println!();
                println!(
                    "Done. {} file(s) and {} folder(s) are back in \"{name}\".",
                    r.files, r.folders
                );
                println!("Run Lock.cmd when you want to lock it again.");
            })
        }
        Mode::Lock => {
            println!("Locking \"{name}\".");
            println!("Choose a password. If you forget it, nothing here can be recovered.");
            let password = match read_password("Password: ") {
                Some(p) => p,
                None => return EXIT_FAILED,
            };
            let again = match read_password("Confirm password: ") {
                Some(p) => p,
                None => return EXIT_FAILED,
            };
            if password.as_bytes() != again.as_bytes() {
                eprintln!("The two passwords do not match. Nothing was changed.");
                return EXIT_FAILED;
            }
            drop(again);
            println!("Encrypting. The originals are deleted only after the vault is verified.");
            lock_folder_in_place(
                folder,
                password.as_bytes(),
                KdfParams::interactive(),
                true,
                &Console::default(),
            )
            .map(|r| {
                println!();
                println!(
                    "Done. {} file(s) and {} folder(s) are now encrypted inside \"{name}\".",
                    r.files, r.folders
                );
                if !r.removal_failures.is_empty() {
                    println!();
                    println!("These could not be deleted and are still readable on disk:");
                    for f in &r.removal_failures {
                        println!("  {f}");
                    }
                    println!("Close whatever has them open and run Lock.cmd again.");
                }
            })
        }
    };

    match outcome {
        Ok(()) => EXIT_OK,
        Err(e @ (VaultError::Authentication | VaultError::WrongCode)) => {
            eprintln!();
            eprintln!("{e}");
            EXIT_FAILED
        }
        Err(e) => {
            eprintln!();
            eprintln!("{e}");
            EXIT_FAILED
        }
    }
}

/// Prompt without echo. The buffer is wiped when dropped.
fn read_password(prompt: &str) -> Option<Zeroizing<String>> {
    print!("{prompt}");
    let _ = io::stdout().flush();

    let mut line = Zeroizing::new(String::new());
    let read = console::with_echo_off(|| io::stdin().lock().read_line(&mut line));
    println!();
    match read {
        Ok(0) => {
            eprintln!("No password entered.");
            None
        }
        Ok(_) => {
            normalize_password_line(&mut line);
            if line.is_empty() {
                eprintln!("No password entered.");
                return None;
            }
            Some(line)
        }
        Err(_) => {
            eprintln!("Could not read from the console.");
            None
        }
    }
}

/// Strip the line terminator, and a UTF-8 byte-order mark if one arrived.
///
/// A person typing at a console never produces a BOM, but a password piped in
/// from PowerShell or read from a file often carries one on the first line
/// only, which made "password" and "confirm" compare unequal when they were
/// typed identically. Nothing else is trimmed: leading or trailing spaces in a
/// password are the user's to keep.
fn normalize_password_line(line: &mut String) {
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    if line.starts_with('\u{feff}') {
        line.remove(0);
    }
}

/// Progress on the console: one line per file, and a running byte count for
/// anything large enough to take a while.
#[derive(Default)]
struct Console {
    last_line_len: std::sync::atomic::AtomicUsize,
}

impl ProgressSink for Console {
    fn report(&self, s: ProgressSnapshot, current_name: &str) {
        use std::sync::atomic::Ordering;
        let pct = if s.total_bytes > 0 {
            (s.bytes_done * 100 / s.total_bytes).min(100)
        } else if s.total_files > 0 {
            s.files_done * 100 / s.total_files
        } else {
            100
        };
        let line = format!("  {pct:>3}%  {}/{}  {current_name}", s.files_done, s.total_files);
        let prev = self.last_line_len.swap(line.len(), Ordering::Relaxed);
        // Overwrite the previous status line in place; pad so a shorter line
        // fully covers a longer one.
        print!("\r{line}{}", " ".repeat(prev.saturating_sub(line.len())));
        let _ = io::stdout().flush();
    }
}

#[cfg(windows)]
mod console {
    use std::io;

    type Handle = *mut core::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
        fn GetStdHandle(std_handle: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    /// Join the console of whatever launched us (cmd.exe, for the launchers),
    /// but only if we were given no standard input at all.
    ///
    /// A GUI-subsystem process started from a console by a double-click gets
    /// null standard handles, and attaching is what gives it the prompt. If a
    /// handle is already there -- stdin redirected from a file or a pipe, as a
    /// script would do -- attaching would swap it for the console and the
    /// process would sit waiting for keystrokes nobody is going to type.
    pub fn attach() {
        // SAFETY: plain Win32 calls with documented sentinel arguments.
        unsafe {
            if GetStdHandle(STD_INPUT_HANDLE).is_null() {
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
        }
    }

    pub fn with_echo_off<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        // SAFETY: Win32 calls on the process's own standard input handle. The
        // mode is restored on every path, including an error from `f`.
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            let have_mode = GetConsoleMode(h, &mut mode) != 0;
            if have_mode {
                SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
            }
            let out = f();
            if have_mode {
                SetConsoleMode(h, mode);
            }
            out
        }
    }
}

#[cfg(not(windows))]
mod console {
    use std::io;
    use std::process::Command;

    /// A `.command` file already runs in Terminal, so there is nothing to
    /// attach to on macOS or Linux.
    pub fn attach() {}

    /// Turn terminal echo off around `f` using `stty`, which every macOS and
    /// Linux system ships. Going through the program rather than `termios`
    /// avoids declaring a struct whose layout differs between the two.
    ///
    /// If stdin is not a terminal (a script piping the password in), `stty`
    /// fails and echo is simply left alone; that is the redirected case, where
    /// nothing is displayed anyway.
    pub fn with_echo_off<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let had_tty = Command::new("stty").arg("-echo").status().map(|s| s.success()).unwrap_or(false);
        let out = f();
        if had_tty {
            let _ = Command::new("stty").arg("echo").status();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_piped_first_line_with_a_bom_equals_the_typed_second_line() {
        let mut first = String::from("\u{feff}gravel tunnel morning kettle\r\n");
        let mut second = String::from("gravel tunnel morning kettle\r\n");
        normalize_password_line(&mut first);
        normalize_password_line(&mut second);
        assert_eq!(first, second);
        assert_eq!(first, "gravel tunnel morning kettle");
    }

    #[test]
    fn spaces_inside_and_around_a_password_are_kept() {
        let mut line = String::from("  two  spaces  \n");
        normalize_password_line(&mut line);
        assert_eq!(line, "  two  spaces  ");
    }

    #[test]
    fn unrelated_arguments_fall_through_to_the_window() {
        let args = vec!["VaultDrive.exe".to_string()];
        assert_eq!(maybe_run(&args), None);
        let args = vec!["VaultDrive.exe".to_string(), "some.vault".to_string()];
        assert_eq!(maybe_run(&args), None);
    }

    #[test]
    fn a_missing_folder_argument_is_a_usage_error() {
        let args = vec!["VaultDrive.exe".to_string(), "--unlock-folder".to_string()];
        assert_eq!(maybe_run(&args), Some(EXIT_USAGE));
    }

    #[test]
    fn unlocking_a_folder_that_is_not_locked_is_a_no_op_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
        let args = vec![
            "VaultDrive.exe".to_string(),
            "--unlock-folder".to_string(),
            dir.path().to_string_lossy().into_owned(),
        ];
        assert_eq!(maybe_run(&args), Some(EXIT_OK));
        assert!(dir.path().join("a.txt").exists());
    }

    #[test]
    fn an_unreadable_path_fails_cleanly() {
        let args = vec![
            "VaultDrive.exe".to_string(),
            "--lock-folder".to_string(),
            "Q:\\no\\such\\folder\\anywhere".to_string(),
        ];
        assert_eq!(maybe_run(&args), Some(EXIT_FAILED));
    }
}
