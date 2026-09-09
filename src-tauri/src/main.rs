// Keep the console window hidden in release builds on Windows. VaultDrive is a
// desktop application; a stray terminal behind it looks like something failed.
// Console mode (`--unlock-folder`, `--lock-folder`) attaches to the console
// that launched it instead, so `Unlock.cmd` still gets a prompt.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = vaultdrive_lib::cli::maybe_run(&args) {
        std::process::exit(code);
    }
    vaultdrive_lib::run()
}
