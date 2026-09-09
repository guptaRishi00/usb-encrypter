# Session log — usb-encrypter (VaultDrive)

## 2026-09-09 — /task: build VaultDrive from an empty folder

- **Starting point:** `Desktop\usb-encrypter` existed and was **completely empty**.
  The workspace map (`Desktop\claude\.claude\CODEBASE_MAP.md`, 2026-09-04) does not
  mention it at all. Greenfield, so `/onboard` had nothing to map; noted rather than stopped.
- **Environment gap, asked first:** no Rust toolchain and no MSVC linker on this machine
  (only a 32-bit MinGW.org gcc 6.3.0, unusable for Rust). Without them the crypto core
  could be written but never compiled or tested. User chose to install. Installed
  `Microsoft.VisualStudio.2022.BuildTools` (VCTools + Win11 SDK) via winget and rustup
  (`x86_64-pc-windows-msvc`, `--no-modify-path`), then added `%USERPROFILE%\.cargo\bin`
  to the **user PATH**. cargo 1.98.1 / rustc 1.98.1. WebView2 runtime was already present.
- **Built:** Tauri 2 + React 19 + TypeScript + Vite shell; the whole vault engine in Rust.
  Format: single `.vault` container, 64-byte plaintext header (magic, version, cipher/kdf
  ids, Argon2 m/t/p, 32-byte salt) used as AAD for every AEAD in the file; 72-byte
  keywrap; **two 88-byte superblock slots** with generation counters for crash-safe
  commits; data region of per-file `aead::stream` BE32 chunk sequences (1 MiB); encrypted
  JSON index holding the whole tree. Argon2id 128 MiB/t=3/p=4 → KEK → unwraps a random
  master key → HKDF-SHA256 subkeys for index / superblock / content.
- **Two real bugs found by the tests, both fixed:**
  1. `validate_name("report.")` passed. It trimmed trailing dots to check for emptiness
     but never compared the trimmed string back, so a name Windows silently rewrites
     could enter the index. Now refused.
  2. **81 ms per file, constant, regardless of file size** — creating a 1000-file vault
     took 86 s. Measured it as linear (80.6 / 81.5 / 82.1 / 81.6 ms per file at
     N=100/200/400/800), so a fixed per-file cost, not an algorithm. Cause: every file
     allocated ~3 MiB of buffers (`Vec::with_capacity(CHUNK_SIZE)`, a `Zeroizing`
     1 MiB read buffer, a 1 MiB read-side buffer) and then **securely wiped** them —
     `zeroize` is a volatile byte-by-byte write, monomorphised into our crate at
     opt-level 0. A 15-byte file paid for a megabyte of wiping. Fixed by sizing every
     buffer to the file (capped at one chunk) and dropping a double-wipe in
     `FileStream::finish`. **81 ms → 0.66 ms per file, ~120x.** This was an application
     bug, not a test artefact.
- **Also:** added `[profile.dev.package."*"] opt-level = 3` — unoptimised ChaCha20 made
  the round-trip tests crawl.
- **Late additions after the first green run:** a `list_folders` command plus a "Move to..."
  destination dialog (the first cut only moved to the parent, which does not satisfy
  "Move files"), and restoring stored mtimes onto exported files via `File::set_modified`
  (they were stored but never written back). Both re-tested.
- **Verified:** `cargo test` → **189 passed, 0 failed** (104 unit + 84 integration across
  password / encryption / integrity / filesystem / security / browser suites), whole suite
  ~9 s. `tsc --noEmit` exit 0. `vite build` clean. UI rendered and driven in the browser
  pane: Home, Create, Open and Settings all correct in dark and light, **zero console
  errors** despite every Tauri `invoke` failing there (all call sites catch).
- **Portable build works.** `npm run build:portable` → exit 0, 4.7 MB exe. Launched it:
  window title `VaultDrive`, 19 WebView2 child processes, home screen rendered correctly
  in the real shell (screenshotted). The raw cargo binary came out as `vaultdrive.exe`,
  not the `VaultDrive.exe` the README and USB layout name, so `[[bin]] name = "VaultDrive"`
  was added to `Cargo.toml` to match `productName`.
- **Disk:** C: hit **0.18 GB free** mid-session (a release build failed with os error 112).
  `cargo clean` reclaimed 11.2 GB. The debug target alone reaches ~12.5 GB — worth
  knowing before any future Rust work on this machine.
- **Not verified:** the in-vault file browser page has no screenshot; it needs a real
  unlocked vault, which only the Tauri window can produce. macOS and Linux builds are
  untested (no machines) and the README says so rather than claiming portability.
- Nothing committed (the folder is not a git repository).

## 2026-09-09 (later) — /task: create a test vault and open it, to verify the browser

The one thing the previous session left unverified was the in-vault file browser, which
needs a real unlocked vault that only the Tauri window can produce. Drove the real
`VaultDrive.exe` end to end with Windows-MCP against a 6-file / 3-folder / 394 KB test tree
(text, a 0-byte file, a PNG, and 400 KB of `/dev/urandom`).

- **Create flow, in the real app:** drive list showed both real volumes with correct free
  space; the folder picker carried the custom title and the scan reported exactly
  `6 files · 3 folders · 394 KB`; the save dialog carried the `.vault` filter; the strength
  meter showed **Weak** for `password` and **Very strong** for the passphrase; the finished
  screen showed **Verified** and offered — did not perform — removal of the originals.
- **Header on disk decodes exactly as the README documents:** `VAULTDRV`, version 1,
  cipher 1, kdf 1, `0x00020000` = 131072 KiB (128 MiB), t=3, p=4, random salt, zeroed
  reserved bytes. Grepped the vault for content, every file name, and the password:
  **all absent**. Source folder untouched (6 files still there).
- **Wrong password** gave exactly `Incorrect password. The vault could not be unlocked.`
  and cleared the field. Correct password opened the browser.
- **Browser verified:** folders before files, sizes exact (incl. `0 B`), timestamps
  preserved; text preview byte-exact and image preview rendered, both labelled "decrypted
  in memory, not written to disk"; New folder, Move to... (the dialog added late last
  session — current parent correctly excluded), and Lock all worked. Deleting/committing
  surfaced a **Compact (1.7 KB → 3.4 KB)** button as superseded indexes became dead space,
  which is the documented behaviour showing itself.
- **Export proved the round trip:** all 6 files match by **SHA-256**, including the 400 KB
  binary and the empty file; mtime preserved to the second; zero `.vdpart`/`.vdtmp`
  leftovers.
- **`settings.json` and `vaultdrive.log` inspected:** log holds only counts, byte totals,
  generations and entry counts — no names, no paths, no keys. Settings hold theme,
  auto-lock and the recent list only.

**Three real defects the GUI run exposed, all fixed:**
1. The "Repeated characters add less protection" note fired on **any** doubled letter, so
   `gravel tunnel morning kettle` was flagged. Almost every English passphrase has one;
   advice that always fires gets ignored. Now needs repetition above 25%. Regression test
   added.
2. The file-preview dialog had **no Close button** — only Escape or clicking the scrim,
   neither discoverable. Added one.
3. **"Check integrity" was completely silent on success**, indistinguishable from a dead
   button. Now reports how many files decrypted and matched.

Verified after the fixes: `cargo test` **190 passed, 0 failed**; `tsc --noEmit` exit 0.
Nothing committed.

## 2026-09-09 (later still) — /task: run the app for manual testing

- Rebuilt and launched `src-tauri/target/release/VaultDrive.exe` (23:37, 4.7 MB) — the build
  carrying the three UX fixes from the previous entry. Window opened, WebView2 loaded.
- **Mistake worth recording:** the app appeared to boot onto the "Open Vault" route, which
  looked like a routing bug. It was not — the **user had already started clicking**. I
  "investigated" by restarting the process, which **destroyed their in-progress session**.
  When a human is driving the app, a surprising UI state is far more likely to be them than
  a bug. Observe, ask, do not restart.
- Staged `Desktop\VaultDrive-test\` for manual testing: `SampleVault.vault` (password
  `gravel tunnel morning kettle`), a `SampleFolder` to encrypt, and a READ ME. Deletable;
  nothing depends on it.
- **Bug spotted on the user's own screen:** the scan summary read `1 files · 0 folders`.
  Added a `quantity(n, singular)` helper in `services/format.ts` and used it for every
  file/folder/item count in `CreateVault` and `VaultBrowser`. `tsc --noEmit` exit 0.
  **Not yet in the running exe** — it needs a rebuild, deliberately deferred so as not to
  kill the user's session a second time.

## 2026-09-09 (later still) — /task: lock the existing folder, not a new .vault file

- **User's complaint, and it was right:** the create flow produced a separate `.vault` file
  somewhere else. They wanted the folder they picked to *become* locked, contents and all.
  The original spec only ever described the portable-container shape, so this is a genuine
  scope addition, not a bug fix.
- Implemented **lock in place** as real encryption, not a permissions or hidden-attribute
  trick — the spec forbids those and an admin or a different OS walks straight past them.
  `folder/` keeps its name and path; everything inside becomes `folder/.vaultdrive.vault`
  plus a plain `HOW TO UNLOCK.txt`. Same format, same crypto as the portable container.
- **Order is the safety argument** (`lock_folder_in_place`): scan → refuse if already locked
  → build the vault to a temp file renamed atomically → **reopen it with the same password
  and confirm the file count** → only then delete the plaintext. Any failure before the last
  step leaves every original untouched. On a verify failure the half-made container is
  removed too.
- `remove_folder_contents(root, keep)` added to `secure_delete` — empties a folder but keeps
  the folder itself and named entries. `keep` matches **case-insensitively**, because a name
  differing only in case is the same file on Windows and deleting it would destroy the vault.
- Fixed name `.vaultdrive.vault` on purpose: "is this locked?" is one `exists()` call rather
  than guessing from whatever `.vault` files are lying about.
- **Space:** the container is written beside the plaintext it encrypts, so the volume holds
  both at once. `ensure_space` runs up front; documented as a limitation, as is the case
  where another program holds a file open so the plaintext copy cannot be deleted (it is
  reported by name rather than silently left).
- UI: Create page now asks which shape you want, **in-place is the default**; nav item and
  home buttons renamed to "Lock a Folder" / "Unlock". Open page gained a "locked folder"
  source that picks a folder, reports its lock state, and restores in place.
- **Verified:** 13 new tests in `tests/in_place_tests.rs` passed first run; full suite
  **206 passed, 0 failed**; `tsc --noEmit` exit 0.

## 2026-09-10 — /task: a .cmd that unlocks a locked folder on another machine, without the app

- **Said plainly to the user:** "without the application" cannot mean without any code —
  Argon2id and XChaCha20-Poly1305 exist in neither cmd.exe nor PowerShell (the totp project
  reached for bcrypt AES-GCM for exactly this reason). What is possible is a **self-contained
  folder**: the lock copies `VaultDrive.exe` in beside `Unlock.cmd` / `Lock.cmd`, and the
  .cmd runs the exe in a new **console mode** (`--unlock-folder <dir>` / `--lock-folder <dir>`)
  that never starts Tauri — so no install, no window, **no WebView2** on the other machine.
- **GUI-subsystem gotcha:** the exe is `windows_subsystem = "windows"`, so a console started
  by cmd.exe is not ours. `cli::console::attach()` calls `AttachConsole(ATTACH_PARENT_PROCESS)`
  first; Rust's std fetches the std handles per call, so stdin/stdout work after that.
  Password read with `ENABLE_ECHO_INPUT` cleared via kernel32 FFI — **no new crate**; on
  non-Windows it reads visibly and says so rather than pretending.
- **The launchers are artefacts:** `IN_PLACE_ARTIFACTS` now lists all five files. They are
  excluded from the scan (or the exe would be encrypted into its own vault and then deleted —
  bricking the folder), kept by `remove_folder_contents`, and **kept on unlock** so `Lock.cmd`
  can re-lock on the other machine. Tested on a lock → unlock → re-lock cycle.
- **Tooling trap that cost real time:** writing a Rust literal containing `\r\n` through a
  bash heredoc got its backslashes mangled twice over (raw CR bytes → a compile error; then a
  `\n`-literal soup). Fixed by building the .cmd text at runtime with `lines.join("\r\n")`
  — no escapes in source at all. Lesson: never route Rust string escapes through a heredoc.
- Checkbox "Make it open on other computers too" on the in-place option, **on by default**.
- **Verified:** `cargo test` **212 passed, 0 failed** (4 cli unit tests + 2 new launcher
  integration tests, one asserting the copied exe is byte-identical to `current_exe()`);
  `tsc --noEmit` exit 0. Rebuild blocked by the user's running instance — asked before
  closing it this time.
- **Two bugs found only by running the real launcher, both fixed and rebuilt:**
  1. Piped/redirected input made "password" and "confirm" disagree even when identical:
     PowerShell prefixes piped native stdin with a UTF-8 BOM on the first line. Proven by
     feeding byte-exact ASCII via `Start-Process -RedirectStandardInput` (worked) vs a PS
     pipe (failed). `normalize_password_line` now strips a leading BOM; unit-tested.
  2. `Unlock.cmd` **hung** when stdin was redirected: `AttachConsole(ATTACH_PARENT_PROCESS)`
     was unconditional, and attaching swaps an inherited pipe for the console, so the exe
     waited for keystrokes nobody would type. A double-clicked GUI-subsystem exe gets **null**
     std handles, so the rule is now: attach only when `GetStdHandle(STD_INPUT_HANDLE)` is
     null. Both paths verified after the fix.
- **Verified with the rebuilt exe (00:42):** console-mode lock → `Unlock.cmd` wrong password
  refused, vault untouched → `Unlock.cmd` right password → **all 3 files SHA-256 identical**,
  vault gone, launchers kept → `Lock.cmd` re-locked; then the **real double-click path**: opened
  `Unlock.cmd` in its own console, typed the password (not echoed), restore confirmed on disk
  byte-identical. The copied `VaultDrive.exe` hashed identical to the build. Killing a run
  mid-unlock left `.vaultdrive.vault` intact with nothing half-restored. `cargo test`
  **214 passed, 0 failed**.
- **Harness traps this session:** a PS parameter named `$args` is shadowed by the automatic
  variable (the map already warns about this — I walked into it anyway); the sandbox blocks
  any command text containing `Remove-Item` near a `/c` token, so `cmd /c` can't share a call
  with cleanup; and `MainWindowHandle` is 0 for a cmd.exe hosted in Windows Terminal.
- **Cosmetic, not fixed:** console-mode unlock reports progress per top-level entry
  (`1/1 note.txt`) because `unlock_folder_in_place` exports each root child separately with
  its own totals. Correct restore, misleading counter.

## 2026-09-10 — /task: "can I deploy it in Vercel?"

- Answered, no code changed. **No:** VaultDrive is a Tauri desktop app; every operation runs in
  the Rust engine on the user's own machine via `invoke`. Vercel runs static sites and
  serverless functions — it cannot run a desktop binary, and the frontend alone on Vercel is
  a dead UI (already observed on 2026-09-09: every `invoke` rejects without the backend).
  A browser rewrite would mean JavaScript/WASM-only encryption, which the user's own spec
  §12 forbids; the sibling `usb-totp-vault/web` is that other design, deliberately.
- Offered: a static download page on Vercel (or GitHub Releases) serving `VaultDrive.exe`,
  `portable/README.txt` and the README. Not built — waiting for the user to choose.

## 2026-09-10 — /task: "so how can I deploy it?"

- Built `release/VaultDrive-0.1.0-windows-portable.zip` (1.88 MB: exe + portable README) and
  `release/SHA256SUMS.txt`. README "Installing" rewritten around distribution rather than
  hosting. Installer build (`npm run build` → NSIS/MSI) blocked by the user's running app
  holding the exe, and NSIS/WiX tooling would be downloaded on first use. GitHub Release needs
  a repo (the folder is not one) and `gh` (absent) or the user's account. Asked before any of
  that. Nothing committed.

## 2026-09-10 — /task: push to github.com/guptaRishi00/usb-encrypter

- User created the repo and gave the URL (superseding the gh-install plan). Added `origin`,
  pushed `main` (2 commits, 74 files; `release/`, `dist/`, `target/`, `node_modules/` ignored),
  verified with `git ls-remote`. Tagged `v0.1.0` and pushed the tag so a Release can be cut
  from it. Release assets (`release/*.zip`, `SHA256SUMS.txt`, `RELEASE_NOTES.md`) are ready
  locally; attaching them needs the GitHub UI or `gh` (not installed).

## 2026-09-10 — /task: unlock with an authenticator code instead of a password

- **Stopped to ask, per spec §26 ("if a feature cannot be implemented securely, do not fake
  it").** A TOTP code is 6 digits (~20 bits) computed from a shared secret + time. Offline, the
  verifying secret must live in or beside the vault, so whoever holds the drive holds the
  secret and can compute the code; and a master key wrapped under a 6-digit code falls to a
  million offline guesses in seconds. The sibling `usb-totp-vault` escapes this only by
  putting the secret on a server (web/, needs internet) or in per-machine DPAPI/Keychain
  (`vault.ps1`/`vault.py`, needs setup on every PC) — both contradict VaultDrive's offline,
  any-machine promise. Laid out the honest options and asked before building any.
- User re-asked for QR + authenticator code as the only unlock. Same math: the QR carries the
  TOTP secret; offline the vault must hold it to verify, so the drive holds the secret, and a
  6-digit space falls to offline guessing anyway. Only a server (their existing usbvault-web)
  or a hardware key makes a code meaningful. Asked once more with two concrete builds.
- **Built: authenticator mode via the user's own `usbvault-web`** (chosen over the offline
  password+code speed bump). New `remote.rs`: `enrol` (POST /api/create → token + otpauth),
  `redeem` (POST /api/unlock → 32-byte key, used verbatim as the vault password bytes so
  the container format is unchanged), `qr_svg` (rendered in Rust — the web vault's qrcodejs
  CDN would be blocked by Tauri's CSP). Sidecar `.vaultdrive.totp.json` {site, token,
  vaultId, name}; `deny_unknown_fields` + a test so a future change cannot persist the key
  beside the vault. Sidecar is an in-place artefact (kept on unlock, never encrypted).
  Errors: 401→WrongCode, 429→TooManyAttempts, transport→Offline, other→RemoteAuth (capped).
  Console mode prompts "Authenticator code:" when the sidecar exists, for unlock and re-lock.
  UI: "Protect it with: password / authenticator app" on the lock page with the QR + manual
  key + code proof; code entry on the unlock page. Deps added with permission: `ureq`,
  `qrcode`. `cargo test` **221 passed**; `tsc` clean. Verified the stand-in TOTP (RFC 6238
  vector) is accepted by the live server before touching the exe.
- **Live end-to-end against usbvault-web.vercel.app with the rebuilt exe (6.2 MB; rustls adds
  ~1.2 MB):** console-mode lock with a real code → folder holds exactly the six artefacts, no
  plaintext, no manual key anywhere → `Unlock.cmd` with `000000` → "Incorrect code", vault
  untouched → `Unlock.cmd` with a fresh code → all 3 files SHA-256 identical, vault gone,
  sidecar + launchers kept → `Lock.cmd` with a fresh code → re-locked under the same
  authenticator entry. Codes are single-use per vault (server, 120 s), so each step waited for
  the next 30-s window. Stand-in TOTP passes the RFC 6238 vector and was accepted by the
  server before any exe step. Not committed — the user did not ask for a commit this round.

## 2026-09-10 — /task: "what about macOS? do something for it"

- **Answer:** `Unlock.cmd` is a batch file running `VaultDrive.exe`; a Mac can run neither.
  **No Mac binary can be built here** (Windows host, no Xcode) — and `cargo check
  --target x86_64-apple-darwin` on the full crate dies in `objc2-exception-helper`'s C build
  script (needs a Mac `cc`) before reaching our code. So: built the Mac side, proved the
  platform-gated lines compile for the Apple target in an isolated crate, and labelled the
  rest untested.
- **Design:** every lock now writes launchers for **both** platforms (`Unlock.cmd`/`Lock.cmd`
  + `Unlock.command`/`Lock.command`), and each platform's build copies **its own** binary
  under its own name (`VaultDrive.exe` / `VaultDrive-macos`, via `OWN_LAUNCHER_BINARY`).
  A folder locked only on Windows carries an `Unlock.command` that says the Mac program is
  not in it yet; lock it once from a Mac and both launchers work. All ten names are
  artefacts (never encrypted, never deleted) — tested with a fake `VaultDrive-macos` that
  survives a Windows lock/unlock and never enters the vault.
- **.command details:** `#!/bin/bash`, LF only (bash treats CR as part of a command),
  `cd "$(dirname "$0")"`, `chmod +x` on the binary (a Windows-formatted stick carries no
  Unix mode bits), best-effort `xattr -d com.apple.quarantine`, `read -p` to hold the
  window. Password prompt on Unix now hides echo via `stty -echo`/`stty echo` (no termios
  struct to get wrong across macOS/Linux; falls back gracefully when stdin is a pipe).
- **Verified:** `cargo test` **222 passed, 0 failed** (Windows). Isolated darwin
  `cargo check` of the exact `#[cfg(not(windows))]` console module and the unix branches of
  `write_launchers`: **Finished, exit 0**. Two test-fixture slips fixed along the way
  (`"pw"` is a substring of `$(pwd)`; earlier `"Secret"` tripped a forbidden-word scan).
- **Unverified, stated in README:** Gatekeeper behaviour on an unsigned Mach-O launched
  from a `.command`, exFAT mount exec permissions, and the whole flow on real macOS.

## 2026-09-10 — /task: push the code

- Committed the work since `v0.1.0` (authenticator mode, cross-platform launchers, console-mode
  fixes, pluralisation, docs) as one commit — the features share `cli.rs`, `vault/mod.rs` and
  the in-place tests, so a per-feature split would not have been honest — and pushed `main`.
  Not tagged: the user asked to push, not to cut a release; `release/` still holds the 0.1.0
  zip, which predates every change in this commit.
