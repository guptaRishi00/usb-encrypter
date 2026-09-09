# VaultDrive

Lock a folder where it sits, or pack it into a single portable `.vault` file for
a USB stick. Either way it opens with the password, and with nothing else.

VaultDrive does not hide folders, set permissions, or rename extensions. The
file contents are encrypted with XChaCha20-Poly1305 under a key derived from
your password with Argon2id. Copy the `.vault` file to another machine and it is
an opaque blob: no file names, no folder structure, no sizes, no file count.

It runs entirely offline. There is no account, no server, and no network code in
the application at all.

> **VaultDrive cannot recover a forgotten password. There is no master password
> and no backdoor.** The key exists only while you have the vault open, and it
> is derived from your password every time. If you forget it, the data is gone.

---

## Contents

- [What it does](#what-it-does)
- [Installing](#installing)
- [Development setup](#development-setup)
- [Commands](#commands)
- [Supported operating systems](#supported-operating-systems)
- [Vault format](#vault-format)
- [Security architecture](#security-architecture)
- [Threat model](#threat-model)
- [Testing](#testing)
- [Portable Windows build](#portable-windows-build)
- [Known limitations](#known-limitations)
- [Project structure](#project-structure)

---

## What it does

There are two ways to protect a folder, and the app asks which you want.

- **Lock a folder in place** (the default). `D:\Secret` keeps its name and its
  location. Everything inside it is encrypted into a single `.vaultdrive.vault`
  file within the folder, and the plaintext is deleted only after that file has
  been reopened with your password and checked. Unlock it later and the contents
  come back exactly where they were. Move or rename the folder and it stays
  locked; it carries everything it needs.
- **Create a separate `.vault` file.** The original folder is left completely
  alone and a portable container is written wherever you choose. This is the one
  to use for putting a copy on a USB drive.

Both use the same format and the same cryptography. The only difference is where
the container lands and whether the originals are removed.

- **Open a vault.** Point at a `.vault` file or at a locked folder, type the
  password. Wrong passwords all fail identically.
- **Browse inside.** A file browser inside the app: folders, import, export,
  create, rename, move, delete. Text and image files can be previewed without
  ever being written to disk.
- **Lock.** Manually, or automatically after a chosen period of inactivity.
- **Remove the originals.** Only if you ask, only after the vault is verified,
  and with an honest description of what overwriting can and cannot guarantee on
  flash media.

---

## Installing

VaultDrive is a desktop program, so "deploying" it means distributing files, not
hosting a site. The artefacts live in `release/`:

| File | What it is |
|---|---|
| `VaultDrive-<version>-windows-portable.zip` | `VaultDrive.exe` plus a README. Unzip anywhere, including a USB stick. No installer. |
| `SHA256SUMS.txt` | Checksums for the zip and the bare exe, so a download can be verified. |

Build them with `npm run build:portable`, then zip the exe with
`portable/README.txt`. `npm run build` additionally produces NSIS and MSI
installers under `src-tauri/target/release/bundle/`.

Publish them somewhere with a stable URL — a GitHub Release is the conventional
home for a desktop binary — and link to that from wherever you want a download
page. Until the executable is code-signed, Windows SmartScreen will warn on
first run; the portable README tells users what to click.

---

## Development setup

**Prerequisites**

| | |
|---|---|
| Node.js | 18 or newer (built and tested on 22) |
| Rust | stable, 1.77 or newer (built and tested on 1.98) |
| Windows | Visual Studio Build Tools with the "Desktop development with C++" workload, and the WebView2 runtime (already present on Windows 11) |
| macOS | Xcode command line tools |
| Linux | `webkit2gtk-4.1`, `libayatana-appindicator3`, `librsvg2`, `build-essential` |

```bash
git clone https://github.com/guptaRishi00/usb-encrypter.git
cd usb-encrypter
npm install
npm run dev
```

`npm run dev` starts Vite on port 5273 and launches the Tauri window against it.
The first Rust build takes several minutes; later ones are incremental.

---

## Commands

| Command | What it does |
|---|---|
| `npm run dev` | Run the app with hot reload |
| `npm run dev:vite` | Frontend only, in a browser (backend calls fail; useful for styling) |
| `npm run typecheck` | TypeScript, no emit |
| `npm run build:vite` | Typecheck and build the frontend into `dist/` |
| `npm run build` | Full desktop build with installers |
| `npm run build:portable` | Single portable `VaultDrive.exe`, no installer |
| `npm run test:rust` | The Rust test suite |
| `npm test` | Typecheck plus the Rust test suite |

---

## Supported operating systems

Windows is the priority, because the portable USB workflow is the point.

| | Status |
|---|---|
| Windows 10 / 11 (x64) | Built and tested |
| macOS | Should build; **not tested — no machine available** |
| Linux | Should build; **not tested — no machine available** |

Everything platform-specific is behind `src-tauri/src/filesystem/`: drive
enumeration and free space go through `sysinfo`, and vault writes go through one
atomic-replace helper. Nothing above that layer knows which system it is on. The
macOS and Linux claims above are honest expectations, not verified results.

---

## Vault format

One file. Everything after byte 64 is ciphertext.

```
offset  size  contents
------  ----  --------------------------------------------------------------
     0     8  MAGIC = "VAULTDRV"
     8     2  format version (u16 LE), currently 1
    10     1  cipher id  (1 = XChaCha20-Poly1305)
    11     1  kdf id     (1 = Argon2id)
    12     4  Argon2id memory cost in KiB (u32 LE)
    16     4  Argon2id passes             (u32 LE)
    20     4  Argon2id lanes              (u32 LE)
    24    32  salt, random per vault
    56     8  reserved, zero
---- 64: end of HEADER. These 64 bytes are the AAD for every AEAD below. ----
    64    72  KEYWRAP: nonce24 ‖ enc(master key) ‖ tag16
   136    88  SUPERBLOCK slot A
   224    88  SUPERBLOCK slot B
---- 312: data region --------------------------------------------------------
   ...        per-file STREAM(XChaCha20-Poly1305) chunk sequences
   ...        the encrypted directory index, located by the live superblock
```

**The header carries no secrets.** An algorithm id, three cost parameters, and a
random salt. It reveals that the file is a VaultDrive vault and nothing else —
not the file count, not a name, not a size.

**The index is where the tree lives.** File names, extensions, sizes,
timestamps and the folder hierarchy are serialised to JSON, encrypted, and
written into the container. Someone inspecting a `.vault` cannot tell whether it
holds one photograph or ten thousand medical records.

**File contents use the STREAM construction.** Each file is encrypted in 1 MiB
chunks with a per-file 19-byte nonce, using `aead::stream`'s BE32 counter. That
means a chunk cannot be reordered, duplicated, dropped, or truncated without
failing authentication — not just modified. Each chunk's associated data binds
the vault header and the file's id, so a chunk stream cannot be relabelled as a
different file or moved into another vault.

**Two superblocks, because edits must be crash-safe.** A superblock records
where the live index is. Renaming a file in a four-gigabyte vault must not
rewrite four gigabytes, and overwriting a single record in place is not
crash-safe. So there are two fixed slots, each with a generation counter and its
own authentication tag. A commit appends the new index, flushes, writes the
*older* slot, and flushes again. Opening picks the highest generation that
authenticates. A crash during a commit leaves the other slot intact and the
vault opens at the previous generation: the interrupted edit is lost, the vault
is not.

**A folder locked in place** holds the container, named `.vaultdrive.vault` so
detection is one `exists()` call rather than a guess, and `HOW TO UNLOCK.txt`, a
plain note explaining what happened. The note contains no secret. Nothing else
of yours survives in the folder.

**Self-contained folders.** With "Make it open on other computers" ticked (the
default), the lock also drops a copy of `VaultDrive.exe` plus `Unlock.cmd` and
`Lock.cmd` into the folder. The `.cmd` files run the exe in **console mode**
(`--unlock-folder` / `--lock-folder`), which attaches to the console that
launched it when it was given no standard input (a double-click), reads from a
redirected pipe or file otherwise (a script), asks for the password without
echo, tolerates a leading UTF-8 byte-order mark on piped input, and works on the
folder it sits in. Console mode never starts Tauri, so it needs **no installation, no window and
no WebView2**: plug the drive into any Windows machine and double-click
`Unlock.cmd`. Unlocking keeps the three launcher files so `Lock.cmd` can lock the
folder again before you unplug. The launchers are never encrypted into the vault
and never deleted with the plaintext, on a first lock or a re-lock. There is no
way to do this "without any program": Argon2id and XChaCha20-Poly1305 are not
available to a bare `.cmd` or to PowerShell, so the folder has to carry the
engine.

**Deletion leaves dead space.** Removing an entry unlinks it from the index; the
ciphertext stays in the container as unreachable bytes until you press Compact,
which rebuilds the file atomically. The UI says this rather than implying a
shred.

---

## Security architecture

```
password ──▶ Argon2id(salt, 128 MiB, t=3, p=4) ──▶ key-encryption key
                                                          │
                        random 256-bit master key ◀── unwraps KEYWRAP
                                    │
                    HKDF-SHA256(salt, master, purpose)
                    ├── index key       (directory tree)
                    ├── superblock key  (commit records)
                    └── content key     (file contents)
```

- **Nothing is hand-rolled.** Argon2id from `argon2`, XChaCha20-Poly1305 and
  STREAM from `chacha20poly1305`/`aead`, HKDF from `hkdf`, all RustCrypto. This
  project wires them together and decides what is bound as associated data; it
  implements no primitive.
- **Every vault gets a fresh 32-byte salt** from the OS CSPRNG, so two vaults
  with the same password share no key material and produce different files from
  identical input.
- **Every segment is authenticated.** The wrapped key, both superblocks, the
  index, and every file chunk carry a Poly1305 tag, and each binds the 64-byte
  header as associated data plus a purpose label. Segments cannot be swapped
  between purposes or between vaults.
- **Keys never touch the disk or the web view.** The master key and all subkeys
  are `Zeroize`/`Zeroizing` and are wiped when the vault is locked. `MasterKey`'s
  `Debug` prints `MasterKey(<redacted>)` so a stray log line cannot leak it.
- **The password is used once** to derive the key-encryption key, held in a
  `Zeroizing` buffer, and dropped.
- **Wrong passwords are indistinguishable.** Wrong password, altered header and
  altered keywrap all return the same error with the same text. Nothing narrows
  the search.
- **Auto-lock is enforced in Rust**, not by a JavaScript timer. A hung renderer
  or an open devtools console cannot keep a vault unlocked past its interval.
- **The web view is not trusted.** It holds entry ids and names for display. It
  cannot read the vault file, and every command validates its arguments in Rust.
  The Tauri capability set grants dialogs and events, and no filesystem plugin.
- **Names are validated in both directions.** A vault someone shares with you
  could carry an entry named `..\..\Startup\evil.exe`. Names are checked when
  they enter the index and again when an export path is built, and the assembled
  path is confirmed to be under the destination folder.

### What is never logged

Passwords, keys, nonces, salts, plaintext contents, and full file paths. The log
records counts, byte totals, durations, vault generations and error kinds. File
names appear in the live progress panel because you asked to watch the
encryption, but they are not written to the log. Settings → Diagnostic log shows
exactly what is on disk; there is no separate "sanitised" export because there is
nothing to sanitise.

---

## Threat model

**VaultDrive protects against**

- Losing the USB drive. Whoever finds it sees an opaque file.
- Someone copying the `.vault` file off your drive.
- Someone modifying the vault. Every segment is authenticated, so tampering is
  detected rather than silently decrypted into corrupt output.
- Casual inspection. The container reveals no names, sizes or file count.
- Offline password guessing, to the strength of your password. Each guess costs a
  full Argon2id evaluation at 128 MiB.

**VaultDrive does not protect against**

- **A compromised computer.** Malware, a keylogger, or another administrator on
  the machine can read the password as you type it and the plaintext while the
  vault is open. There is no defence against this from inside an application.
- **Memory capture while unlocked.** Keys are wiped on lock, but while a vault is
  open they are in RAM, and the operating system may page them to disk. Rust
  cannot prevent that portably.
- **A forgotten password.** Nothing recovers it.
- **Traffic analysis of the file itself.** The vault's *size* is roughly the size
  of your data. That leaks how much you are protecting, not what.
- **Someone who already has your original folder.** Encrypting a copy does
  nothing about the copy.
- **Forensic recovery of the originals** after "Remove originals". See below.

---

## Testing

```bash
npm run test:rust      # 214 tests
npm test               # typecheck + the above
```

The suite is organised the way the requirements are:

| Suite | Covers |
|---|---|
| `src-tauri/src/**` unit tests (114) | Header encoding, superblock bounds, AEAD round trips and every-bit tampering, chunk reordering, index structure and name validation, atomic replace, source scanning, drive enumeration, secure deletion, settings, password scoring |
| `tests/password_tests.rs` (10) | Correct and incorrect passwords, empty and 5 KB passwords, Unicode, and that a near-miss and a wild guess fail identically |
| `tests/encryption_tests.rs` (15) | Round trips for nested trees, empty files, empty folders, all 256 byte values, files spanning several chunks, Unicode names, 1000-file vaults, timestamp preservation through export, and opening a vault after moving it |
| `tests/integrity_tests.rs` (16) | Bit flips in the header, keywrap, superblocks and data; truncation at ~150 cut points; appended junk; wrong format version; unknown cipher; a hostile Argon2 parameter; splicing data between two vaults |
| `tests/filesystem_tests.rs` (14) | Missing drive, cancellation, files that grow or shrink mid-write, read-only media, and the OS-error mapping for locked files, removed devices and full disks |
| `tests/security_tests.rs` (14) | That the vault file contains no plaintext, no file names, and no password; that identical files do not produce identical ciphertext; that settings hold nothing secret; that deleted data leaves the file after compaction; that creation never deletes the source |
| `tests/in_place_tests.rs` (15) | Locking a folder in place, with and without launchers: what survives in the folder, byte-for-byte round trips, state reporting, that no plaintext or file name remains, wrong password, double-lock, empty folder, empty password, moving a locked folder, three lock/unlock cycles, a tampered container, and the note left behind |
| `tests/browser_tests.rs` (16) | Import, export, rename, move, delete, create folder, 30 sequential edits, superblock alternation, and compaction |

Tests use deliberately weak Argon2 parameters
(`KdfParams::insecure_fast_for_tests`, 8 KiB / 1 pass) so the suite runs in about
nine seconds. The application always uses `KdfParams::interactive()`.

---

## Portable Windows build

```bash
npm run build:portable
```

The executable lands at:

```
src-tauri/target/release/VaultDrive.exe
```

Copy it onto the USB drive next to your vault, along with
[`portable/README.txt`](portable/README.txt), which explains the SmartScreen
warning and the no-recovery rule to whoever picks the drive up:

```
USB DRIVE
├── VaultDrive.exe
├── MyVault.vault
└── README.txt
```

It needs no installation, no internet, no account, and not the computer the
vault was made on.

### Portability limits, stated plainly

- **A self-unlocking folder does not need WebView2**, because `Unlock.cmd` runs
  console mode, which never opens a window. The limits below apply to the full
  application only.
- **WebView2 is required.** VaultDrive draws its interface in the system web
  view. Windows 11 and current Windows 10 ship WebView2, but a machine without it
  will show an error rather than a window, and installing it needs administrator
  rights and a download. This is the one thing that can stop a portable run.
- **SmartScreen will warn.** An unsigned executable off a USB stick gets "Windows
  protected your PC" until someone clicks More info → Run anyway. Code signing
  removes this; it needs a certificate this project does not have.
- **Locked-down machines may refuse it.** AppLocker, Windows Defender
  Application Control, or a policy blocking executables on removable media will
  stop it, and nothing in the application can work around that by design.
- **The vault stays on the drive.** VaultDrive writes one settings file in the
  user's app-data folder for the theme, auto-lock interval and recent-vault
  list. Nothing secret, but it does mean a portable run leaves that trace on the
  host machine.

---

## Known limitations

1. **Forgotten passwords are unrecoverable.** By design, and worth repeating.
2. **The web view sees the password as a JavaScript string.** It is passed
   straight to a command and the reference is dropped, but JavaScript strings are
   immutable and cannot be wiped, so a copy may sit in the renderer's heap until
   garbage collection. Rust wipes its copies. Removing this entirely would mean
   collecting the password outside the web view.
3. **Only text and image files preview in the app.** Anything else must be
   exported, because handing a file to another program means writing the
   plaintext to disk first. Preview is capped at 8 MB.
4. **"Remove originals" is not forensic erasure.** Each file is overwritten once
   with random bytes and deleted. On SSDs and USB flash drives, wear levelling
   means the overwrite usually lands on different physical cells and the
   originals may survive until the controller reuses them. This defeats undelete
   tools, not a laboratory. The dialog says so.
5. **Deleted entries stay in the file until you compact.** They are encrypted and
   unreachable, but present.
6. **Vault size leaks roughly how much data you have.** There is no padding.
7. **Timestamps are seconds, files only.** Modification times are stored to
   whole seconds and restored on export. Folder timestamps are not restored,
   because writing files into a folder updates it again anyway. Creation and
   access times are not kept, and neither are permissions, ownership or
   alternate data streams.
8. **Symbolic links are skipped, not stored.** Following them would let one link
   pull an entire filesystem into a vault; recreating them on export is a
   privilege problem on Windows. They are reported as skipped, never silently
   dropped.
9. **Trailing dots and spaces, and Windows device names, are refused.** `report.`
   and `report` are the same file on Windows, and `CON.txt` cannot be created
   there. Refusing at scan time beats failing halfway through a restore.
10. **A file changing mid-encryption aborts the vault.** VaultDrive will not store
   a file whose recorded size is a lie. Nothing is deleted; you try again.
11. **Compaction rewrites the whole container** and needs room for a second copy
    on the same volume.
12. **Locking in place needs room for both copies at once.** The container is
    written beside the plaintext it is encrypting, so the volume briefly holds
    both. VaultDrive checks free space first and refuses rather than running out
    with the originals half-deleted. Unlocking has the same requirement in
    reverse.
13. **A file another program holds open cannot be deleted** during an in-place
    lock. It is still encrypted into the container, but the plaintext copy stays
    on disk, and it is reported by name so you can close that program and lock
    again.
14. **macOS and Linux are untested.** The code is written for them and nothing in
    it is Windows-only, but no one has run it there.
15. **One vault open at a time.** The session holds a single unlocked vault.
16. **No key file or hardware token support.** Password only.

---

## Project structure

```
usb-encrypter/
├── src/                        React + TypeScript frontend
│   ├── components/             Icons, dialogs, password field, progress, drives
│   ├── pages/                  Home, MyVaults, CreateVault, OpenVault,
│   │                           VaultBrowser, Settings
│   ├── hooks/                  settings + theme, activity ping, progress events
│   ├── services/               api.ts (the only bridge to Rust), formatting
│   ├── types/                  shapes shared with the Rust commands
│   ├── styles/global.css       the whole visual language
│   └── App.tsx
│
├── src-tauri/
│   ├── src/
│   │   ├── main.rs             four lines
│   │   ├── lib.rs              app wiring, command registry, auto-lock thread
│   │   ├── error.rs            user-facing errors; no crypto detail escapes
│   │   ├── logging.rs          structured logs, redaction policy
│   │   ├── password.rs         strength estimation
│   │   ├── settings.rs         preferences and recent vaults
│   │   ├── crypto/             kdf, keys, aead, random
│   │   ├── vault/              format, index, container, session, progress
│   │   ├── filesystem/         atomic writes, scanning, drives, secure delete
│   │   └── commands/           the Tauri command surface
│   ├── tests/                  integration and security suites
│   ├── capabilities/           the window's permission set
│   ├── Cargo.toml
│   └── tauri.conf.json
│
├── portable/README.txt         drop this on the USB drive beside the .exe
├── tests/                      pointer to the Rust suites
├── package.json
└── README.md
```

Everything security-sensitive is in Rust. The frontend holds ids and names, and
asks.
