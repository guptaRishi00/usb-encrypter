# Tests

The test suites live in `src-tauri/`, because Cargo only discovers integration
tests inside the crate that they exercise.

| Location | Contents |
|---|---|
| `src-tauri/src/**/mod tests` | Unit tests, next to the code they cover |
| `src-tauri/tests/password_tests.rs` | Which passwords open a vault, and which do not |
| `src-tauri/tests/encryption_tests.rs` | Round trips: nesting, sizes, Unicode, large files, export |
| `src-tauri/tests/integrity_tests.rs` | Tampering, truncation, corruption, version and cipher mismatches |
| `src-tauri/tests/filesystem_tests.rs` | Removed drives, cancellation, read-only media, OS error mapping |
| `src-tauri/tests/security_tests.rs` | What must never appear in the vault file, the settings file or a log |
| `src-tauri/tests/browser_tests.rs` | The in-vault file browser and compaction |
| `src-tauri/tests/common/mod.rs` | Shared fixtures |

Run them all:

```bash
npm run test:rust
```

Or directly:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

The frontend has no unit tests; it is checked by `npm run typecheck` under
TypeScript's strict mode. Everything worth asserting about vault behaviour lives
in Rust, which is where the vault behaviour lives.
