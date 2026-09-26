# AGENTS.md

NEVER USE em dash(—) in *.md files, comments, commits, and RR description - USE hyphen(-) instead.

NEVER put spaces around `/` in prose (write `stop/purge`, not `stop / purge`). Paths and code are unchanged.

NEVER mention `cap-`/`CAP-` issue-tracker IDs in the codebase or docs - describe the follow-up work instead (e.g. `G-14 evidence follow-up`, not the tracker ID).

## Git Conventions

### Branch naming

ALWAYS use the following prefixes for branch names:

- `feat/` - New features (e.g., `feat/add-user-dashboard`)
- `fix/` - Bug fixes (e.g., `fix/api-key-validation`)
- `docs/` - Documentation updates (e.g., `docs/api-reference`)
- `refactor/` - Code refactoring (e.g., `refactor/auth-module`)
- `chore/` - Maintenance tasks (e.g., `chore/update-deps`)

### Pull request titles

Follow the same format as commit messages, but in title case:

```bash
<Type>(<Scope>): <Description>
```

Examples:

- `feat(auth): add API key rotation`
- `fix(api): resolve rate limiting bug`
- `docs(api): document POST /v1/sandboxes endpoint`

### Commit messages

Follow conventional commits:

```bash
<type>(<scope>): <description>

[optional body]
[optional footer]
```

Examples:

- `feat(auth): add API key rotation`
- `fix(api): resolve rate limiting bug`
- `docs: update API documentation`

## Build & Test Commands
- Build: `cargo build`
- Test all: `cargo nextest run`
- Test single: `cargo nextest run <test_name>` or `cargo nextest run --test <file> <test_name>`
- Format: `cargo fmt --all`
- Lint fix: `./scripts/lint-fix.sh`
- Feature check: `cargo hack check --feature-powerset --no-dev-deps --depth 1`

## Code Style
ALWAYS use Rust 2024 edition

### General
- Imports: group std, external crates, then internal modules; use `crate::` for internal imports
- Cross-crate imports: use the exporting crate's root re-exports (`use pico_guest_protocol::GuestSession`), never deep module paths (`pico_guest_protocol::session::GuestSession`). Namespace modules for constants/proto groups (`pico_guest_protocol::framed`, `pico_guest_protocol::operational_v1`) are the exception. Public types added to a library crate MUST be re-exported from the crate root.
- Naming: snake_case for functions/variables, PascalCase for types, SCREAMING_SNAKE for constants
- Use `hashbrown::HashMap<K, V, FxBuildHasher>` (or similar) instead of `std::collections::HashMap` for hot-path maps where SipHash overhead matters and DoS resistance isn't required. Don't swap import paths without also swapping the hasher - plain `hashbrown::HashMap` with default hasher is no different from std.
- Use `parking_lot::{Mutex, RwLock}` instead of `std::sync::{Mutex, RwLock}` for synchronous/CPU-bound sections only. Never hold a `parking_lot` guard across an `.await` - use `tokio::sync::{Mutex, RwLock}` for state accessed inside async fns. Be aware `parking_lot` locks don't poison on panic.

### Borrowing & Ownership
- Prefer `&T` over `.clone()` unless ownership transfer is required
- Use `&str` over `String`, `&[T]` over `Vec<T>` in function parameters
- Small `Copy` types (≤24 bytes) can be passed by value

### Error Handling
- Return `Result<T, E>` for fallible operations; avoid `panic!` in production
- Never use `unwrap()`/`expect()` outside tests
- Use `thiserror` for library errors, `anyhow` for binaries only
- Prefer `?` operator over match chains for error propagation

### Performance
- Always benchmark with `--release` flag
- Run `cargo clippy -- -D clippy::perf` for performance hints
- Avoid cloning in loops; use `.iter()` instead of `.into_iter()` for Copy types
- Prefer iterators over manual loops; avoid intermediate `.collect()` calls
- Never use `std::thread::sleep` in async
- Avoid async fns that don't actually need to be async
- Use `-> impl Future` for async 'pass-through' functions
- Use the `futures` crate to allow more async fns to be rewritten as a 'pass-through' function
- When possible, refactor code to share await points
- Pass references to large variables instead of moving them in

### Security
- Don't use `openssl`/`openssl-sys` - use `boring`, `ring`, or `rustls` instead

### Linting
Run regularly: `cargo clippy --all-targets --all-features --locked -- -D warnings`

Key lints to watch:
- `redundant_clone` - unnecessary cloning
- `large_enum_variant` - oversized variants (consider boxing)
- `needless_collect` - premature collection

Use `#[expect(..., reason = "...")]` over `#[allow(...)]` with justification comment

### Documentation
- `//` comments explain *why* (safety, workarounds, design rationale)
- `///` doc comments explain *what* and *how* for public APIs
- Enable `#![deny(missing_docs)]` for libraries
- Always update README.md and ARCHITECTURE.md for significant changes to the codebase structure or functionality (e.g., module restructuring or new feature additions)

## Protocol Development
- When adding a new RPC to the host/guest protocol, run through the [misuse-resistance checklist](docs/robustness/misuse-resistance-checklist.md) and add at least one robustness test per misuse vector
- Protocol robustness tests live in `crates/pico-guest-protocol/tests/robustness.rs`
- Compatibility fixtures live in `crates/pico-guest-protocol/tests/compat_fixtures.rs`
