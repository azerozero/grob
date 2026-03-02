# How to Contribute

## Requirements

- Rust stable toolchain (edition 2021)
- `cargo-nextest` for running tests
- Sign the [Contributor License Agreement](../../CLA.md)

## Development workflow

1. Fork the repository and clone your fork
2. Create a branch from `develop` (not `main`)
3. Make your changes
4. Run the checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo test --doc
```

5. Open a pull request against `develop`

## Code style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Doc comments on all public items (see CLAUDE.md for conventions)
- Comments explain **why**, not what
- File size target: 200-500 lines. If a file exceeds 500 lines, check if it has a single responsibility.
- Feature flags: use `#[cfg(feature = "...")]` for optional features (dlp, oauth, tap, compliance)

## Testing

- Unit tests go in `#[cfg(test)] mod tests` inside the source file
- Integration tests go in `tests/`
- Snapshot tests use `insta`
- Benchmarks use `criterion` in `benches/`

```bash
cargo nextest run                     # All tests
cargo nextest run -E 'test(router)'   # Filter by name
cargo test --doc                      # Doc tests
```

## CI pipeline

Pull requests run:

| Job | What it checks |
|-----|---------------|
| `fmt` | Code formatting |
| `clippy` | Lints (Linux, macOS, Windows) |
| `test` | Tests with nextest (Linux, macOS, Windows) |
| `coverage` | Code coverage via cargo-llvm-cov |
| `audit` | Security advisories (cargo-audit) |
| `deny` | License and dependency policy (cargo-deny) |
| `feature-check` | Feature powerset compilation (cargo-hack) |
| `machete` | Unused dependencies |

## License

Grob is licensed under AGPL-3.0. By submitting a pull request, you agree to the [CLA](../../CLA.md), which grants A00 SASU the right to distribute your contributions under both AGPL-3.0 and the commercial license.
