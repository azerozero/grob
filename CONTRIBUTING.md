# Contributing to Grob

Thanks for your interest in contributing. Grob is a multi-provider LLM
routing proxy written in Rust. This document describes the workflow,
conventions, and checks you need to pass before a pull request can be
merged.

For the in-depth technical guide see
[`docs/how-to/contribute.md`](docs/how-to/contribute.md). This file is the
top-level summary and the authoritative reference for branching, commit
style, and the review process.

## Code of conduct

By participating in this project you agree to abide by the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Report unacceptable behaviour to `conduct@a00.fr`.

## License and CLA

Grob is licensed under AGPL-3.0. By submitting a pull request you agree
to the [Contributor License Agreement](CLA.md), which grants A00 SASU
the right to distribute your contributions under both AGPL-3.0 and the
commercial licence.

## Getting started

### Prerequisites

- Rust stable toolchain (edition 2021)
- `cargo-nextest` for running the test suite
- [`prek`](https://github.com/j178/prek) for the pre-commit hooks

Install `prek` with one of:

```bash
brew install j178/tap/prek
cargo install prek
curl -fsSL https://prek.sh | sh
```

### First-time setup

```bash
git clone https://github.com/azerozero/grob
cd grob
prek install
cargo build
cargo nextest run
```

`prek install` wires the pre-commit hooks that run `cargo fmt`, `clippy`,
and `gitleaks` on every commit, and heavier checks (tests, audit) on
push. The configuration lives in `prek.toml`.

## Branching model

Grob follows GitHub Flow.

```
feat/* or fix/* ──► main ──► release-plz PR ──► tag v* ──► release
```

- `main` is the only long-lived branch. Never commit or push directly to
  it — it is protected by a GitHub ruleset that requires a reviewed PR.
- Create feature branches from `main` named `feat/<topic>` or
  `fix/<topic>`. Open the PR against `main`.
- When two PRs modify overlapping files, base the second branch on the
  first (`git checkout -b feat/B feat/A`) so the second PR does not need
  a merge when the first lands.
- Enable auto-merge on every PR as soon as CI starts:
  `gh pr merge <num> --auto --merge`. Do not wait for CI to merge by
  hand.
- Releases are handled by release-plz. It watches `main`, opens a
  Release PR with a version bump and changelog entries, and creates the
  `v*` tag when that PR merges.

## Conventional Commits

Every commit message must follow
[Conventional Commits v1.0.0](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

Allowed types and what they trigger:

| Type | release-plz bump | When to use |
|------|------------------|-------------|
| `feat` | minor | New user-visible capability |
| `fix` | patch | Bug fix |
| `refactor` | patch | Internal restructuring, no user impact |
| `perf` | patch | Performance improvement |
| `docs` | none | Documentation only |
| `test` | none | Test-only changes |
| `chore` | none | Build, tooling, dependency bumps |
| `style` | none | Formatting |

Only `feat`, `fix`, `refactor`, and `perf` trigger a version bump.
Breaking changes get a `!` after the type or a `BREAKING CHANGE:`
footer and are bumped to the next major version.

Scopes are optional but encouraged when the change is localised (for
example `feat(routing):` or `fix(openai-compat):`).

## Pull request process

1. Open the PR against `main` with a clear title in Conventional Commit
   style (the squash-merge will use this title).
2. Fill in the PR description. Describe the problem, the chosen
   approach, the blast radius, and any follow-up work.
3. Enable auto-merge: `gh pr merge <num> --auto --merge`.
4. Wait for the required CI checks to pass. Do not force-push after
   review has started unless you need to rebase onto `main`.
5. Respond to review comments in the PR thread. One approval from a
   maintainer is enough for merge.
6. The PR is squash-merged. The squash commit subject is the PR title,
   so keep it Conventional-Commits-compliant.

### What CI checks

Pull requests run the full pipeline defined in `.github/workflows/ci.yml`:

| Stage | What it checks |
|-------|----------------|
| Quality gates | `fmt`, `clippy`, `doc`, `actionlint` |
| Tests | Unit + integration on Ubuntu, macOS, Windows |
| Feature powerset | `cargo-hack` compiles every feature combination |
| Audit | `cargo-audit` + `cargo-deny` for advisories and licences |

Mutation testing (`cargo-mutants`) and cross-target builds run on merge
to `main`.

## Code style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- Doc comments on all public items. Grob enforces the doc-comment rules
  in [`CLAUDE.md`](CLAUDE.md) — third-person present tense, no
  `This function…`, standard section order
  (`# Errors`, `# Panics`, `# Safety`, `# Examples`).
- `//` comments explain **why**, not what. Tags are `TODO:`, `FIXME:`,
  `HACK:`, `NOTE:`, `SAFETY:` (capitalised, colon, sentence ending with
  a period).
- File size target: 200–500 lines. If a module exceeds 500 lines, check
  whether it has a single responsibility.
- Feature flags use `#[cfg(feature = "…")]`. Optional features include
  `dlp`, `oauth`, `tap`, `compliance`, and `harness`.
- No commented-out code. Delete it — git has the history.

## Testing

- Unit tests go in `#[cfg(test)] mod tests` inside the source file.
- Integration tests live under `tests/`.
- Snapshot tests use [`insta`](https://insta.rs/).
- Cucumber scenarios live under `tests/cucumber/features/` and must
  appear in `tests/cucumber/RTM.md` (requirements traceability matrix).
- Benchmarks use `criterion` in `benches/`.

Common test commands:

```bash
cargo nextest run                     # all tests
cargo nextest run -E 'test(router)'   # filter by test name
cargo test --doc                      # doc tests only
```

## Documentation

External documentation follows the [Diátaxis](https://diataxis.fr/)
framework. Each file belongs to exactly one category:

| Folder | Type | Question answered |
|--------|------|-------------------|
| `docs/tutorials/` | Tutorial | How do I learn this? |
| `docs/how-to/` | How-to | How do I solve X? |
| `docs/reference/` | Reference | What are the exact details? |
| `docs/explanation/` | Explanation | Why does it work this way? |
| `docs/decisions/` | ADR (MADR 4.0) | Why was this decision made? |

When the scope of a change involves a new architectural decision, add
an ADR in `docs/decisions/NNNN-short-title.md` using
`docs/decisions/0000-template.md`.

## Reporting bugs

File bugs at <https://github.com/azerozero/grob/issues/new>. Include
the grob version (`grob --version`), the invocation, and a reproduction
— ideally the shortest TOML config and the curl or SDK call that
triggers the problem. Redact API keys and OAuth tokens before pasting.

For security-sensitive issues follow [`SECURITY.md`](SECURITY.md) —
do not open a public issue.

## Getting help

- Questions about the architecture: read `CLAUDE.md` for a module-level
  map.
- Questions about the roadmap: open a discussion in the GitHub
  Discussions tab.
- Commercial support: <mailto:hello@a00.fr>.
