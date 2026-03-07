# Agent Setup

## Repo Context Model

- `AGENTS.md` stays short and stable.
- `docs/project/` is the compact expert digest.
- `README.md` and `REPRODUCIBILITY.md` remain the user-facing operational documents.

## Local OpenCode Setup

Recommended local MCPs for this repository:

- `git_local_codegraph`
  - repository: this repo root
- `memory_local`
  - enabled

Keep broad `filesystem_local` optional. Use it only if needed for cross-workspace help.

## Refresh Rules

- After a major benchmark run, update only `docs/project/benchmark_latest.md`.
- After a capability or support-matrix change, update `docs/project/current_state.md`.
- After a new bounded limitation appears, update `docs/project/open_issues.md`.
