# Agent Setup

## Repo Context Model

- `AGENTS.md` stays short and stable.
- `.opencode/project/` is the compact expert digest.
- `README.md` and `REPRODUCIBILITY.md` remain the user-facing operational documents.

## Repo-Local OpenCode Setup

- `opencode.json` enables the project instructions layer and the `skill` tool.
- Project-local skills live under `.opencode/skills/`.
- Project-local agents live under `.opencode/agents/`.

## Local Machine Setup

Recommended local MCPs for this repository:

- `git_local_codegraph`
  - repository: this repo root
- `memory_local`
  - enabled

Keep broad `filesystem_local` optional. Use it only if needed for cross-workspace help.

## Refresh Rules

- After a major benchmark run, update only `.opencode/project/benchmark_latest.md`.
- After a capability or support-matrix change, update `.opencode/project/current_state.md`.
- After a new bounded limitation appears, update `.opencode/project/open_issues.md`.
