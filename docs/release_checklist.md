# Release Checklist

Use this checklist for small repository releases so Git tags, GitHub release notes, and manifest versions stay synchronized.

Before changing repository visibility, complete the separate
[public release checklist](./public_release_checklist.md).

## Scope

- release from `main`
- keep the GitHub release tag as the canonical published version
- keep [pyproject.toml](../pyproject.toml) and [frontend/package.json](../frontend/package.json) aligned with the same version unless there is a deliberate reason not to

## Checklist

1. Confirm `main` is up to date and the working tree is clean.
2. Choose the next version tag, for example `v0.5.1` or `v0.6.0`.
3. Update the backend manifest version in [pyproject.toml](../pyproject.toml).
4. Update the frontend manifest version in [frontend/package.json](../frontend/package.json).
5. Commit the version-bump changes to `main` or merge them through the normal PR flow.
6. Verify the relevant checks are green:
   - `uv run ruff check .`
   - `UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q`
   - `PATH="$(pwd)/.venv/bin:$PATH" make policy-check`
   - `cd frontend && yarn lint && yarn test && yarn build`
7. Draft release notes that summarize the changes since the previous tag.
8. Create the GitHub release from `main` using the same version number as the manifests.
9. Verify the published result:
   - the Git tag exists
   - the GitHub release title matches the tag
   - the release notes describe the correct changes
   - [pyproject.toml](../pyproject.toml) and [frontend/package.json](../frontend/package.json) match the published version

## Suggested Notes Template

```text
Highlights

- [major user-visible change]
- [important reliability or correctness fix]
- [notable evaluation, policy, or remediation improvement]

Included Since [previous tag]

- [cluster of backend changes]
- [cluster of frontend changes]
- [cluster of test or workflow changes]
```

## Notes

- If a release is only documentation or metadata, a patch version is usually enough.
- If the release includes meaningful new features or workflow expansions, prefer a minor version bump.
- If manifests intentionally diverge from the Git tag, document that decision in the release notes.
- While the repository is private, update the static README release badge with each release.
