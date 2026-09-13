# Public Release Checklist

Use this gate once, immediately before changing the repository from private to public. Routine tagged releases should continue to use [release_checklist.md](./release_checklist.md).

## 1. Scope and Licensing

- [ ] Confirm that the root MIT license covers all original CodeGraph source
      intended for publication.
- [ ] Review [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and verify that
      every retained corpus-derived artifact has the required attribution and
      license treatment.
- [ ] Decide whether all tracked thesis evidence and generated indexes should
      be distributed publicly.
- [ ] Obtain legal or institutional review if distribution rights remain
      unclear; do not infer them from the root license.

## 2. History and Privacy

- [ ] Review tracked files and Git history for secrets, private datasets,
      personal paths, and email addresses.
- [ ] Run a secret scanner against the full history and review every finding.
- [ ] Explicitly accept or remove historical machine-specific paths in
      canonical evidence. Do not rewrite those artifacts casually: their
      checksums and provenance are part of the thesis record.
- [ ] If a history rewrite is necessary, treat it as a separate migration,
      coordinate with every clone, and regenerate affected provenance and
      checksums.

## 3. Release Metadata

- [ ] Choose the first public release version. Use `v1.0.0` only when the public
      API and artifact scope are intentionally stable.
- [ ] Align `pyproject.toml`, `frontend/package.json`, `CITATION.cff`, the Git
      tag, and the GitHub release.
- [ ] Confirm that README claims match the canonical outputs and the tagged
      source revision.
- [ ] Publish release notes that describe research scope, limitations,
      supported remediation tiers, and safe refusal behavior.

## 4. GitHub Controls

- [ ] Enable Private Vulnerability Reporting and verify the link in
      [SECURITY.md](../SECURITY.md).
- [ ] Protect `main` with required CI checks and pull-request review.
- [ ] Enable secret scanning, push protection, Dependabot alerts, and code
      scanning where available.
- [ ] Review repository topics, description, homepage, issue templates, and
      discussion settings.
- [ ] Confirm that automatic deletion of merged branches remains enabled.

## 5. Final Verification

- [ ] Run every command in [release_checklist.md](./release_checklist.md).
- [ ] Verify `outputs/canonical_manifest.sha256`.
- [ ] Review open issues, pull requests, Actions runs, releases, branches, and
      tags for stale or private material.
- [ ] Test the documented setup from a clean clone without local-only files.
- [ ] Change visibility only after every unresolved item above has an explicit
      owner or documented acceptance.
