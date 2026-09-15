## Summary

<!-- Describe the problem and the smallest change that solves it. -->

## Validation

<!-- Check relevant gates; mark non-applicable items as N/A with a short reason. -->

- [ ] `uv run ruff check .`
- [ ] `uv run python -m pytest -q`
- [ ] `PATH="$(pwd)/.venv/bin:$PATH" make policy-check`
- [ ] `make opengrep-test`
- [ ] `make docs-check`
- [ ] `cd frontend && yarn lint && yarn test && yarn build`
- [ ] `make java-parser-build` when the JDT adapter changes

## Review Checklist

- [ ] Tests and documentation cover changed behavior.
- [ ] API payload changes include matching Zod schema updates.
- [ ] Benchmark mappings, engine ownership, remediation tiers, and evidence are unchanged or explicitly justified.
- [ ] Research claim changes cite matching `outputs/` artifacts and preserve provenance.
