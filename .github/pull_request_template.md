## Summary

<!-- Describe the problem and the smallest change that solves it. -->

## Validation

<!-- Check each relevant item; mark non-applicable items as N/A with a short reason. -->

- [ ] `uv run ruff check .`
- [ ] `uv run python -m pytest -q`
- [ ] `PATH="$(pwd)/.venv/bin:$PATH" make policy-check`
- [ ] `cd frontend && yarn lint && yarn test && yarn build`

## Review Checklist

- [ ] Tests and documentation cover the changed behavior.
- [ ] API payload changes include matching Zod schema updates.
- [ ] Benchmark semantics and control mappings are unchanged, or the change is explicitly justified.
- [ ] Benchmark claim changes cite matching `outputs/` artifacts and preserve canonical evidence.
