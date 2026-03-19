## Baseline-Recovery Checklist

- [ ] `.venv/bin/ruff check .`
- [ ] `UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q`
- [ ] `cd frontend && yarn build`
- [ ] Detection smoke rerun written to `outputs/branch_baseline_recovery/detection_smoke/`
- [ ] Bounded remediation smoke rerun written to `outputs/branch_baseline_recovery/remediation_bounded_smoke/`
- [ ] If supported remediation medium was rerun, results are written to `outputs/branch_baseline_recovery/remediation_supported_medium/`
- [ ] Any benchmark claim changes cite matching `outputs/` artifacts and distinguish branch-local reruns from frozen historical baselines
