# gs-securing-web

Source:
- [spring-guides/gs-securing-web](https://github.com/spring-guides/gs-securing-web)

## Acquisition

```bash
git clone --depth 1 https://github.com/spring-guides/gs-securing-web.git /tmp/gs-securing-web
cd /tmp/gs-securing-web
zip -qr /tmp/gs-securing-web.zip . -x ".git/*" "target/*"
```

## Expected Validation Focus

- lighter JVM service validation target
- confirms the framework transfers to a smaller project without relying on OWASP Benchmark structure
- useful for checking policy evaluation and explanation on a compact Spring Security codebase
- remediation should only be attempted if a supported category appears naturally

## Suggested Output Folder

- `outputs/case_study_gs_securing_web/`

## Notes

- Use this case study to complement PetClinic with a smaller repository and faster ingest cycle.
- This target is expected to be more about workflow validation than remediation coverage.
