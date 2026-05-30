## Summary

What does this PR change, and why?

## Testing

- [ ] `pip install -e ".[dev]"`
- [ ] `python -m pytest -v`
- [ ] `python -m picodome sandbox echo ci-test`

## Checklist

- [ ] Determinism preserved (no timestamps/random IDs in output)
- [ ] Platform behavior considered (Linux seccomp, macOS seatbelt, subprocess fallback)
- [ ] No secrets added; logs/output redacted
- [ ] Docs updated where appropriate

## Notes for reviewers

Anything risky or tricky?
