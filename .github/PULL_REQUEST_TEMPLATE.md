## Summary

<!-- What changed and why? Keep it to a few sentences. -->

## Related issue

<!-- Closes #123, or "None". -->

## API or behavior changes

<!-- Note public API or behavior changes, and whether they are breaking. Write "None" if there are none. -->

## Validation

Commands actually run, with their outcome:

The feature runner excludes the `tinywallet-client` native integration tests,
which need the module staged by `scripts/test-e2e.sh`. Use the shell runner on
Unix and the PowerShell runner on Windows.

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo build --all-targets --all-features`
- [ ] `bash scripts/test-features.sh` (or `scripts/test-features.ps1` on Windows)

## Tests

<!-- What tests were added or updated? Note any deliberately untested edge case and why. -->

## Documentation

<!-- Link updated docs, or explain why documentation was not needed. -->

## Checklist

- [ ] The change is focused on one logical change
- [ ] No new `#[allow(...)]`, `#[ignore]`, or relaxed lints
- [ ] No secrets, tokens, or `.env` contents in the diff or the description
