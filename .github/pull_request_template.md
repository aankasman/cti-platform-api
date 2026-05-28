<!--
Thanks for opening a PR. The fields below match how we review.
Keep the title in Conventional Commits style: `feat(scope): …`, `fix(scope): …`, `chore: …`, `docs: …`, `security(scope): …`, `refactor(scope): …`.
-->

## Summary

<!-- What does this PR do, in 2-4 sentences? Reviewer should be able to read just this and know whether to keep going. -->

## Why

<!-- The problem this solves. Link to issues, incidents, or related PRs. Not "I'm refactoring" — "this caused X bug" or "this unblocks Y feature." -->

Closes #

## Implementation notes

<!-- Anything non-obvious in the diff. Trade-offs you considered. Things you intentionally didn't do and why. -->

## Test plan

<!-- How the reviewer (and you) can confirm this works. Concrete commands, URLs, expected output. Not "I tested it locally." -->

- [ ] `pnpm --filter @rinjani/api exec tsc --noEmit` clean
- [ ] `pnpm test` passes (or N/A for docs-only)
- [ ] Manual: <!-- describe the manual flow you exercised, e.g. "POST /v1/iocs/... returned 201 with the expected body" -->

## Risk

<!-- What could break? Anything that needs a follow-up? Anything that requires coordinated deploy with the dashboard repo? -->

## Checklist

- [ ] PR title follows Conventional Commits
- [ ] Commits are scoped (no drive-by changes)
- [ ] Migrations are forward-only (new file, never edit existing) — N/A if no schema change
- [ ] No `.env` or secrets in the diff
- [ ] Docs / README / DEPLOY updated if behaviour changed
- [ ] Security: I've considered injection, auth bypass, and supply-chain risk for any new dependency

<!--
🤖 If this was assisted by Claude Code, leave the trailing line below intact.
-->
