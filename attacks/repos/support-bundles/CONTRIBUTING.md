# Contributing to bundlekit

Thanks for taking the time to work on bundlekit. This document
describes the workflow the maintainers use, so a change can be
reviewed quickly and merged without follow-up questions.

## Before you start

- Search the issue tracker for an existing report.
- For a behaviour change, open an issue first and agree on the shape.
- Keep each pull request focused on one topic.


## Local workflow

```console
git switch -c feature/short-description
pip install -e '.[dev]'
pytest -q
```

Commit messages follow the conventional form: a type, a scope in
parentheses and a short imperative subject. The body explains why the
change is needed and what alternatives you considered.

```text
fix(render): keep permissions when copying assets

The copy step used write_bytes, which resets the mode. Use copy2 so
executable assets stay executable.
```

## Code style

- Formatting and linting are enforced by `ruff`.
- Prefer small functions with explicit arguments over shared state.
- Public functions need a docstring that states the contract.
- New behaviour needs a test that fails without the change.

## Issue triage

A new issue gets one of four labels during triage: `bug`, `feature`,
`question` or `docs`. The label decides who looks at it next, not how
important it is. A bug with a reproduction moves to the front of the
queue regardless of age.

A report is ready to work on when it states the version, the platform,
the expected result and the observed result. Ask for the missing piece
once, in one comment, and leave the issue open while you wait.

## Design proposals

A change that alters the public interface starts as a short proposal
in the issue tracker. The proposal states the problem, the shape of
the change, the alternatives considered and the migration path for an
existing user.

Proposals are cheap and code is not. A paragraph that settles the
shape of a change saves a review cycle on a branch that would have
been rewritten anyway.

## Testing tiers

Every change needs a test at the lowest tier that can catch the bug.

- A parsing or validation bug needs a unit test with the smallest
  input that reproduces it.
- A formatting bug needs a snapshot update plus a test that asserts the
  new line, so the snapshot cannot drift back.
- A pipeline bug needs an integration test, marked `integration`, that
  exercises the service adapter.

Tests must be deterministic. A test that depends on wall-clock time,
network access or the order of a directory listing will fail on
someone else's machine, and the failure will be blamed on their
change.

Run the fast suite before every commit and the full suite before
opening a pull request. CI runs both, but a red CI costs a review
cycle that a local run would have avoided.

## Documentation

Documentation lives next to the thing it describes. A new flag needs a
line in the usage section; a new error code needs a row in the table;
a changed default needs a note in the changelog.

Write for the reader who knows the problem and not the code. Lead with
what the command does, then how to call it, then why it is built this
way. An example that runs is worth a paragraph of explanation.

## Release notes

The changelog is grouped by kind: added, changed, fixed and removed.
Each entry is one sentence in the imperative, written for a user rather
than a contributor.

An entry that says `refactor renderer` tells a user nothing. An entry
that says `keep executable permissions when copying assets` tells them
whether they were affected.

## Security reports

Do not open a public issue for a suspected vulnerability. Send the
report to the maintainers privately with the version, the steps and
the impact. A fix is prepared on a private branch and released with a
note that names the affected versions.

## Dependencies

A new runtime dependency needs a sentence in the pull request that
says what it does, why the standard library is not enough and what the
package weighs. A development dependency needs only the first two.

Pin a lower bound that you tested and an upper bound on the major
version. An unpinned dependency turns a green build red when a
maintainer you have never met publishes a release.

Vendoring is allowed for a single small file with a permissive
licence. Put the licence text next to the file and record the version
in the module docstring, so the next upgrade starts from a known
point.

## Performance

A change that touches the loader or the renderer gets a timing note in
the pull request. Run the reference build three times and report the
median; a single run on a busy laptop is not evidence.

A regression of more than ten percent needs either a fix or a
sentence that explains why the trade is worth it. The summary already
prints the slowest templates, which is the first place to look.

## Deprecation

A removed flag is announced one minor release before it disappears.
The old flag keeps working, prints a warning that names the
replacement and appears in the changelog under `deprecated`.

The removal release deletes the flag, the warning and the test that
covered the warning. Leaving the warning behind is worse than leaving
the flag, because it trains users to ignore warnings.

## Maintainer duties

A maintainer does four things besides review: triage new issues,
keep the release branch green, cut releases on the agreed cadence and
answer a question when a contributor is stuck.

Review is a conversation about the change, not about the person. Say
what would make the change mergeable, and say it once. A comment that
only says `this is wrong` costs the contributor a round trip.

When two maintainers disagree about a design, the proposal decides.
If the proposal is silent, write the missing paragraph and ask again
in the issue rather than in the pull request.

## Backporting

A fix that affects a supported release is backported to the oldest
affected branch. The pull request names the branch and the release
note mentions the patch version.

Backports are cherry-picks, not rewrites. If a fix does not apply
cleanly, the branch has drifted too far and the release is either
supported with a targeted patch or retired.

## Community

Questions are welcome in the discussion forum. A question that gets
the same answer twice becomes a documentation change, because the
document was the thing that was missing.

A first-time contributor gets a review within a week. If nobody can
review it in that window, say so and give a date, rather than letting
the pull request sit in silence.

## Review

A reviewer checks four things:

1. Does the change do what the description says?
2. Is there a test that would have caught the old behaviour?
3. Does it keep the public interface stable, or is the break
   documented?
4. Is the diff small enough to read in one sitting?

Address review comments with new commits. The maintainer squashes the
branch on merge, so the history stays linear.

## Reporting a problem

Include the version, the platform, the configuration and the exact
command. A reproduction that starts from a clean checkout is worth
more than a long description.

## Code of conduct

Be direct about the work and generous with the person. Disagreement
about a design is expected; personal remarks are not.
