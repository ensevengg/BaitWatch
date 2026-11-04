# Results

These are the sources for the results table in the [README](../README.md).

## Our attack repos

- **Date:** 2026-11-04
- **Build:** commit `b5bfaf5`
- **Method:** each repo in [`attacks/repos/`](../attacks/repos) went through the installed hook, using the fine-tuned detector and the Muse Spark judge.

| Group | Repos | Result |
|---|---|---|
| Attack repos | 17 | 15 block, 2 ask |
| Harmless twins | 5 | 5 allow |

The two attack repos that got "ask" are `git-hook-installer` and `runtime-eval-chain`. Both still stop the agent until a person decides.

## Popular repos

- **Date:** 2026-11-04
- **Build:** the hook as it was before the changes merged in PR #22 later that day
- **Method:** 100 popular GitHub repos, chosen across star and size bands, none used before. Each went through the hook once.
- **Result:** 77 allow, 17 ask, 6 block

This test measures false alarms, because these are ordinary projects and not planted attacks. About 10 of the 23 stops came from a scan running out of time.

The test harness and per-repo results are not in this repo.

## Detector alone

The figures of 128 of 150 held-out attacks and 39 of 7,989 held-out harmless files come from the [model card](../read/docs/MODEL_CARD.md), which also lists known misses.
