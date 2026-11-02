# Contributing to RouterShift

Thank you for helping. RouterShift converts switch and router configurations between vendors and says, item by
item, how faithful the result is. Contributions of every size are welcome: a configuration line it does not read,
a syntax a release rejects, a new feature or a new platform.

## Reporting a problem

Open an issue with:

* the source and target platform, and the release of each where it matters;
* the smallest configuration snippet that shows the problem, **with secrets, addresses and names you care about
  replaced**;
* what RouterShift wrote, what you expected, and the error the device gave, if any.

Lines RouterShift does not understand are listed under "Not understood" in the report; quoting a few of them is
the quickest way to get them supported.

## Developing

[DEVELOPMENT.md](DEVELOPMENT.md) explains the setup, how the code is laid out, how to add a feature, a reader or a
writer, the tests and the CI, and how versions and releases work. In short:

```
pip install -e ".[dev]"
pytest -q
mypy
```

Both must pass on Python 3.9 and 3.13, and the branch ruleset needs the `build and test` check to be green before a
pull request can merge. RouterShift has no runtime dependencies, and should stay that way: use the standard library
only.

## Ground rules

* **Never guess.** When a target cannot express something, write the nearest equivalent and say what changed
  (`Severity.APPROX`), or leave it out and say why (`report.skip(...)` or `Severity.REVIEW`). A reader that does
  not understand a line puts it in `device.unparsed`, so it shows under "Not understood".
* **Secrets stay out of reports.** Findings must not quote passwords, keys or communities; `report.redact` masks
  the "Not understood" lines. When a secret is encrypted in a form the target cannot take, write `CHANGE-ME`
  (`aaa.PLACEHOLDER`) and add a finding.
* **Round trips must hold.** What a writer writes, its own platform's reader must read back with nothing
  unparsed. The tests check this for every sample.
* **Every pull request lists the syntax it could not verify** on a real device or in vendor documentation, under
  "Unverified syntax", so reviewers with the hardware can check it.

## Style

* Python 3.9 syntax, type hints everywhere (`mypy --strict` must pass), `from __future__ import annotations`.
* Lines up to 120 characters. Short functions; a comment says why, not what.
* Each source file starts with the licence header that the other files have.
* Report messages are full sentences in plain English, naming the platform and saying what to do.

## Pull requests

* Base each pull request on `main`, one feature or fix per pull request.
* Describe what changed, how you tested it, and the unverified syntax.
* Add a line under "Unreleased" in `CHANGELOG.md` when the change affects what RouterShift reads, writes or
  reports.
* By contributing you agree that your contribution is licensed under the GPL-3.0-or-later, the licence of the
  project.
