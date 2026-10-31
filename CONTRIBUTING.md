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

## Development setup

```
git clone https://github.com/jkobierczynski/RouterShift.git
cd RouterShift
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
mypy
```

Both `pytest` and `mypy` (strict) must pass; the CI runs them on Python 3.9 and 3.13, and the branch ruleset needs
the `build and test` check to be green before a pull request can merge.

RouterShift has no runtime dependencies, and should stay that way: use the standard library only.

## How the code is laid out

```
src/routershift/
  model.py          the vendor-neutral model: dataclasses for every feature
  parsers/          one reader per platform: text -> model.Device
  emitters/         one writer per platform: model.Device -> text, plus findings in the report
  report.py         the fidelity report (items, findings, statuses, secret masking)
  names.py          canonical interface names and the port mapper
  convert.py        the platform list and the convert() entry point
  cli.py            the command line
  <feature>.py      helpers each feature shares between readers and writers (acl.py, ospf.py, bgp.py, fhrp.py,
                    vxlan.py, ...), including the "not supported" reports
  partial.py        the "not written for <platform> yet" reports of writers that cover part of the model
  confparse.py      the indented-block parser the Cisco-style readers share
  junostext.py      Junos braces and set lines, read and written
tests/
  data/             one sample configuration per platform
  test_all_pairs.py converts every full sample to every full platform and checks that features survive
  test_<feature>.py one file per feature
```

A conversion is always: read into the model, map the ports, write, report. Readers never know about targets and
writers never know about sources, so each new reader or writer works with all the others.

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

## Adding a feature

1. **Model.** Add fields or a dataclass in `model.py`, with a comment on the meaning and the default. Prefer the
   meaning over any one vendor's spelling.
2. **Helper.** If more than one platform needs the same logic (labels, defaults, conversions, the "unsupported"
   report), put it in a `<feature>.py` module.
3. **Readers.** Teach each reader the platform's syntax. Anything it cannot place goes to `unparsed`.
4. **Writers.** Write the feature for each platform that has it; report it on the others. For Junos and NX-OS,
   either write it or make sure `partial.py` lists it.
5. **Report kind.** Use an existing kind (`system`, `interface`, `ospf`, ...); a new area needs an entry in
   `report._KIND_TITLES`.
6. **Samples and tests.** Add the feature to the samples in `tests/data/` so `test_all_pairs.py` converts it
   everywhere, extend the all-pairs checks if the feature must survive, and add a `tests/test_<feature>.py` with
   the details per platform.
7. **Docs.** Add a row to the README status paragraph and a section to `docs/SCOPE.md`, including what each
   platform does differently.

## Adding a platform

1. Pick a key (`ios`, `junos`, ...) and add it to `convert.PLATFORMS`, `parsers.PARSERS` and `emitters.EMITTERS`.
2. Teach `names.PortMapper` the platform's port names (`_default_physical`, `_default_logical`) and the reader
   how to turn them into canonical names.
3. Write the reader. Start with system settings, VLANs, interfaces, addresses and static routes; put everything
   else in `unparsed`.
4. Write the writer with the same core. Use `partial.port` and `partial.device` so every feature not written yet
   is reported.
5. Add a sample to `tests/data/` and a `tests/test_<platform>.py` that reads the sample, round-trips it, converts
   every other sample to it and it to every other platform.
6. Document the platform's habits under its own heading in `docs/SCOPE.md`.

## Style

* Python 3.9 syntax, type hints everywhere (`mypy --strict` must pass), `from __future__ import annotations`.
* Lines up to 120 characters. Short functions; a comment says why, not what.
* Each source file starts with the licence header that the other files have.
* Report messages are full sentences in plain English, naming the platform and saying what to do.

## Pull requests

* Base each pull request on `main`, one feature or fix per pull request.
* Describe what changed, how you tested it, and the unverified syntax.
* By contributing you agree that your contribution is licensed under the GPL-3.0-or-later, the licence of the
  project.
