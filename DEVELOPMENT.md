# Developing RouterShift

This guide is for people changing the code: how to set up, how the pieces fit, how to add a feature, a reader or a
writer, how the tests and the CI work, and how a release is made. [CONTRIBUTING.md](CONTRIBUTING.md) has the
ground rules every change follows, and how to report a problem.

RouterShift is a quick reference for how a configuration looks on another platform. It is not a migration tool:
it never talks to a device, and it does not plan cutovers. Keep changes inside that purpose.

## Setup

RouterShift needs Python 3.9 or later and has no runtime dependencies. Development needs pytest and mypy.

```
git clone https://github.com/jkobierczynski/RouterShift.git
cd RouterShift
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
mypy
routershift --version
```

The editable install (`-e`) puts the `routershift` command on the path and runs the code in `src/` directly, so a
change is live without reinstalling. `pytest` also finds the package without installing, through `pythonpath` in
`pyproject.toml`.

Try a conversion with one of the samples:

```
routershift convert tests/data/eos_leaf.cfg --from eos --to junos --report report.txt
routershift parse tests/data/ios_access.cfg --from ios      # the neutral model as JSON
routershift platforms
```

## Architecture

Every conversion is the same four steps, in `convert.convert()`:

```
  source text ──reader──▶ model.Device ──port map──▶ writer ──▶ target text
                                                       │
                                                       └──────▶ report.Report (gaps.py adds the last checks)
```

1. **Read.** `parsers.PARSERS[source]` turns the text into a `model.Device`. A line the reader cannot place goes
   to `device.unparsed`, so it ends up in the report under "Not understood" (or under "Recognised, not converted"
   when `known.py` knows what it is).
2. **Map the ports.** `names.PortMapper` maps each canonical interface name (`Ethernet1/0/1`, `Port-channel10`,
   `Vlan20`, ...) to the target's spelling. The user can override it with `--port-map`.
3. **Write.** `emitters.EMITTERS[target]` writes the device and records, per item, whether it converted exactly,
   approximately, needs review or was skipped.
4. **Check.** `gaps.unwritten` and `gaps.partly_converted` make sure no item is called exact while part of it was
   not converted.

Readers never know the target and writers never know the source. That is what lets a new reader work with every
writer, and a new writer with every reader: seven platforms need seven readers and seven writers, not 42
converters. It is the same design as [FWShift](https://github.com/jkobierczynski/FWShift).

### Where things live

```
src/routershift/
  __init__.py       __version__, the one place the version is set
  cli.py            the command line (convert, roundtrip, parse, platforms, --version)
  convert.py        PLATFORMS and convert(): read, map, write, check
  model.py          the vendor-neutral model: one dataclass per feature, with meaning and defaults
  roundtrip.py      round trips: convert there and back, compare the two models setting by setting
  report.py         the fidelity report: items, findings, severities, secret masking, text and JSON output
  names.py          canonical interface names and the port mapper
  gaps.py           the checks that run after every writer
  known.py          lines recognised but not converted, with the reason
  partial.py        "not written for <platform> yet" reports for writers that cover part of the model
  confparse.py      the indented-block parser the Cisco-style readers share (IOS, EOS, NX-OS, IOS-XR, AOS-CX)
  junostext.py      Junos braces and set lines, read and written
  parsers/          one reader per platform: text -> model.Device
                    (ioslike.py serves IOS, EOS and NX-OS)
  emitters/         one writer per platform: model.Device -> text and report findings
                    (ioslike.py serves IOS and EOS)
  <feature>.py      logic a feature shares between readers and writers: acl.py, bgp.py, ospf.py, fhrp.py,
                    vxlan.py, qos.py, ... including the "not supported on <platform>" reports
  <platform><area>.py
                    the larger platform-specific parts of a reader and writer, kept out of the main files:
                    junosrouting.py, aoscxsec.py, nxosfabric.py, iosxrpolicy.py, ...
tests/
  data/             sample configurations, at least one per platform
  helpers.py        sample() loads a file from data/
  test_all_pairs.py converts every sample to every platform and checks that the features survive
  test_roundtrip_baseline.py
                    every sample there and back through every platform, against data/roundtrip_baseline.json
  test_<feature>.py and test_<platform>[_<area>].py
                    the details per feature and per platform
docs/
  MANUAL.md         how to use RouterShift
  SCOPE.md          what converts, per area and per platform
```

### The report

The report is the product as much as the configuration is. Each item (`report.item(kind, name)`) gets findings with
a severity:

| Severity | Item status | Use it when |
|---|---|---|
| `INFO` | exact | the target says the same thing, perhaps in other words |
| `APPROX` | approximated | the nearest construct was written; the message says what differs |
| `REVIEW` | needs-review | something was left out or must be checked by a person |
| `report.skip(...)` | skipped | the item was not written at all; the message says why |

Findings never quote secrets; write `CHANGE-ME` (`aaa.PLACEHOLDER`) where an encrypted secret cannot be carried
over, and say so.

## Adding a feature

1. **Model.** Add fields or a dataclass in `model.py`, with a comment on the meaning and the default. Model the
   meaning, not one vendor's spelling.
2. **Shared logic.** If more than one platform needs the same logic (labels, defaults, unit conversions, the
   "unsupported" report), put it in a `<feature>.py` module.
3. **Readers.** Teach each reader the syntax. Anything it cannot place still goes to `device.unparsed`.
4. **Writers.** Write the feature on each platform that has it, and report it on the others. A writer that covers
   part of the model must list the feature in `partial.py` until it writes it.
5. **Report kind.** Use an existing kind (`system`, `interface`, `ospf`, ...); a new area needs an entry in
   `report._KIND_TITLES`.
6. **Tests.** Add the feature to the samples in `tests/data/` so `test_all_pairs.py` converts it everywhere,
   extend the all-pairs checks if the feature must survive every conversion, and add `tests/test_<feature>.py`
   with the details per platform.
7. **Docs and changelog.** Add the feature to the README status paragraph, a section to `docs/SCOPE.md` with what
   each platform does differently, and a line under "Unreleased" in `CHANGELOG.md`.

## Adding a reader (parser)

1. Add the platform key and title to `convert.PLATFORMS`.
2. Write `parsers/<platform>.py` with `parse(text: str) -> Device`, and register it in `parsers.PARSERS`. If the
   syntax is a Cisco-style indented CLI, build on `confparse.py`; if it is a close relative of IOS, consider a
   flavour of `parsers/ioslike.py` instead, as EOS and NX-OS are.
3. Turn the platform's port names into canonical names (see the `model.py` docstring) and keep the original in
   `source_name`.
4. Start with system settings, VLANs, interfaces, addresses and static routes. Everything else goes to
   `device.unparsed` until it is read; add recognised-but-unconverted blocks to `known.py`.
5. Add a sample to `tests/data/` and a `tests/test_<platform>.py` that reads it and converts it to every platform.

## Adding a writer (emitter)

1. Write `emitters/<platform>.py` with `emit(device: Device, ports: PortMapper, report: Report) -> str`, and
   register it in `emitters.EMITTERS`.
2. Teach `names.PortMapper` the platform's port names (`_default_physical`, `_default_logical`).
3. Write the same core as above first. Call `partial.port` and `partial.device` so every feature not written yet
   is reported rather than dropped.
4. The round trip must hold: what the writer writes, its own platform's reader must read back with nothing in
   `unparsed`. Add the platform to the round-trip and all-pairs tests.
5. Document the platform's habits under its own heading in `docs/SCOPE.md`.

A platform needs both a reader and a writer before it is listed in `PLATFORMS`, because the CLI offers every key in
both directions and the tests check round trips.

## Tests

```
pytest -q                       # everything, about a minute
pytest tests/test_bgp.py -q     # one file
pytest -k junos -q              # by name
mypy                            # strict type check of src/routershift
```

* `test_all_pairs.py` is the safety net: every sample to every platform, with checks that VLANs, addresses,
  routing and the other core features survive. A change that breaks a pair someone did not think of shows here.
* Round trips (write a platform, read it back, compare the model) catch writers and readers that disagree.
* `test_roundtrip_baseline.py` takes every sample to every other platform and back with `roundtrip.round_trip`
  and compares what is lost, changed or not read back with `tests/data/roundtrip_baseline.json`. A setting that
  starts to get lost fails the test; so does one that stops getting lost, until the baseline is written again with
  `python tests/test_roundtrip_baseline.py`. Commit the new baseline with the change: its diff shows the reviewer
  what now comes back, or what is now lost on purpose.
* Feature and platform tests check exact output lines. When a vendor spelling is a guess, say so in the pull
  request under "Unverified syntax", not only in the test.
* `test_version.py` checks that the version is valid and has a changelog entry.

## Continuous integration

`.github/workflows/test.yml` runs on every pull request and every push to `main`. It installs the package with the
dev extras and runs `pytest -q` and `mypy` on Python 3.9 (the oldest supported) and 3.13 (the newest).

The branch ruleset on `main` requires one check, named exactly **`build and test`**. It is the summary job
`build-and-test` in `test.yml`, which passes only when every Python version passed. If you change the workflow,
keep that job and its name, or no pull request can merge.

## Versions and releases

### Version numbers

The first release, 0.1.0, is tagged `v0.1.0` in git. Everything merged since is listed under "Unreleased" in
`CHANGELOG.md` and goes into the next release.

RouterShift follows [semantic versioning](https://semver.org), `MAJOR.MINOR.PATCH`. The version is set in exactly
one place, `__version__` in `src/routershift/__init__.py`. `pyproject.toml` reads it from there
(`dynamic = ["version"]`), `routershift --version` prints it, the report names it, and the release workflow refuses
a tag that does not match it. Never write the version anywhere else.

While RouterShift is below 1.0, the public interface is still settling:

* **MINOR** (0.2.0 → 0.3.0) for new platforms, new features, and changes to the command line, the JSON report or
  the model that can break a script relying on them.
* **PATCH** (0.2.0 → 0.2.1) for fixes: a line read wrongly, a syntax a device rejects, a wrong report status.

From 1.0 on, the command line, the JSON report format and the `routershift.convert` functions are the public
interface, and a change that breaks them needs a new MAJOR version. The generated configuration text is not an
interface: it may change in any release to be more faithful.

### Changelog

Every pull request that changes what RouterShift reads, writes or reports adds a line under "Unreleased" in
`CHANGELOG.md`, written for a user: what they can now convert, or what was wrong before. Docs, tests and refactors
need no line.

### Making a release

1. Pick the number from the changes under "Unreleased", using the rules above.
2. In one pull request: set `__version__`, rename "Unreleased" in `CHANGELOG.md` to `X.Y.Z (YYYY-MM-DD)` and put a
   new empty "Unreleased" above it. Merge it once `build and test` is green.
3. Tag the merge commit on `main` and push the tag:

   ```
   git switch main && git pull
   git tag -a vX.Y.Z -m "RouterShift X.Y.Z"
   git push origin vX.Y.Z
   ```

4. `.github/workflows/release.yml` runs on the tag: it runs the tests and mypy, checks the tag matches
   `__version__`, builds the wheel and sdist, and publishes them to PyPI through trusted publishing (no token in the
   repository). It needs a one-time setup on pypi.org (a trusted publisher for `routershift`, workflow
   `release.yml`, environment `pypi`) and a `pypi` environment in the GitHub repository settings.
5. Create a GitHub release from the tag (Releases → Draft a new release → choose the tag) and paste the changelog
   section as its notes.

A mistake in a published release is fixed with a new PATCH release, never by moving or reusing a tag: PyPI does not
accept the same version twice.
