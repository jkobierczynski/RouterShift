# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exceptions raised by routershift."""

from __future__ import annotations


class RoutershiftError(Exception):
    """Base class: a problem the user can act on."""


class ParseError(RoutershiftError):
    """The input configuration could not be read."""


class EmitError(RoutershiftError):
    """The device cannot be written for the chosen target."""
