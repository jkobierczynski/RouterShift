# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reads an indented CLI configuration (IOS, EOS, NX-OS, AOS-CX) into a tree of lines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Node:
    line: int  # 1-based line number in the source
    text: str  # stripped
    children: List["Node"] = field(default_factory=list)

    @property
    def words(self) -> List[str]:
        return self.text.split()


@dataclass
class Banner:
    kind: str  # "motd", "login", "exec"
    line: int
    text: str


def _indent(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" "))


def _banner(lines: List[str], i: int) -> Tuple[Banner, int]:
    """The banner that starts on lines[i]; returns it and the index of the line after it.

    IOS: ``banner motd ^C`` (or any delimiter) up to the next delimiter, possibly on the same line.
    EOS: ``banner motd`` alone, then lines up to ``EOF``.
    """
    words = lines[i].split(None, 2)
    kind = words[1] if len(words) > 1 else "motd"
    rest = words[2] if len(words) > 2 else ""
    if not rest:  # EOS
        body: List[str] = []
        j = i + 1
        while j < len(lines) and lines[j].strip() != "EOF":
            body.append(lines[j])
            j += 1
        return Banner(kind, i + 1, "\n".join(body)), j + 1
    delim = "^C" if rest.startswith("^C") else rest[0]
    rest = rest[len(delim):]
    if delim in rest:
        return Banner(kind, i + 1, rest[: rest.index(delim)]), i + 1
    body = [rest] if rest else []
    j = i + 1
    while j < len(lines) and delim not in lines[j]:
        body.append(lines[j])
        j += 1
    if j < len(lines):
        tail = lines[j][: lines[j].index(delim)]
        if tail:
            body.append(tail)
    return Banner(kind, i + 1, "\n".join(body)), j + 1


def read(text: str, comment: str = "!", banner_word: str = "banner") -> Tuple[List[Node], List[Banner]]:
    """The top-level nodes of a configuration and its banners. Comments and blank lines are left out; a comment at
    the start of a line also ends the block before it (Comware separates blocks with ``#`` and indents global
    lines by one space)."""
    lines = text.replace("\r\n", "\n").replace("\t", " ").split("\n")
    roots: List[Node] = []
    banners: List[Banner] = []
    stack: List[Tuple[int, Node]] = []
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        stripped = raw.strip()
        if stripped.startswith(banner_word + " ") and _indent(raw) <= 1 and not (stack and stack[-1][0] < _indent(raw)):
            banner, i = _banner(lines, i)
            banners.append(banner)
            stack.clear()
            continue
        i += 1
        if not stripped or stripped.startswith(comment):
            if stripped and _indent(raw) == 0:
                stack.clear()
            continue
        node = Node(i, stripped)
        depth = _indent(raw)
        while stack and stack[-1][0] >= depth:
            stack.pop()
        if stack:
            stack[-1][1].children.append(node)
        else:
            roots.append(node)
        stack.append((depth, node))
    return roots, banners
