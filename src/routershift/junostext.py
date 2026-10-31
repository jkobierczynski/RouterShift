# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos configuration text: the curly-brace hierarchy or 'set' lines read into statements (one word list per leaf,
as a set command names it), and statements written back as a hierarchy."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(#.*)|([{};\[\]])|([^\s{};\[\]"]+)')


@dataclass
class Statement:
    line: int
    words: List[str]
    inactive: bool = False

    @property
    def text(self) -> str:
        return "set " + " ".join(quote(w) for w in self.words)


def quote(word: str) -> str:
    return f'"{word}"' if not word or re.search(r'[\s;{}\[\]#"]', word) else word


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return "\n".join("" if line.lstrip().startswith("#") else line for line in text.splitlines())


def read(text: str) -> List[Statement]:
    """The statements of a configuration in either form."""
    lines = text.splitlines()
    if any(line.startswith(("set ", "deactivate ", "delete ")) for line in lines):
        out: List[Statement] = []
        for n, line in enumerate(lines, 1):
            words = _words(line)
            if not words:
                continue
            if words[0] == "set":
                out.append(Statement(n, words[1:]))
            else:
                out.append(Statement(n, words, inactive=True))  # deactivate / delete: kept for the report
        return out
    return _hierarchy(_strip_comments(text))


def _words(line: str) -> List[str]:
    return [m.group(1) if m.group(1) is not None else m.group(3) or m.group(4) for m in _TOKEN.finditer(line)
            if m.group(2) is None]


def _hierarchy(text: str) -> List[Statement]:
    tokens: List[Tuple[int, str, bool]] = []  # line, token, quoted
    for n, line in enumerate(text.splitlines(), 1):
        for m in _TOKEN.finditer(line):
            if m.group(1) is not None:
                tokens.append((n, m.group(1), True))
            elif m.group(2) is None:  # not a comment
                tokens.append((n, m.group(3) or m.group(4), False))
    out: List[Statement] = []
    stack: List[Tuple[List[str], bool, int]] = []  # each open block: its words, inactive, statements before it
    words: List[str] = []
    first_line = 0
    in_list = False
    items: List[str] = []
    for n, token, quoted in tokens:
        if not quoted and token == "[":
            in_list, items = True, []
            continue
        if not quoted and token == "]":
            in_list = False
            continue
        if in_list:
            items.append(token)
            continue
        if not quoted and token in ("{", ";", "}"):
            path = [w for ws, _, _ in stack for w in ws]
            inactive = any(i for _, i, _ in stack)
            mine = words
            if mine and mine[0] in ("inactive:", "protect:"):
                inactive = inactive or mine[0] == "inactive:"
                mine = mine[1:]
            if token == "{":
                stack.append((mine, inactive, len(out)))
            elif token == ";":
                if items:
                    for item in items:
                        out.append(Statement(first_line, path + mine + [item], inactive))
                elif mine:
                    out.append(Statement(first_line, path + mine, inactive))
                items = []
            else:
                if stack:
                    block, block_inactive, before = stack.pop()
                    if len(out) == before:  # an empty block is a statement of its own
                        path = [w for ws, _, _ in stack for w in ws]
                        out.append(Statement(n, path + block, block_inactive))
            words = []
            continue
        if not words:
            first_line = n
        words.append(token)
    return out


# Statements that hold a list of values
LISTS = {"members", "vlan", "domain-search", "next-hop"}


@dataclass
class Tree:
    """Statements gathered into a hierarchy for writing: each key is the text of a statement or block header."""

    children: Dict[str, "Tree"] = field(default_factory=dict)

    def add(self, *path: str) -> None:
        node = self
        for part in path:
            node = node.children.setdefault(part, Tree())

    def render(self, indent: int = 0) -> List[str]:
        lines: List[str] = []
        pad = "    " * indent
        lists: Dict[str, List[str]] = {}  # leaves of a list statement, written together as "members [ A B ];"
        for key in self.children:
            word, _, value = key.partition(" ")
            if word in LISTS and value and not self.children[key].children:
                lists.setdefault(word, []).append(value)
        done = set()
        for key, child in self.children.items():
            word = key.partition(" ")[0]
            if word in lists and len(lists[word]) > 1 and not child.children:
                if word not in done:
                    lines.append(f"{pad}{word} [ {' '.join(lists[word])} ];")
                    done.add(word)
            elif child.children:
                lines.append(f"{pad}{key} {{")
                lines += child.render(indent + 1)
                lines.append(f"{pad}}}")
            else:
                lines.append(f"{pad}{key};")
        return lines
