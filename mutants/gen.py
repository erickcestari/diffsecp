#!/usr/bin/env python3
"""Builds the mutant schemata: a copy of libsecp256k1 in which every mutation in
mutants.txt sits behind a run-time switch, plus mutants.h naming them for
src/fuzz.c. One build then holds every mutant, and the fuzz driver picks one per
run by setting diffsecp_mutant.

Fails unless each original expression appears exactly once in its function, so
an upstream change that moves a site breaks the build instead of silently
dropping the mutant. Writes only files whose content changes, so make rebuilds
only what did.

usage: gen.py SECP OUT"""

import os
import re
import sys

LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants.txt")
COPIED = ("src", "include", "contrib")

# DIFFSECP_MUTATE(k, o, m) is m while mutant k is on. With diffsecp_mutant
# negative no mutant is on, and it flags k wherever m would differ from o.
PRELUDE = """\
/* Mutant schemata written by diffsecp's mutants/gen.py. */
#ifndef DIFFSECP_MUTATE
extern int diffsecp_mutant;
extern unsigned char diffsecp_mutant_infected[];
#define DIFFSECP_MUTATE(k, o, m) (diffsecp_mutant == (k) ? (m) : \\
    (diffsecp_mutant < 0 && (o) != (m)) ? (diffsecp_mutant_infected[k] = 1, (o)) : (o))
#endif
"""


def fail(msg):
    sys.exit("mutants/gen.py: " + msg)


def parse(path):
    """Returns (file, function, anchor, original, mutated, line) per record,
    with anchor None when the record has none."""
    records, cur = [], None
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            if not line[0].isspace():
                fields = line.split()
                if len(fields) != 2:
                    fail("%s:%d: expected FILE FUNCTION" % (path, n))
                cur = fields + [n]
                records.append(cur)
            elif cur is None or len(cur) == 6:
                fail("%s:%d: expression outside a record" % (path, n))
            else:
                cur.insert(-1, line.strip())
    for r in records:
        if len(r) == 5:
            r.insert(2, None)
        if len(r) != 6:
            fail("%s:%d: a record needs an original and a mutated expression" % (path, r[-1]))
    if not records:
        fail("%s lists no mutants" % path)
    return [tuple(r) for r in records]


def body(text, function):
    """Returns the span of FUNCTION's body in text: from its definition line,
    which starts in column 0 and ends in "{", to the first line that is just "}"."""
    head = re.compile(r"^\w[^;\n]*\b%s\(.*\{$" % re.escape(function), re.M)
    heads = list(head.finditer(text))
    if len(heads) != 1:
        return None
    end = text.find("\n}\n", heads[0].end())
    return (heads[0].end(), end) if end >= 0 else None


def mutate(secp, records):
    """Returns {file: text} for every mutated file."""
    sites = {}
    for k, (path, function, anchor, original, mutated, line) in enumerate(records):
        where = "%s:%d" % (LIST, line)
        if path not in sites:
            try:
                with open(os.path.join(secp, path)) as f:
                    sites[path] = (f.read(), [])
            except OSError as e:
                fail("%s: %s" % (where, e))
        text, found = sites[path]
        span = body(text, function)
        if span is None:
            fail("%s: no single definition of %s in %s" % (where, function, path))
        if anchor is not None:
            anchors = [m.end() for m in re.finditer(re.escape(anchor), text[span[0]:span[1]])]
            if len(anchors) != 1:
                fail("%s: anchor %r appears %d times in %s" % (where, anchor, len(anchors), function))
            span = (span[0] + anchors[0], span[1])
        hits = [m.start() for m in re.finditer(re.escape(original), text[span[0]:span[1]])]
        if len(hits) != 1:
            fail("%s: %r appears %d times in %s%s" % (where, original, len(hits), function,
                                                      "" if anchor is None else " after its anchor"))
        found.append((span[0] + hits[0], len(original), "DIFFSECP_MUTATE(%d, (%s), (%s))" % (k, original, mutated)))

    out = {}
    for path, (text, found) in sites.items():
        # Rewrite from the end so earlier offsets stay valid.
        found.sort(reverse=True)
        for i in range(1, len(found)):
            if found[i][0] + found[i][1] > found[i - 1][0]:
                fail("mutations overlap in %s" % path)
        for start, length, replacement in found:
            text = text[:start] + replacement + text[start + length:]
        out[path] = PRELUDE + text
    return out


def write_if_changed(path, data):
    try:
        with open(path, "rb") as f:
            if f.read() == data:
                return
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def c_string(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__.rsplit("\n\n", 1)[1])
    secp, out = sys.argv[1:]
    records = parse(LIST)
    mutated = mutate(secp, records)

    for top in COPIED:
        for root, _, files in os.walk(os.path.join(secp, top)):
            for name in files:
                src = os.path.join(root, name)
                rel = os.path.relpath(src, secp)
                if rel in mutated:
                    data = mutated[rel].encode()
                else:
                    with open(src, "rb") as f:
                        data = f.read()
                write_if_changed(os.path.join(out, "secp", rel), data)

    names = ["%s:%s: %s -> %s" % (path, function, original, m) for path, function, _, original, m, _ in records]
    header = ("/* Generated by mutants/gen.py from mutants/mutants.txt. */\n"
              "#define DIFFSECP_MUTANT_DETECT (-1)\n"
              "#define DIFFSECP_MUTANT_COUNT %d\n"
              "#define DIFFSECP_MUTANT_NAMES { \\\n%s \\\n}\n"
              % (len(records), " \\\n".join("    %s," % c_string(n) for n in names)))
    write_if_changed(os.path.join(out, "mutants.h"), header.encode())


if __name__ == "__main__":
    main()
