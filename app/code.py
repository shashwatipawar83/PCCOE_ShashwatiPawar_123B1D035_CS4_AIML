"""Lightweight C/C++ source model: comment/string masking, function discovery, chunking, metrics."""
from __future__ import annotations
import re
from bisect import bisect_right
from dataclasses import dataclass

C_EXT = (".c", ".h", ".cpp", ".hpp", ".cc")
KEYWORDS = {"if", "for", "while", "switch", "else", "do", "return", "sizeof", "case", "defined",
            "int", "char", "void", "long", "short", "float", "double", "unsigned", "signed"}
FUNC_HDR = re.compile(r"([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:const\s*)?$", re.S)
CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
CC = re.compile(r"\b(?:if|for|while|case)\b|&&|\|\||\?")


def mask(src: str) -> str:
    """Blank out comments and string/char literal contents, preserving offsets and newlines."""
    out, i, n, state = [], 0, len(src), None
    while i < n:
        c, two = src[i], src[i:i + 2]
        if state is None:
            if two == "//":
                state = "line"; out.append("  "); i += 2
            elif two == "/*":
                state = "block"; out.append("  "); i += 2
            elif c == '"':
                state = "str"; out.append('"'); i += 1
            elif c == "'":
                state = "chr"; out.append("'"); i += 1
            else:
                out.append(c); i += 1
        elif state == "line":
            if c == "\n":
                state = None; out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if two == "*/":
                state = None; out.append("  "); i += 2
            else:
                out.append("\n" if c == "\n" else " "); i += 1
        else:
            q = '"' if state == "str" else "'"
            if c == "\\" and i + 1 < n:
                out.append(" "); out.append("\n" if src[i + 1] == "\n" else " "); i += 2
            elif c == q:
                state = None; out.append(q); i += 1
            else:
                out.append("\n" if c == "\n" else " "); i += 1
    return "".join(out)


def match_brace(masked: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(masked) - 1


@dataclass
class Func:
    name: str
    start: int      # 1-based line of the signature
    end: int        # 1-based line of closing brace
    body_off: int   # offset of '{'
    end_off: int    # offset of '}'


class Ctx:
    """Everything the analysers need to know about one source file."""

    def __init__(self, path: str, src: str):
        self.path, self.src = path, src
        self.masked = mask(src)
        self.lines = src.split("\n")
        self.starts = [0] + [m.end() for m in re.finditer("\n", src)]
        self.is_c = path.lower().endswith(C_EXT)
        self.funcs = self._find_functions() if self.is_c else []

    def line(self, off: int) -> int:
        return bisect_right(self.starts, off)

    def func_at(self, line: int):
        for f in self.funcs:
            if f.start <= line <= f.end:
                return f
        return None

    def body(self, f: Func) -> str:
        return self.masked[f.body_off:f.end_off + 1]

    def snippet(self, a: int, b: int, ctx: int = 1) -> str:
        lo, hi = max(1, a - ctx), min(len(self.lines), b + ctx)
        return "\n".join(f"{n:>4}: {self.lines[n - 1]}" for n in range(lo, hi + 1))

    def suppressed(self, rule: str, line: int) -> bool:
        for n in (line, line - 1):
            if 1 <= n <= len(self.lines) and re.search(rf"scr-ignore\s+{re.escape(rule)}\b", self.lines[n - 1]):
                return True
        return False

    def _find_functions(self):
        m_, funcs, depth, stmt, cur = self.masked, [], 0, 0, None
        for i, c in enumerate(m_):
            if c == "{":
                if depth == 0:
                    raw = m_[stmt:i]
                    hdr = re.sub(r"^[ \t]*#.*$", lambda m: " " * len(m.group()), raw, flags=re.M).rstrip()
                    m = FUNC_HDR.search(hdr)
                    cur = None
                    if m and m.group(1) not in KEYWORDS and "=" not in hdr:
                        cur = (m.group(1), self.line(stmt + m.start(1)), i)
                depth += 1
            elif c == "}":
                depth = max(depth - 1, 0)
                if depth == 0:
                    if cur:
                        funcs.append(Func(cur[0], cur[1], self.line(i), cur[2], i))
                        cur = None
                    stmt = i + 1
            elif c == ";" and depth == 0:
                stmt = i + 1
        return funcs

    # ---- derived information ------------------------------------------------
    def includes(self):
        return re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', self.src, re.M)

    def stats(self):
        names = {f.name for f in self.funcs}
        res = []
        for f in self.funcs:
            b = self.body(f)
            calls = [c for c in CALL.findall(b) if c not in KEYWORDS and c != f.name]
            res.append({
                "name": f.name, "start": f.start, "end": f.end, "loc": f.end - f.start + 1,
                "complexity": 1 + len(CC.findall(b)),
                "branches": len(re.findall(r"\bif\b|\belse\b", b)),
                "loops": len(re.findall(r"\b(?:for|while)\b", b)),
                "switches": len(re.findall(r"\bswitch\b", b)),
                "gotos": len(re.findall(r"\bgoto\b", b)),
                "returns": len(re.findall(r"\breturn\b", b)),
                "calls_internal": sorted({c for c in calls if c in names}),
                "calls_external": sorted({c for c in calls if c not in names}),
            })
        return res


def chunk_file(ctx: Ctx, max_chars: int = 3500):
    """Function-level chunks (plus one header chunk) for C; sliding windows otherwise."""
    chunks = []
    if ctx.funcs:
        inside = set()
        for f in ctx.funcs:
            inside.update(range(f.start, f.end + 1))
            text = "\n".join(ctx.lines[f.start - 1:f.end])[:max_chars]
            chunks.append({"text": text, "meta": {"path": ctx.path, "kind": "function", "name": f.name,
                                                  "start": f.start, "end": f.end}})
        outside = [(i + 1, l) for i, l in enumerate(ctx.lines) if i + 1 not in inside and l.strip()]
        if outside:
            chunks.append({"text": "\n".join(l for _, l in outside)[:max_chars],
                           "meta": {"path": ctx.path, "kind": "file-header", "name": ctx.path,
                                    "start": outside[0][0], "end": outside[-1][0]}})
    else:
        step, win = 50, 60
        for s in range(0, max(len(ctx.lines), 1), step):
            seg = ctx.lines[s:s + win]
            if any(x.strip() for x in seg):
                chunks.append({"text": "\n".join(seg)[:max_chars],
                               "meta": {"path": ctx.path, "kind": "window", "name": ctx.path,
                                        "start": s + 1, "end": s + len(seg)}})
    return chunks
