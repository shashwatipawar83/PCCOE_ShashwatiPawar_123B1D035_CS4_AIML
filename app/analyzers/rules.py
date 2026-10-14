"""Internal coding-rule catalogue + deterministic checks (MISRA-oriented and security-focused).

Rule IDs are *internal* (ICR-xxx). `ref` cross-references MISRA C:2012 rule/directive numbers and CWE ids
for traceability only; it does not reproduce licensed standard text and is not a MISRA compliance claim.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

from .. import guard
from ..code import CC, Ctx, match_brace


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    ref: str
    description: str
    fix: str
    confidence: float


R = Rule
CATALOGUE = {r.id: r for r in [
    R("ICR-001", "Dynamic memory allocation", "medium", "misra", "MISRA C:2012 Dir 4.12 / Rule 21.3",
      "Heap allocation in ECU code risks fragmentation, non-deterministic timing and leaks.",
      "Use statically allocated buffers or a fixed-size memory pool with compile-time bounds.", 0.9),
    R("ICR-002", "Unsafe string/IO function", "high", "security", "CWE-120 / CWE-676 / MISRA C:2012 Rule 21.6",
      "Unbounded copy/format functions can overflow the destination buffer.",
      "Use bounded variants (snprintf, memcpy with a verified length, strlcpy-style helpers) and check destination size.", 0.9),
    R("ICR-003", "Use of goto", "low", "misra", "MISRA C:2012 Rule 15.1",
      "goto obscures control flow and hampers static analysis and review.",
      "Restructure with loops, early returns or a single cleanup block.", 0.9),
    R("ICR-004", "switch without default", "medium", "misra", "MISRA C:2012 Rule 16.4",
      "A switch with no default branch silently ignores unexpected values.",
      "Add a default branch that handles or reports unexpected values (and assert in debug builds).", 0.85),
    R("ICR-005", "Allocation result not checked", "high", "reliability", "CWE-476",
      "The pointer returned by an allocator is used without a NULL check.",
      "Test the result against NULL before use and define the failure behaviour (error code / safe state).", 0.75),
    R("ICR-006", "Assignment inside condition", "medium", "misra", "MISRA C:2012 Rule 13.4",
      "An assignment used as a truth value is very often a mistyped comparison.",
      "Use '==' for comparison, or perform the assignment in a separate statement.", 0.8),
    R("ICR-007", "Direct recursion", "medium", "misra", "MISRA C:2012 Rule 17.2",
      "Recursion makes worst-case stack usage unbounded, which is unacceptable on constrained ECUs.",
      "Rewrite iteratively or enforce and prove a maximum recursion depth.", 0.9),
    R("ICR-008", "Loop bound allows out-of-bounds array access", "high", "reliability", "CWE-193 / CWE-787",
      "The loop uses '<=' with the same bound as the array length, so the last iteration indexes one element past the end.",
      "Use '<' with the array length (or sizeof(arr)/sizeof(arr[0])) and validate externally supplied lengths.", 0.8),
    R("ICR-009", "Hard-coded credential or key", "critical", "security", "CWE-798",
      "Secrets embedded in firmware can be extracted and reused across vehicles.",
      "Load keys from the HSM/secure storage or provisioning flow; never commit key material to source control.", 0.7),
    R("ICR-010", "Weak random number generator", "medium", "security", "CWE-338",
      "rand() is predictable and unsuitable for seeds, nonces, challenges or keys.",
      "Use the HSM/TRNG-backed API or an approved CSPRNG for any security-relevant value.", 0.7),
    R("ICR-011", "Non-literal format string", "high", "security", "CWE-134",
      "Passing a variable as the format string lets data control the format and can leak or corrupt memory.",
      "Use a constant format string: printf(\"%s\", msg).", 0.85),
    R("ICR-012", "Resource opened but never closed", "medium", "reliability", "CWE-772",
      "fopen() without a matching fclose() in the same function leaks the handle on every call.",
      "Close the handle on all paths (single exit/cleanup block).", 0.7),
    R("ICR-013", "Unchecked numeric conversion", "low", "reliability", "CWE-190 / MISRA C:2012 Rule 21.7",
      "atoi/atol/atof give no error indication and have undefined behaviour on overflow.",
      "Use strtol/strtoul with end-pointer and errno checks, and range-validate the result.", 0.85),
    R("ICR-014", "High cyclomatic complexity", "low", "maintainability", "ISO 26262-6 Table 1 (complexity)",
      "Functions with many decision points are hard to review and to test exhaustively.",
      "Split the function or replace if-chains with table-driven logic.", 0.9),
    R("ICR-SEC1", "Possible prompt-injection text in source", "medium", "security", "internal",
      "Text addressed to an AI reviewer was found in the code base. It was ignored and removed from every model prompt.",
      "Review who added this text and remove it; treat the commit as suspicious.", 0.8),
    R("ICR-CMP", "Compiler diagnostic", "medium", "build", "compiler",
      "Reported by the compiler during the build.", "Fix the cause; do not silence the warning.", 0.9),
    R("ICR-SA", "Static-analysis tool finding", "medium", "static-analysis", "tool report",
      "Reported by an external static-analysis tool.", "Follow the tool message; confirm and fix or document a deviation.", 0.8),
    R("ICR-RT", "Runtime sanitizer / crash evidence", "high", "runtime", "sanitizer log",
      "Observed at runtime (sanitizer or crash log).", "Reproduce, fix the faulting access, add a regression test.", 0.85),
]}


def _mk(ctx: Ctx, rid: str, l1: int, l2: int | None = None, detail: str = "", conf: float | None = None,
        redact: bool = False, anchor: str | None = None):
    if ctx.suppressed(rid, l1):
        return None
    r, l2 = CATALOGUE[rid], l2 or l1
    f = ctx.func_at(l1)
    ev = ctx.snippet(l1, l2)
    if redact:
        ev = re.sub(r'"[^"\n]{4,}"', '"****"', ev)
    return {"rule": rid, "title": r.title + (f": {detail}" if detail else ""), "severity": r.severity,
            "category": r.category, "file": ctx.path, "function": f.name if f else None,
            "line_start": l1, "line_end": l2, "evidence": ev, "description": r.description,
            "suggestion": r.fix, "confidence": conf or r.confidence, "source": "static-rule",
            "reference": r.ref, "anchor": anchor or ctx.lines[l1 - 1].strip()}


_SIMPLE = [
    ("ICR-001", re.compile(r"\b(malloc|calloc|realloc|free)\s*\("), lambda m: m.group(1)),
    ("ICR-002", re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\("), lambda m: m.group(1)),
    ("ICR-003", re.compile(r"\bgoto\b"), lambda m: ""),
    ("ICR-006", re.compile(r"\b(?:if|while)\s*\(\s*[A-Za-z_][\w.\[\]>-]*\s*=(?!=)"), lambda m: ""),
    ("ICR-010", re.compile(r"\b(?:rand|srand)\s*\("), lambda m: ""),
    ("ICR-011", re.compile(r"\bprintf\s*\(\s*[A-Za-z_]\w*\s*\)|\bfprintf\s*\(\s*\w+\s*,\s*[A-Za-z_]\w*\s*\)"), lambda m: ""),
    ("ICR-013", re.compile(r"\b(atoi|atol|atof)\s*\("), lambda m: m.group(1)),
]
_ARR = re.compile(r"\b(?:u?int\d*_t|char|short|int|long|float|double|unsigned|signed|size_t|bool|\w+_t)\s+"
                  r"\**(\w+)\s*\[\s*(\w+)\s*\]\s*(?:;|=|,)")
_LOOP = re.compile(r"for\s*\(\s*(?:[\w\s*]+\s+)?(\w+)\s*=\s*[^;]*;\s*\1\s*<=\s*(\w+)\s*;")
_ALLOC = re.compile(r"\b(\w+)\s*=\s*(?:\([^()]*\)\s*)?(?:malloc|calloc|realloc)\s*\([^;]*\)\s*;")
_CRED = re.compile(r"\b(\w*(?:pass(?:word|wd)?|secret|token|apikey|api_key|privatekey|private_key|_key|key_|Key)\w*)"
                   r"\s*(?:\[[^\]]*\])?\s*=\s*\"", re.I)


def run_rules(ctx: Ctx) -> list[dict]:
    out: list[dict] = []
    add = lambda f: out.append(f) if f else None
    m_ = ctx.masked

    if ctx.is_c:
        for rid, rx, det in _SIMPLE:
            for m in rx.finditer(m_):
                add(_mk(ctx, rid, ctx.line(m.start()), detail=det(m)))

        for m in re.finditer(r"\bswitch\s*\(", m_):
            o = m_.find("{", m.end())
            if o > 0 and not re.search(r"\bdefault\s*:", m_[o:match_brace(m_, o)]):
                add(_mk(ctx, "ICR-004", ctx.line(m.start())))

        for m in _ALLOC.finditer(m_):
            v, tail = m.group(1), m_[m.end(): m.end() + 400]
            chk = (rf"\bif\s*\(\s*!?\s*{v}\b|\b{v}\s*(==|!=)\s*(NULL|0)\b|\b(NULL|0)\s*(==|!=)\s*{v}\b|"
                   rf"\bassert\s*\(\s*{v}\b")
            if not re.search(chk, tail):
                add(_mk(ctx, "ICR-005", ctx.line(m.start()), detail=v))

        arrays = {n: s for n, s in _ARR.findall(m_)}
        for m in _LOOP.finditer(m_):
            idx, bound = m.groups()
            tail = m_[m.end(): m.end() + 800]
            for arr, size in arrays.items():
                if size == bound and re.search(rf"\b{arr}\s*\[\s*{idx}\s*\]", tail):
                    add(_mk(ctx, "ICR-008", ctx.line(m.start()), detail=f"{arr}[{size}] indexed up to {bound}"))

        for m in _CRED.finditer(m_):
            q = m.end() - 1
            end = ctx.src.find('"', q + 1)
            if end - q - 1 >= 4:
                add(_mk(ctx, "ICR-009", ctx.line(m.start()), redact=True, detail=m.group(1),
                        anchor=f"cred:{m.group(1)}"))

        for f in ctx.funcs:
            body = ctx.body(f)
            m = re.search(rf"\b{re.escape(f.name)}\s*\(", body[1:])
            if m:
                add(_mk(ctx, "ICR-007", ctx.line(f.body_off + 1 + m.start()), detail=f.name))
            if re.search(r"\bfopen\s*\(", body) and not re.search(r"\bfclose\s*\(", body):
                add(_mk(ctx, "ICR-012", ctx.line(f.body_off + re.search(r"\bfopen\s*\(", body).start()), detail=f.name))
            cc = 1 + len(CC.findall(body))
            if cc > 10:
                add(_mk(ctx, "ICR-014", f.start, f.end, detail=f"{f.name} (cyclomatic complexity ≈ {cc})",
                        anchor=f"cc:{f.name}"))

    for n, _line in guard.scan(ctx.src):
        add(_mk(ctx, "ICR-SEC1", n, anchor="injection"))

    seen, uniq = set(), []
    for f in out:
        k = (f["rule"], f["line_start"], f["title"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return sorted(uniq, key=lambda f: f["line_start"])
