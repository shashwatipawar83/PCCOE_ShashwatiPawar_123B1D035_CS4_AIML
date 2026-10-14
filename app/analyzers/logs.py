"""Parsers for compiler output, cppcheck XML and sanitizer/crash logs."""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET

GCC = re.compile(r"^(?P<file>[^\s:][^:]*?):(?P<line>\d+):(?:\d+:)?\s*(?P<sev>warning|error):\s*(?P<msg>.*?)"
                 r"(?:\s*\[(?P<flag>-W[\w=+-]+)\])?\s*$")
HIGH_FLAGS = ("-Wstringop-overflow", "-Warray-bounds", "-Wformat-security", "-Wformat", "-Wuninitialized",
              "-Wmaybe-uninitialized", "-Wreturn-type", "-Wnonnull", "-Wint-conversion")


def parse_compiler(text: str):
    out = []
    for line in (text or "").splitlines():
        m = GCC.match(line.strip())
        if not m:
            continue
        flag = m.group("flag") or ""
        if m.group("sev") == "error" or flag.startswith(HIGH_FLAGS):
            sev = "high"
        elif flag.startswith("-Wunused") or "unused" in m.group("msg"):
            sev = "low"
        else:
            sev = "medium"
        out.append({"tool": "compiler", "file": m.group("file"), "line": int(m.group("line")),
                    "severity": sev, "msg": m.group("msg") + (f" [{flag}]" if flag else ""), "id": flag})
    return out


def parse_cppcheck(xml_text: str):
    out = []
    if not (xml_text or "").strip():
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    sev_map = {"error": "high", "warning": "medium", "style": "low", "performance": "low",
               "portability": "low", "information": "info"}
    for e in root.iter("error"):
        loc = e.find("location")
        if loc is None:
            continue
        out.append({"tool": "cppcheck", "file": loc.get("file", ""), "line": int(loc.get("line", "0") or 0),
                    "severity": sev_map.get(e.get("severity", ""), "medium"),
                    "msg": f'{e.get("msg", "")} ({e.get("id", "")})', "id": e.get("id", "")})
    return out


def resolve_log_path(p: str, files):
    """Map a path found in a log (absolute / build-dir relative) to a repository-relative file."""
    p = p.replace("\\", "/")
    while p.startswith(("./", "../")):
        p = p.split("/", 1)[1]
    files = list(files)
    if p in files:
        return p
    cands = [f for f in files if p.endswith("/" + f) or f.endswith("/" + p)]
    if cands:
        return max(cands, key=len)
    base = p.rsplit("/", 1)[-1]
    same = [f for f in files if f.rsplit("/", 1)[-1] == base]
    return same[0] if len(same) == 1 else None


_RUNTIME_HINTS = [
    ("global-buffer-overflow", "A write/read went past the end of a global or static array.",
     "Check loop bounds ('<=' vs '<'), length parameters (DLC) and copy sizes against the array length."),
    ("stack-buffer-overflow", "A local array was accessed out of bounds.",
     "Check copy lengths, unbounded string functions and loop bounds on stack buffers."),
    ("heap-buffer-overflow", "A heap block was accessed out of bounds.",
     "Check the allocation size versus the copy length; look for off-by-one and unchecked sizes."),
    ("heap-use-after-free", "Memory was used after being freed.",
     "Find the free() on this path; null the pointer after free and review ownership."),
    ("use-after-return", "A pointer to a dead stack frame was dereferenced.",
     "Do not return/store addresses of locals; use caller-provided buffers."),
    ("null", "A NULL pointer was dereferenced.",
     "Add NULL checks on parameters and allocator results; define the failure path."),
    ("signed integer overflow", "Signed arithmetic overflowed (undefined behaviour).",
     "Use wider/unsigned types with explicit range checks before the operation."),
    ("stack smashing", "The stack canary was overwritten: a stack buffer overflow occurred.",
     "Look for unbounded copies into local arrays in the crashing function."),
    ("segmentation fault", "Invalid memory access (NULL/dangling/out-of-bounds pointer).",
     "Get a backtrace, then check pointer validity and bounds at the faulting line."),
]


def parse_runtime(text: str):
    """Parse AddressSanitizer / UBSan / generic crash logs. Returns None if nothing recognisable."""
    t = text or ""
    kind = None
    m = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", t) or re.search(r"runtime error: ([^\n]+)", t)
    if m:
        kind = m.group(1).strip()
    else:
        for key, *_ in _RUNTIME_HINTS:
            if key in t.lower():
                kind = key
                break
    if not kind:
        return None
    frames = [{"func": f, "file": fl, "line": int(ln)} for f, fl, ln in
              re.findall(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+?):(\d+)(?::\d+)?", t)]
    for fl, ln, msg in re.findall(r"^(\S+?):(\d+):\d+: runtime error: ([^\n]+)", t, re.M):
        frames.append({"func": None, "file": fl, "line": int(ln)})
    hyp, check = next(((h, c) for k, h, c in _RUNTIME_HINTS if k in kind.lower() or k in t.lower()),
                      ("Unclassified fault.", "Reproduce under a debugger/sanitizer and inspect the faulting line."))
    return {"kind": kind, "frames": frames, "hypothesis": hyp, "check": check}
