"""Review engine: static analysis + log evidence + RAG grounding + optional local-LLM enrichment."""
from __future__ import annotations
import re

from . import guard
from .analyzers.logs import parse_compiler, parse_cppcheck, parse_runtime, resolve_log_path
from .analyzers.rules import CATALOGUE, run_rules
from .code import Ctx
from .llm import LLMUnavailable
from .services import ApiError, SEV_ORDER, Services

FP_LEVELS = {"low", "medium", "high"}


class Engine:
    def __init__(self, svc: Services):
        self.svc = svc

    # ------------------------------------------------------------------ review
    def review(self, user, repo, paths=None, build_log=None, cppcheck_xml=None, use_llm=True):
        svc = self.svc
        svc.require_repo_access(user, repo)
        files = svc.authorized_files(user, repo)
        denied = 0
        if paths:
            sel = [p.strip("/") for p in paths]
            denied = sum(1 for f in svc.all_files(repo) if any(f == p or f.startswith(p + "/") for p in sel)
                         and not svc.can_access(user, repo, f))
            files = [f for f in files if any(f == p or f.startswith(p + "/") for p in sel)]
        ctxs, findings = {}, []
        for rel in files:
            ctx = ctxs[rel] = Ctx(rel, svc.read_file(repo, rel))
            findings += run_rules(ctx)
        unmapped = 0
        for e in parse_compiler(build_log) + parse_cppcheck(cppcheck_xml):
            rel = resolve_log_path(e["file"], files)
            if not rel:
                unmapped += 1
                continue
            findings.append(self._log_finding(ctxs[rel], e))
        llm_n = self._enrich(findings, ctxs, use_llm)
        rows = [svc.save_finding(user, repo, f) for f in findings]
        svc.db.audit(user["username"], "review", {"repo": repo, "files": len(files), "findings": len(rows),
                                                   "skipped_unauthorized": denied, "llm": llm_n})
        rows.sort(key=lambda r: (-SEV_ORDER[r["severity"]], r["file"], r["line_start"]))
        by = {}
        for r in rows:
            by[r["severity"]] = by.get(r["severity"], 0) + 1
        return {"findings": rows, "stats": {"files_scanned": len(files), "findings": len(rows), "by_severity": by,
                                            "skipped_unauthorized": denied, "unmapped_log_entries": unmapped,
                                            "llm_enriched": llm_n, "llm_mode": svc.llm.backend}}

    def _log_finding(self, ctx: Ctx, e):
        rid = "ICR-CMP" if e["tool"] == "compiler" else "ICR-SA"
        r, fn = CATALOGUE[rid], ctx.func_at(e["line"])
        ln = max(1, min(e["line"], len(ctx.lines)))
        return {"rule": rid, "title": f"{e['tool']}: {e['msg']}", "severity": e["severity"], "category": r.category,
                "file": ctx.path, "function": fn.name if fn else None, "line_start": ln, "line_end": ln,
                "evidence": ctx.snippet(ln, ln), "description": r.description, "suggestion": r.fix,
                "confidence": r.confidence, "source": e["tool"], "reference": r.ref, "anchor": e["msg"]}

    def _enrich(self, findings, ctxs, use_llm) -> int:
        svc, llm_n = self.svc, 0
        for f in findings:
            f["citations"] = [{"type": "code", "file": f["file"], "lines": f"{f['line_start']}-{f['line_end']}",
                               "function": f["function"]}]
            g = svc.guidelines.lookup(f["rule"])
            if g:
                f["citations"].append({"type": "guideline", "id": g["id"], "title": g["title"]})
            for rel in svc.guidelines.related(f"{f['title']} {f['description']}", exclude=f["rule"], k=1):
                f["citations"].append({"type": "guideline", "id": rel["id"], "title": rel["title"]})
        if not (use_llm and svc.llm.available):
            return 0
        todo = sorted((f for f in findings if f["rule"] != "ICR-SEC1"), key=lambda f: -SEV_ORDER[f["severity"]])
        for f in todo[: svc.settings.max_llm_findings]:
            ctx = ctxs.get(f["file"])
            fn = ctx.func_at(f["line_start"]) if ctx else None
            code = "\n".join(ctx.lines[fn.start - 1: fn.end]) if fn else f["evidence"]
            guid = "\n".join(svc.guidelines.lookup(c["id"])["text"] for c in f["citations"] if c["type"] == "guideline")
            prompt = (f"Finding: {f['rule']} - {f['title']} (severity {f['severity']}) at {f['file']}:{f['line_start']}\n"
                      f"Trusted guideline excerpts:\n{guid}\n\n"
                      f"{guard.wrap_untrusted(f['file'], code[:3000])}\n\n"
                      'Return JSON: {"explanation": "<=3 sentences why this is a problem here", '
                      '"suggested_fix": "concrete fix for this code", "likely_false_positive": "low|medium|high"}')
            try:
                d = svc.llm.complete_json(guard.SYSTEM_PROMPT, prompt, ("explanation", "suggested_fix", "likely_false_positive"))
                if (d["likely_false_positive"] not in FP_LEVELS or len(d["explanation"]) > 1500
                        or not guard.output_is_safe(d["explanation"] + d["suggested_fix"])):
                    continue
                f["explanation"], f["suggestion"], f["llm_used"] = d["explanation"], d["suggested_fix"], True
                if d["likely_false_positive"] == "high":
                    f["confidence"] = round(f["confidence"] * 0.6, 2)
                llm_n += 1
            except LLMUnavailable:
                continue
        return llm_n

    # ------------------------------------------------------------------ Q&A
    def ask(self, user, repo, question, k=5, use_llm=True):
        svc = self.svc
        svc.require_repo_access(user, repo)
        allowed = lambda m: svc.can_access(user, repo, m["path"])     # authorise BEFORE ranking
        hits = svc.store.search(f"code::{repo}", question, k=k, predicate=allowed)
        guides = svc.guidelines.related(question, k=2, min_score=0.25)
        cites = [{"n": i + 1, "file": m["path"], "lines": f"{m['start']}-{m['end']}", "function": m["name"],
                  "score": round(s, 2)} for i, (s, m, _) in enumerate(hits)]
        svc.db.audit(user["username"], "ask", {"repo": repo, "q": question[:200], "chunks": [c["file"] for c in cites]})
        if not hits:
            return {"answer": "No authorised, indexed code matched this question. (Has the repository been indexed?)",
                    "citations": [], "guidelines": guides, "mode": "none"}
        if use_llm and svc.llm.available:
            ctx = "\n\n".join(guard.wrap_untrusted(f"[{c['n']}] {c['file']}:{c['lines']}", t[:1800])
                              for c, (_, _, t) in zip(cites, hits))
            gtxt = "\n".join(svc.guidelines.lookup(g["id"])["text"] for g in guides)
            try:
                ans = svc.llm.complete(guard.SYSTEM_PROMPT.replace("Reply ONLY in the requested JSON format.",
                                       "Answer in plain text and cite sources as [n]."),
                                       f"Question: {question}\nGuidelines (trusted):\n{gtxt}\n\nCode sources:\n{ctx}")
                if guard.output_is_safe(ans):
                    if not re.search(r"\[\d+\]", ans):
                        ans += "\n\nSources: " + ", ".join(f"[{c['n']}] {c['file']}:{c['lines']}" for c in cites)
                    return {"answer": ans, "citations": cites, "guidelines": guides, "mode": "llm"}
            except LLMUnavailable:
                pass
        lines = [f"[{c['n']}] `{c['function']}` in {c['file']}:{c['lines']} (relevance {c['score']})" for c in cites]
        return {"answer": "Most relevant authorised code (extractive mode - no LLM configured):\n" + "\n".join(lines),
                "citations": cites, "guidelines": guides, "mode": "extractive"}

    # ------------------------------------------------------------------ summaries
    def summarize(self, user, repo, path, function=None, use_llm=True):
        ctx = self.svc.read_authorized(user, repo, path)
        stats = ctx.stats()
        if function:
            stats = [s for s in stats if s["name"] == function]
            if not stats:
                raise ApiError(404, f"function '{function}' not found")
        out = {"file": path, "includes": ctx.includes(), "functions": stats, "loc": len(ctx.lines),
               "dependency_notes": [f"{s['name']} -> {', '.join(s['calls_internal'])}" for s in stats if s["calls_internal"]],
               "narrative": None}
        if use_llm and self.svc.llm.available:
            code = "\n".join(ctx.lines[stats[0]["start"] - 1: stats[0]["end"]]) if function else ctx.src[:6000]
            try:
                out["narrative"] = self.svc.llm.complete(
                    guard.SYSTEM_PROMPT.replace("Reply ONLY in the requested JSON format.", "Reply in plain text."),
                    "Summarise what this code does, its inputs/outputs and notable risks in <=8 lines.\n"
                    + guard.wrap_untrusted(path, code))
            except LLMUnavailable:
                pass
        self.svc.db.audit(user["username"], "summarize", {"repo": repo, "file": path, "fn": function})
        return out

    # ------------------------------------------------------------------ debugging
    def debug(self, user, repo, log_text, use_llm=True):
        svc = self.svc
        svc.require_repo_access(user, repo)
        files = svc.authorized_files(user, repo)
        rt = parse_runtime(log_text)
        causes, created = [], []
        if rt:
            for fr in rt["frames"][:6]:
                rel = resolve_log_path(fr["file"], files)
                if not rel:
                    continue
                ctx = Ctx(rel, svc.read_file(repo, rel))
                fn = ctx.func_at(fr["line"])
                corr = [f for f in run_rules(ctx) if fn and fn.start <= f["line_start"] <= fn.end]
                conf = min(0.9, 0.5 + 0.2 * len(corr))
                ln = max(1, min(fr["line"], len(ctx.lines)))
                cause = {"title": f"{rt['kind']} in {fn.name if fn else rel}", "hypothesis": rt["hypothesis"],
                         "what_to_check": rt["check"], "location": {"file": rel, "function": fn.name if fn else None, "line": ln},
                         "evidence": ctx.snippet(ln, ln),
                         "corroborating_findings": [{"rule": f["rule"], "title": f["title"], "line": f["line_start"]} for f in corr],
                         "confidence": round(conf, 2), "llm_analysis": None}
                if use_llm and svc.llm.available and fn and not any(c["location"]["function"] == fn.name for c in causes):
                    try:
                        cause["llm_analysis"] = svc.llm.complete(
                            guard.SYSTEM_PROMPT.replace("Reply ONLY in the requested JSON format.", "Reply in plain text, <=8 lines."),
                            f"Runtime evidence (parsed, trusted): {rt['kind']} at {rel}:{ln}.\n"
                            "Give the most likely root cause and a fix.\n"
                            + guard.wrap_untrusted(rel, "\n".join(ctx.lines[fn.start - 1: fn.end])[:3000])
                            + "\n" + guard.wrap_untrusted("log", log_text[:1500]))
                    except LLMUnavailable:
                        pass
                causes.append(cause)
                r = CATALOGUE["ICR-RT"]
                created.append(svc.save_finding(user, repo, {
                    "rule": "ICR-RT", "title": cause["title"], "severity": "high", "category": "runtime", "file": rel,
                    "function": cause["location"]["function"], "line_start": ln, "line_end": ln,
                    "evidence": cause["evidence"], "description": rt["hypothesis"], "suggestion": rt["check"],
                    "confidence": cause["confidence"], "source": "runtime", "reference": r.ref,
                    "anchor": rt["kind"], "llm_used": bool(cause["llm_analysis"]),
                    "explanation": cause["llm_analysis"],
                    "citations": [{"type": "code", "file": rel, "lines": str(ln), "function": cause["location"]["function"]}]}))
        else:
            res = self.review(user, repo, build_log=log_text, cppcheck_xml=log_text if "<error" in log_text else None, use_llm=use_llm)
            created = [f for f in res["findings"] if f["source"] in ("compiler", "cppcheck")]
        svc.db.audit(user["username"], "debug", {"repo": repo, "kind": rt["kind"] if rt else "build/static", "causes": len(causes)})
        return {"log_kind": rt["kind"] if rt else "build/static-analysis", "root_causes": causes,
                "findings": created, "llm_mode": svc.llm.backend}
