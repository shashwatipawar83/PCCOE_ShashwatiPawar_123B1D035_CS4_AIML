"""Streamlit engineering UI for the Secure Code Review Assistant (talks to the FastAPI backend)."""
import os

import pandas as pd
import requests
import streamlit as st

API = os.getenv("SCR_API_URL", "http://127.0.0.1:8000")
st.set_page_config(page_title="Secure Code Review Assistant", page_icon="🛡️", layout="wide")


def call(method, path, **kw):
    h = {"Authorization": f"Bearer {st.session_state.get('token', '')}"}
    try:
        r = requests.request(method, API + path, headers=h, timeout=300, **kw)
    except requests.RequestException as e:
        st.error(f"Backend unreachable: {e}")
        return None
    if r.status_code >= 400:
        st.error(f"{r.status_code}: {r.json().get('detail', r.text) if r.headers.get('content-type','').startswith('application/json') else r.text}")
        return None
    return r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text


# ------------------------------------------------------------------ sidebar / login
with st.sidebar:
    st.title("🛡️ Secure Code Review")
    h = requests.get(API + "/health", timeout=5).json() if st.session_state.get("ok", True) else {}
    st.caption(f"LLM backend: **{h.get('llm_backend', '?')}** · embedder: {h.get('embedder', '?')}")
    if "token" not in st.session_state:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Sign in", type="primary"):
            r = requests.post(API + "/auth/login", json={"username": u, "password": p}, timeout=30)
            if r.ok:
                st.session_state.token = r.json()["access_token"]
                st.rerun()
            else:
                st.error("Invalid credentials")
        st.stop()
    me = call("GET", "/me")
    if not me:
        del st.session_state["token"]
        st.rerun()
    st.success(f"{me['username']} ({me['role']})")
    repos = call("GET", "/repos") or []
    repo = st.selectbox("Repository", [r["name"] for r in repos]) if repos else None
    use_llm = st.toggle("Use local LLM", value=True, help="Falls back to deterministic output if no model is configured")
    if st.button("Sign out"):
        del st.session_state["token"]
        st.rerun()
    st.caption("All analysis runs inside your network. AI output is advisory; a reviewer must disposition each finding.")

if not repo:
    st.warning("No repository is available to your account.")
    st.stop()

tabs = st.tabs(["🔎 Review", "💬 Ask the code", "🐞 Debug a log", "📄 Summaries", "✅ Findings", "📊 Metrics & audit"])

# ------------------------------------------------------------------ review
with tabs[0]:
    files = next(r["files"] for r in repos if r["name"] == repo)
    sel = st.multiselect("Limit to files (empty = everything you may access)", files)
    c1, c2 = st.columns(2)
    blog = c1.text_area("Compiler / build log (optional)", height=120)
    cxml = c2.text_area("cppcheck XML (optional)", height=120)
    if st.button("Run review", type="primary"):
        with st.spinner("Analysing…"):
            res = call("POST", "/review", json={"repo": repo, "paths": sel or None, "build_log": blog or None,
                                                "cppcheck_xml": cxml or None, "use_llm": use_llm})
        if res:
            s = res["stats"]
            m = st.columns(4)
            m[0].metric("Files scanned", s["files_scanned"]); m[1].metric("Findings", s["findings"])
            m[2].metric("LLM-enriched", s["llm_enriched"]); m[3].metric("Skipped (no access)", s["skipped_unauthorized"])
            st.json(s["by_severity"])
            st.info("Open the **Findings** tab to review and disposition results.")

# ------------------------------------------------------------------ ask
with tabs[1]:
    q = st.text_input("Ask about the code (e.g. 'where is the CAN receive buffer copied?')")
    if q and st.button("Ask"):
        r = call("POST", "/ask", json={"repo": repo, "question": q, "use_llm": use_llm})
        if r:
            st.caption(f"mode: {r['mode']}")
            st.markdown(r["answer"])
            if r["citations"]:
                st.dataframe(pd.DataFrame(r["citations"]), hide_index=True, use_container_width=True)
            if r["guidelines"]:
                st.write("Related guidelines:", ", ".join(f"{g['id']} – {g['title']}" for g in r["guidelines"]))

# ------------------------------------------------------------------ debug
with tabs[2]:
    log = st.text_area("Paste a sanitizer / crash / compiler / cppcheck log", height=200)
    if log and st.button("Analyse log"):
        r = call("POST", "/debug", json={"repo": repo, "log": log, "use_llm": use_llm})
        if r:
            st.subheader(f"Detected: {r['log_kind']}")
            for c in r["root_causes"]:
                with st.expander(f"{c['title']} — confidence {c['confidence']}", expanded=True):
                    loc = c["location"]
                    st.write(f"**Location:** `{loc['file']}:{loc['line']}` in `{loc['function']}`")
                    st.write(f"**Hypothesis:** {c['hypothesis']}\n\n**Check:** {c['what_to_check']}")
                    st.code(c["evidence"], language="c")
                    if c["corroborating_findings"]:
                        st.write("Corroborated by static findings:", c["corroborating_findings"])
                    if c["llm_analysis"]:
                        st.markdown("**LLM analysis (advisory):**\n\n" + c["llm_analysis"])
            if r["findings"]:
                st.write(f"{len(r['findings'])} finding(s) recorded.")

# ------------------------------------------------------------------ summaries
with tabs[3]:
    path = st.selectbox("File", next(r["files"] for r in repos if r["name"] == repo), key="sumfile")
    if st.button("Summarise file"):
        r = call("POST", "/summarize", json={"repo": repo, "path": path, "use_llm": use_llm})
        if r:
            st.write(f"**{r['loc']} lines** · includes: {', '.join(r['includes']) or '—'}")
            if r["narrative"]:
                st.markdown(r["narrative"])
            if r["functions"]:
                df = pd.DataFrame(r["functions"])
                st.dataframe(df[["name", "start", "end", "loc", "complexity", "branches", "loops", "switches", "gotos",
                                 "calls_internal", "calls_external"]], hide_index=True, use_container_width=True)
            for n in r["dependency_notes"]:
                st.code(n)

# ------------------------------------------------------------------ findings
with tabs[4]:
    f1, f2 = st.columns(2)
    status = f1.selectbox("Status", ["", "open", "accepted", "rejected", "fixed"])
    minsev = f2.selectbox("Minimum severity", ["", "low", "medium", "high", "critical"])
    params = {"repo": repo, **({"status": status} if status else {}), **({"min_severity": minsev} if minsev else {})}
    rows = call("GET", "/findings", params=params) or []
    if rows:
        df = pd.DataFrame(rows)
        st.dataframe(df[["id", "severity", "rule", "title", "file", "function", "line_start", "confidence", "status", "source"]],
                     hide_index=True, use_container_width=True)
        fid = st.selectbox("Open finding", [r["id"] for r in rows])
        f = next(r for r in rows if r["id"] == fid)
        st.markdown(f"### [{f['severity'].upper()}] {f['title']}")
        st.caption(f"{f['file']}:{f['line_start']} · {f['function']} · {f['reference']} · confidence {f['confidence']} · source {f['source']}"
                   + (" · LLM-assisted" if f["llm_used"] else ""))
        st.code(f["evidence"], language="c")
        st.markdown(f"**Why:** {f['explanation'] or f['description']}\n\n**Suggested fix:** {f['suggestion']}")
        st.write("Citations:", [c.get("id") or f"{c.get('file')}:{c.get('lines')}" for c in f["citations"]])
        opts = {"reviewer": ["accepted", "rejected", "open"], "admin": ["accepted", "rejected", "open", "fixed"],
                "developer": ["fixed"]}[me["role"]]
        d1, d2 = st.columns([1, 3])
        new = d1.selectbox("Disposition", opts)
        cm = d2.text_input("Comment (required to reject)")
        if st.button("Save disposition"):
            if call("PATCH", f"/findings/{fid}", json={"status": new, "comment": cm}):
                st.rerun()
        b1, b2 = st.columns(2)
        if me["role"] in ("reviewer", "admin") and b1.button("Publish accepted → workflow system"):
            st.success(call("POST", "/findings/publish", params={"repo": repo}))
        b2.download_button("Download report (Markdown)", call("GET", "/findings/export", params={"repo": repo}) or "",
                           file_name="review_report.md")
    else:
        st.info("No findings yet. Run a review first.")

# ------------------------------------------------------------------ metrics / audit
with tabs[5]:
    m = call("GET", "/metrics", params={"repo": repo})
    if m:
        c = st.columns(4)
        c[0].metric("Findings", m["total"]); c[1].metric("Reviewed", m["reviewed"])
        c[2].metric("Finding precision", m["finding_precision"] if m["finding_precision"] is not None else "n/a")
        c[3].metric("Processed in boundary", f"{m['processed_inside_boundary_pct']}%")
        st.write("By status", m["by_status"]); st.write("By rule", m["by_rule"])
        st.caption(f"Audit hash-chain valid: {m['audit_chain_valid']}")
    if me["role"] == "admin":
        st.subheader("Audit log")
        a = call("GET", "/admin/audit")
        if a:
            st.dataframe(pd.DataFrame(a["entries"]), hide_index=True, use_container_width=True)
        if st.button("Re-index repository"):
            st.write(call("POST", f"/admin/repos/{repo}/index"))
