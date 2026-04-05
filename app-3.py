"""
╔══════════════════════════════════════════════════════════════════╗
║     B U I L D  V U L N E R A B I L I T Y  S C A N N E R          ║
║                          U S I N G   A I                         ║
╚══════════════════════════════════════════════════════════════════╝

Run:  streamlit run app.py

pip install:
  streamlit>=1.32 pandas numpy scikit-learn joblib
  networkx plotly fpdf2
"""

from __future__ import annotations

import io
import math
import re
import warnings
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

warnings.filterwarnings("ignore")

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Build Vulnerability Scanner using AI",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
#  CYBER-STEALTH CSS
# ══════════════════════════════════════════════════════════════════════════════
CYBER_CSS = """
<style>
/* ── Google Fonts ── */
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');

/* ── Palette ── */
:root {
  --void:      #060a10;
  --deep:      #080d18;
  --panel:     #0b1220;
  --card:      #0e1628;
  --border:    #162035;
  --border-hi: #1e3055;
  --green:     #00ff88;
  --green-dim: #00994d;
  --amber:     #ffb300;
  --amber-dim: #996900;
  --red:       #ff2d2d;
  --red-dim:   #991a1a;
  --cyan:      #00e5ff;
  --cyan-dim:  #008899;
  --text:      #b8c8e0;
  --text-dim:  #4a6080;
  --text-hi:   #e4eeff;
}

/* ── Base ── */
html, body, [class*="css"] {
  font-family: 'Rajdhani', sans-serif;
  background: var(--void);
  color: var(--text);
}

/* Scanline overlay */
body::after {
  content: '';
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,255,136,0.012) 2px,
    rgba(0,255,136,0.012) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

.main .block-container {
  padding: 0.8rem 1.6rem 2rem;
  max-width: 1600px;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
  background: var(--deep) !important;
  border-right: 1px solid var(--border-hi) !important;
}
section[data-testid="stSidebar"]::before {
  content: '';
  display: block;
  height: 2px;
  background: linear-gradient(90deg, var(--green), transparent);
  margin-bottom: 0.5rem;
}

/* ── KPI cards ── */
.kpi-row { display: flex; gap: 1rem; margin-bottom: 1.4rem; }

.kpi-card {
  flex: 1;
  background: var(--card);
  border: 1px solid var(--border);
  border-top: 2px solid var(--kpi-color, var(--green));
  border-radius: 4px;
  padding: 1rem 1.2rem;
  position: relative;
  overflow: hidden;
  transition: border-color .25s, box-shadow .25s;
}
.kpi-card::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at top left,
    color-mix(in srgb, var(--kpi-color, var(--green)) 6%, transparent),
    transparent 70%);
}
.kpi-card:hover {
  border-color: var(--kpi-color, var(--green));
  box-shadow: 0 0 24px color-mix(in srgb, var(--kpi-color, var(--green)) 20%, transparent);
}
.kpi-label {
  font-family: 'Share Tech Mono', monospace;
  font-size: 0.63rem;
  letter-spacing: .16em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: .3rem;
}
.kpi-value {
  font-family: 'Orbitron', monospace;
  font-size: 2.2rem;
  font-weight: 900;
  color: var(--kpi-color, var(--green));
  line-height: 1;
}
.kpi-sub {
  font-size: 0.72rem;
  color: var(--text-dim);
  margin-top: .2rem;
  font-family: 'Share Tech Mono', monospace;
}

/* ── Section label ── */
.sec-label {
  font-family: 'Share Tech Mono', monospace;
  font-size: 0.65rem;
  letter-spacing: .2em;
  text-transform: uppercase;
  color: var(--green);
  border-bottom: 1px solid var(--border);
  padding-bottom: .35rem;
  margin: 1.4rem 0 .8rem;
  display: flex;
  align-items: center;
  gap: .5rem;
}
.sec-label::before {
  content: '▸';
  color: var(--green);
}

/* ── Severity badges ── */
.sev {
  display: inline-block;
  padding: 2px 9px;
  border-radius: 2px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
}
.sev-CRITICAL { background: #2a0505; color: #ff2d2d; border: 1px solid #ff2d2d44; }
.sev-HIGH     { background: #261400; color: #ff7a00; border: 1px solid #ff7a0044; }
.sev-MEDIUM   { background: #261e00; color: #ffb300; border: 1px solid #ffb30044; }
.sev-LOW      { background: #001f26; color: #00e5ff; border: 1px solid #00e5ff44; }
.sev-INFO     { background: #131b26; color: #4a6080; border: 1px solid #4a608044; }

/* ── Risk label ── */
.risk-HIGH   { color:#ff2d2d; font-family:'Orbitron',monospace; font-weight:700; }
.risk-LOW    { color:#00ff88; font-family:'Orbitron',monospace; font-weight:700; }
.risk-MEDIUM { color:#ffb300; font-family:'Orbitron',monospace; font-weight:700; }

/* ── Terminal header ── */
.term-header {
  font-family: 'Orbitron', monospace;
  font-weight: 900;
  letter-spacing: .04em;
  color: var(--green);
  text-shadow: 0 0 30px rgba(0,255,136,.5);
}

/* ── Remediation card ── */
.remed-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-left: 3px solid var(--remed-color, var(--amber));
  border-radius: 3px;
  padding: 1rem 1.2rem;
  margin-bottom: .8rem;
  font-size: .85rem;
}
.remed-title {
  font-family: 'Share Tech Mono', monospace;
  color: var(--remed-color, var(--amber));
  font-size: .8rem;
  margin-bottom: .4rem;
  text-transform: uppercase;
  letter-spacing: .08em;
}

/* ── Streamlit overrides ── */
.stTabs [data-baseweb="tab-list"] {
  background: var(--deep);
  border-bottom: 1px solid var(--border-hi);
  gap: 0;
}
.stTabs [data-baseweb="tab"] {
  font-family: 'Share Tech Mono', monospace !important;
  font-size: 0.72rem !important;
  letter-spacing: .12em !important;
  text-transform: uppercase !important;
  color: var(--text-dim) !important;
  background: transparent !important;
  border: none !important;
  padding: .7rem 1.4rem !important;
  border-bottom: 2px solid transparent !important;
}
.stTabs [aria-selected="true"] {
  color: var(--green) !important;
  border-bottom-color: var(--green) !important;
}
.stDataFrame { border: 1px solid var(--border) !important; border-radius: 4px; }
.stFileUploader label, .stMultiSelect label,
.stSelectbox label, .stTextInput label {
  font-family: 'Share Tech Mono', monospace !important;
  font-size: .7rem !important;
  letter-spacing: .1em !important;
  color: var(--text-dim) !important;
  text-transform: uppercase;
}
.stButton > button {
  background: transparent !important;
  border: 1px solid var(--green) !important;
  color: var(--green) !important;
  font-family: 'Share Tech Mono', monospace !important;
  font-size: .72rem !important;
  letter-spacing: .1em !important;
  text-transform: uppercase;
  border-radius: 2px !important;
  transition: all .2s !important;
}
.stButton > button:hover {
  background: var(--green) !important;
  color: var(--void) !important;
}
div[data-testid="stMetricValue"] {
  font-family: 'Orbitron', monospace !important;
  color: var(--green) !important;
}
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
DEFAULT_CSV = Path(__file__).parent / "report_from_scan_transfer_to_ai.csv"
DEFAULT_RF  = Path(__file__).parent / "Vulcan_RF_Pipeline_Final.pkl"
DEFAULT_SVM = Path(__file__).parent / "SVM_best_payload_classifier.pkl"

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR  = {
    "CRITICAL": "#ff2d2d",
    "HIGH":     "#ff7a00",
    "MEDIUM":   "#ffb300",
    "LOW":      "#00e5ff",
    "INFO":     "#4a6080",
}
RISK_COLOR = {"HIGH": "#ff2d2d", "MEDIUM": "#ffb300", "LOW": "#00ff88"}

SEV_BASE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.6, "INFO": 0.5}
EPSS_MAP = {"CRITICAL": 0.55, "HIGH": 0.35, "MEDIUM": 0.12, "LOW": 0.04, "INFO": 0.01}

# ══════════════════════════════════════════════════════════════════════════════
#  REMEDIATION DATABASE
# ══════════════════════════════════════════════════════════════════════════════
REMEDIATION_DB: dict[str, dict] = {
    "26194": {
        "title": "Enforce HTTPS / Disable Plain HTTP",
        "priority": "HIGH",
        "steps": [
            "Obtain and install a valid TLS/SSL certificate (Let's Encrypt is free).",
            "Configure the web server to redirect all HTTP (port 80) requests to HTTPS (port 443).",
            "Nginx: add `return 301 https://$host$request_uri;` in the HTTP server block.",
            "Apache: add `RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]` in .htaccess.",
            "Set HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
            "Test with: `curl -I http://your-host` — should return 301.",
        ],
        "refs": ["CWE-319", "OWASP TLS Cheat Sheet"],
    },
    "50345": {
        "title": "Add Strict-Transport-Security Header",
        "priority": "MEDIUM",
        "steps": [
            "Add the HSTS response header to all HTTPS responses.",
            "Nginx: `add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;`",
            "Apache: `Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\"` (requires mod_headers).",
            "Start with a short max-age (300s) to test, then increase to 1 year (31536000).",
            "Submit to the HSTS preload list at https://hstspreload.org once stable.",
            "Test with: `curl -I https://your-host | grep Strict`",
        ],
        "refs": ["RFC 6797", "OWASP HSTS Cheat Sheet"],
    },
    "85582": {
        "title": "Mitigate Clickjacking — X-Frame-Options",
        "priority": "MEDIUM",
        "steps": [
            "Add `X-Frame-Options: DENY` header if the site should never be framed.",
            "Use `X-Frame-Options: SAMEORIGIN` to allow only same-origin framing.",
            "Nginx: `add_header X-Frame-Options DENY always;`",
            "Apache: `Header always set X-Frame-Options DENY`",
            "Modern alternative: use Content-Security-Policy `frame-ancestors 'none'` (supersedes X-Frame-Options).",
            "Test using browser developer tools or https://securityheaders.com",
        ],
        "refs": ["CWE-1021", "OWASP Clickjacking Defense"],
    },
    "10107": {
        "title": "Suppress Server Banner Disclosure",
        "priority": "LOW",
        "steps": [
            "Remove or redact the Server response header to prevent version fingerprinting.",
            "Nginx: set `server_tokens off;` in http/server block.",
            "Apache: set `ServerTokens Prod` and `ServerSignature Off` in httpd.conf.",
            "Consider using a WAF (Cloudflare, ModSecurity) to strip/replace the header.",
            "Verify with: `curl -I http://your-host | grep Server` — output should be blank or generic.",
        ],
        "refs": ["CWE-200", "OWASP Information Exposure"],
    },
    "10302": {
        "title": "Restrict robots.txt Information Disclosure",
        "priority": "LOW",
        "steps": [
            "Audit /robots.txt — never list sensitive paths (e.g. /admin, /backup, /api).",
            "Use authentication/authorisation to protect sensitive endpoints instead of relying on robots.txt.",
            "If paths must be disallowed, use generic rules: `Disallow: /` for bots you want to block entirely.",
            "Consider removing specific disallowed paths that reveal internal structure.",
            "Note: robots.txt is public by design — treat it as a roadmap for attackers if misused.",
        ],
        "refs": ["CWE-200", "Google Search Central — robots.txt"],
    },
    "84502": {
        "title": "Add X-Content-Type-Options Header",
        "priority": "LOW",
        "steps": [
            "Add `X-Content-Type-Options: nosniff` to all responses.",
            "Nginx: `add_header X-Content-Type-Options nosniff always;`",
            "Apache: `Header always set X-Content-Type-Options nosniff`",
            "This prevents MIME-type sniffing attacks in older browsers.",
            "Ensure all responses have accurate Content-Type headers set.",
        ],
        "refs": ["CWE-16", "OWASP Secure Headers Project"],
    },
    "56759": {
        "title": "Implement Content-Security-Policy",
        "priority": "MEDIUM",
        "steps": [
            "Start with a report-only policy to identify violations before enforcing.",
            "Use `Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report`.",
            "Define explicit allowlists: `default-src 'self'; script-src 'self' cdn.example.com; style-src 'self' 'unsafe-inline';`",
            "Block inline scripts by removing `'unsafe-inline'` from script-src (requires code changes).",
            "Use CSP nonces for legitimate inline scripts: `script-src 'nonce-{random}'`.",
            "Validate policy at https://csp-evaluator.withgoogle.com",
        ],
        "refs": ["CWE-693", "OWASP CSP Cheat Sheet", "CSP Level 3 W3C"],
    },
    "50344": {
        "title": "Add X-XSS-Protection Header",
        "priority": "LOW",
        "steps": [
            "Add `X-XSS-Protection: 1; mode=block` for legacy browser protection.",
            "Note: modern browsers rely on CSP instead — add this for defence-in-depth.",
            "Nginx: `add_header X-XSS-Protection \"1; mode=block\" always;`",
            "Apache: `Header always set X-XSS-Protection \"1; mode=block\"`",
            "Prioritise implementing a strong Content-Security-Policy as the primary XSS control.",
        ],
        "refs": ["CWE-79", "OWASP XSS Prevention Cheat Sheet"],
    },
    "DEFAULT": {
        "title": "General Security Hardening",
        "priority": "MEDIUM",
        "steps": [
            "Patch all software components to their latest stable versions.",
            "Apply principle of least privilege to all services and accounts.",
            "Enable centralised logging and alerting (SIEM).",
            "Conduct regular penetration tests and vulnerability assessments.",
            "Review and apply CIS Benchmarks for the affected software.",
            "Consult vendor security advisories for specific patches.",
        ],
        "refs": ["OWASP Top 10", "NIST Cybersecurity Framework"],
    },
}


def get_remediation(plugin_id: str, name: str) -> dict:
    """Return remediation dict by plugin ID, falling back to name-based lookup."""
    pid = str(plugin_id).strip()
    if pid in REMEDIATION_DB:
        return REMEDIATION_DB[pid]
    name_lower = str(name).lower()
    for key, val in REMEDIATION_DB.items():
        if key == "DEFAULT":
            continue
        if any(word in name_lower for word in val["title"].lower().split()):
            return val
    return REMEDIATION_DB["DEFAULT"]


# ══════════════════════════════════════════════════════════════════════════════
#  ML HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _infer_attack_vector(desc: str) -> str:
    d = str(desc).lower()
    if any(w in d for w in ("network", "http", "remote", "web", "url", "internet")):
        return "NETWORK"
    if any(w in d for w in ("local", "cleartext", "unencrypted", "credential")):
        return "LOCAL"
    if "adjacent" in d:
        return "ADJACENT_NETWORK"
    if "physical" in d:
        return "PHYSICAL"
    return "NETWORK"


def build_rf_feature_vector(row: pd.Series, rf_bundle: dict) -> np.ndarray:
    le_vuln   = rf_bundle["le_vuln"]
    le_vector = rf_bundle["le_vector"]
    features  = rf_bundle["expected_features"]

    sev  = str(row.get("severity", "INFO")).upper()
    cvss = float(row.get("cvss", 0)) if pd.notna(row.get("cvss")) else 0.0
    desc = str(row.get("description", ""))

    base_score        = cvss if cvss > 0 else SEV_BASE.get(sev, 1.0)
    exploitability    = round(base_score * 0.68, 4)
    impact            = round(base_score * 0.72, 4)
    epss_score        = EPSS_MAP.get(sev, 0.05)
    epss_perc         = round(epss_score * 0.85, 4)
    vuln_enc          = 0

    av = _infer_attack_vector(desc)
    try:
        vec_enc = int(le_vector.transform([av])[0])
    except ValueError:
        vec_enc = int(le_vector.transform(["NETWORK"])[0])

    fmap = {
        "base_score":            base_score,
        "exploitability_score":  exploitability,
        "impact_score":          impact,
        "epss_score":            epss_score,
        "epss_perc":             epss_perc,
        "vulnerability_encoded": vuln_enc,
        "attack_vector_encoded": vec_enc,
    }
    return np.array([fmap.get(f, 0.0) for f in features], dtype=float).reshape(1, -1)


def rf_predict_row(row: pd.Series, rf_bundle: dict) -> tuple[str, dict[str, float]]:
    model     = rf_bundle["model"]
    le_target = rf_bundle["le_target"]
    X = build_rf_feature_vector(row, rf_bundle)
    proba = model.predict_proba(X)[0]
    pred_idx = model.predict(X)[0]
    pred_label = le_target.inverse_transform([pred_idx])[0]
    prob_dict = {
        le_target.classes_[i]: float(proba[j])
        for j, i in enumerate(model.classes_)
    }
    return pred_label, prob_dict


def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - x.max()
    e = np.exp(x)
    return e / e.sum()


def svm_predict_row(text: str, svm_bundle: dict) -> tuple[str, dict[str, float]]:
    model     = svm_bundle["model"]
    clf       = model.named_steps["clf"]
    classes   = list(clf.classes_)
    cleaned   = re.sub(r"\s+", " ", str(text).lower().strip())
    decision  = model.decision_function([cleaned])[0]
    probs     = _softmax(np.array(decision, dtype=float))
    pred      = model.predict([cleaned])[0]
    return str(pred), dict(zip(classes, probs.tolist()))


def enrich_df(df: pd.DataFrame, rf_bundle: Optional[dict]) -> pd.DataFrame:
    df = df.copy()
    rf_risks, prob_highs, prob_lows = [], [], []
    for _, row in df.iterrows():
        if rf_bundle is not None:
            try:
                label, probs = rf_predict_row(row, rf_bundle)
                rf_risks.append(label)
                prob_highs.append(probs.get("HIGH", 0.5))
                prob_lows.append(probs.get("LOW", 0.5))
            except Exception:
                rf_risks.append("LOW")
                prob_highs.append(0.3)
                prob_lows.append(0.7)
        else:
            sev = str(row.get("severity", "INFO")).upper()
            cvss = float(row.get("cvss", 0)) if pd.notna(row.get("cvss")) else 0.0
            combined = SEV_BASE.get(sev, 1.0) * 0.55 + cvss * 0.45
            if combined >= 7.0:
                lbl, ph = "HIGH", min(0.95, combined / 10)
            elif combined >= 4.0:
                lbl, ph = "MEDIUM", 0.45
            else:
                lbl, ph = "LOW", 0.15
            rf_risks.append(lbl)
            prob_highs.append(ph)
            prob_lows.append(1.0 - ph)

    df["rf_risk"]      = rf_risks
    df["rf_prob_high"] = prob_highs
    df["rf_prob_low"]  = prob_lows

    sev_score_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}
    risk_score_map = {"HIGH": 8, "MEDIUM": 5, "LOW": 2}
    df["sev_score"]  = df["severity"].map(sev_score_map).fillna(1)
    df["risk_score"] = df["rf_risk"].map(risk_score_map).fillna(2)
    df["composite"]  = (df["sev_score"] * 0.4 + df["risk_score"] * 0.4 +
                        df["rf_prob_high"] * 10 * 0.2).round(2)
    return df


# ══════════════════════════════════════════════════════════════════════════════
#  DATA LOADERS (cached)
# ══════════════════════════════════════════════════════════════════════════════
@st.cache_data(show_spinner=False)
def load_csv(raw: bytes | str | Path) -> pd.DataFrame:
    try:
        if isinstance(raw, bytes):
            df = pd.read_csv(io.BytesIO(raw))
        else:
            df = pd.read_csv(raw)
        df.columns = df.columns.str.strip().str.lower()
        df["severity"] = df["severity"].astype(str).str.upper().str.strip()
        df["cvss"]     = pd.to_numeric(df.get("cvss", pd.Series(dtype=float)), errors="coerce")
        df["host"]     = df["host"].astype(str).str.strip()
        df["plugin"]   = df.get("plugin", pd.Series(dtype=str)).astype(str).str.strip()
        return df
    except Exception as exc:
        st.error(f"CSV load error: {exc}")
        return pd.DataFrame()


@st.cache_resource(show_spinner=False)
def load_rf(path: str | Path) -> Optional[dict]:
    try:
        return joblib.load(path)
    except Exception:
        return None


@st.cache_resource(show_spinner=False)
def load_svm(path: str | Path) -> Optional[dict]:
    try:
        return joblib.load(path)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  PLOTLY THEME
# ══════════════════════════════════════════════════════════════════════════════
PLOTLY_LAYOUT = dict(
    paper_bgcolor="#080d18",
    plot_bgcolor="#080d18",
    font=dict(family="Share Tech Mono, monospace", color="#b8c8e0"),
    margin=dict(l=20, r=20, t=40, b=20),
    xaxis=dict(gridcolor="#162035", zeroline=False),
    yaxis=dict(gridcolor="#162035", zeroline=False),
)


# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK GRAPH BUILDER
# ══════════════════════════════════════════════════════════════════════════════
def build_network_graph(df: pd.DataFrame) -> go.Figure:
    if df.empty or "host" not in df.columns:
        fig = go.Figure()
        fig.update_layout(**PLOTLY_LAYOUT)
        fig.update_layout(title="No data")
        return fig

    hosts = df["host"].unique().tolist()

    def ip_sort_key(h):
        parts = str(h).split(".")
        try:
            return tuple(int(p) for p in parts)
        except ValueError:
            return (999,)

    gateway = min(hosts, key=ip_sort_key)

    G = nx.Graph()
    G.add_node("SCANNER", node_type="scanner")
    G.add_node(gateway, node_type="gateway")
    G.add_edge("SCANNER", gateway, weight=1)

    host_stats: dict[str, dict] = {}
    for host in hosts:
        hdf = df[df["host"] == host]
        risk_val = hdf["rf_prob_high"].mean() if "rf_prob_high" in hdf else 0.3
        dominant = (
            hdf["rf_risk"].value_counts().idxmax()
            if "rf_risk" in hdf.columns and not hdf.empty
            else "LOW"
        )
        vuln_count = len(hdf)
        sev_counts = hdf["severity"].value_counts().to_dict() if "severity" in hdf else {}
        host_stats[host] = {
            "risk_prob": risk_val,
            "dominant":  dominant,
            "vuln_count": vuln_count,
            "sev_counts": sev_counts,
        }
        ntype = "gateway" if host == gateway else "host"
        G.add_node(host, node_type=ntype)
        G.add_edge(gateway, host, weight=vuln_count)

    pos = nx.spring_layout(G, seed=42, k=2.2)

    edge_x, edge_y = [], []
    edge_label_x, edge_label_y, edge_label_text = [], [], []
    for u, v, edata in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]
        edge_label_x.append((x0 + x1) / 2)
        edge_label_y.append((y0 + y1) / 2)
        w = edata.get("weight", 1)
        edge_label_text.append(f"{w} vuln{'s' if w != 1 else ''}")

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=1.2, color="#1e3055"),
        hoverinfo="none",
    )
    edge_lbl_trace = go.Scatter(
        x=edge_label_x, y=edge_label_y,
        mode="text",
        text=edge_label_text,
        textfont=dict(size=9, color="#4a6080"),
        hoverinfo="none",
    )

    node_traces = []
    for node in G.nodes():
        x, y = pos[node]
        ntype = G.nodes[node].get("node_type", "host")

        if ntype == "scanner":
            color, size, symbol = "#00e5ff", 28, "hexagram"
            label = "SCANNER"
            hover = "<b>VULCAN SCANNER</b><br>Origin node"
        elif ntype == "gateway":
            stats  = host_stats.get(node, {})
            dom    = stats.get("dominant", "LOW")
            color  = RISK_COLOR.get(dom, "#00ff88")
            size   = 26
            symbol = "diamond"
            sc     = stats.get("sev_counts", {})
            hover  = (
                f"<b>GATEWAY: {node}</b><br>"
                f"Vulnerabilities: {stats.get('vuln_count', 0)}<br>"
                f"AI Risk: {dom}  (P={stats.get('risk_prob', 0):.2f})<br>"
                + "<br>".join(f"  {k}: {v}" for k, v in sc.items())
            )
            label = node
        else:
            stats  = host_stats.get(node, {})
            dom    = stats.get("dominant", "LOW")
            prob   = stats.get("risk_prob", 0.3)
            color  = RISK_COLOR.get(dom, "#00ff88")
            size   = max(14, int(14 + prob * 18))
            symbol = "circle"
            sc     = stats.get("sev_counts", {})
            hover  = (
                f"<b>HOST: {node}</b><br>"
                f"Vulnerabilities: {stats.get('vuln_count', 0)}<br>"
                f"AI Risk: {dom}  (P(HIGH)={prob:.2f})<br>"
                + "<br>".join(f"  {k}: {v}" for k, v in sc.items())
            )
            label = node

        trace = go.Scatter(
            x=[x], y=[y],
            mode="markers+text",
            name=label,
            marker=dict(
                size=size,
                color=color,
                symbol=symbol,
                line=dict(width=2, color=color),
                opacity=0.92,
            ),
            text=label,
            textposition="top center",
            textfont=dict(family="Share Tech Mono", size=10, color=color),
            hovertemplate=hover + "<extra></extra>",
            showlegend=False,
        )
        node_traces.append(trace)

        if ntype == "host" and host_stats.get(node, {}).get("dominant") == "HIGH":
            halo = go.Scatter(
                x=[x], y=[y],
                mode="markers",
                marker=dict(
                    size=size + 14,
                    color="rgba(255,45,45,0.12)",
                    line=dict(width=1.5, color="rgba(255,45,45,0.4)"),
                    symbol="circle",
                ),
                hoverinfo="none",
                showlegend=False,
            )
            node_traces.append(halo)

    fig = go.Figure(data=[edge_trace, edge_lbl_trace] + node_traces)
    
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(
            text="◈ LIVE NETWORK TOPOLOGY",
            font=dict(family="Orbitron", size=14, color="#00ff88"),
            x=0.01,
        ),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        hovermode="closest",
        height=540,
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
#  GAUGE CHART — RF CONFIDENCE
# ══════════════════════════════════════════════════════════════════════════════
def build_gauge(prob_high: float, title: str = "") -> go.Figure:
    pct = prob_high * 100
    if pct >= 60:
        color, label = "#ff2d2d", "HIGH RISK"
    elif pct >= 35:
        color, label = "#ffb300", "MEDIUM RISK"
    else:
        color, label = "#00ff88", "LOW RISK"

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=round(pct, 1),
        number=dict(suffix="%", font=dict(family="Orbitron", size=28, color=color)),
        title=dict(
            text=f"<b style='color:#b8c8e0;font-family:Share Tech Mono'>{title}</b>"
                 f"<br><span style='font-size:.8em;color:{color}'>{label}</span>",
            font=dict(size=11),
        ),
        delta=dict(reference=50, increasing=dict(color="#ff2d2d"), decreasing=dict(color="#00ff88")),
        gauge=dict(
            axis=dict(
                range=[0, 100],
                tickwidth=1,
                tickcolor="#162035",
                tickfont=dict(family="Share Tech Mono", size=9, color="#4a6080"),
            ),
            bar=dict(color=color, thickness=0.28),
            bgcolor="#0b1220",
            borderwidth=1,
            bordercolor="#162035",
            steps=[
                dict(range=[0, 35],  color="#001a0d"),
                dict(range=[35, 60], color="#1a1200"),
                dict(range=[60, 100], color="#1a0505"),
            ],
            threshold=dict(
                line=dict(color=color, width=3),
                thickness=0.75,
                value=pct,
            ),
        ),
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        height=260,
        margin=dict(l=30, r=30, t=60, b=20),
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
#  PROBABILITY STACKED BAR
# ══════════════════════════════════════════════════════════════════════════════
def build_prob_bar(prob_dict: dict[str, float], title: str = "") -> go.Figure:
    classes = list(prob_dict.keys())
    probs   = [prob_dict[c] * 100 for c in classes]
    palette = ["#ff2d2d", "#ff7a00", "#ffb300", "#00ff88", "#00e5ff",
               "#a78bfa", "#f472b6", "#34d399", "#60a5fa", "#fbbf24", "#818cf8"]

    fig = go.Figure()
    for i, (cls, pct) in enumerate(zip(classes, probs)):
        fig.add_trace(go.Bar(
            name=cls,
            x=[round(pct, 1)],
            y=["confidence"],
            orientation="h",
            marker=dict(
                color=palette[i % len(palette)],
                line=dict(width=0),
                opacity=0.85,
            ),
            text=f"{cls}<br>{pct:.1f}%",
            textposition="inside",
            insidetextanchor="middle",
            textfont=dict(family="Share Tech Mono", size=9, color="#060a10"),
            hovertemplate=f"<b>{cls}</b>: {pct:.1f}%<extra></extra>",
        ))

    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        barmode="stack",
        title=dict(
            text=f"<span style='font-family:Share Tech Mono;font-size:11px;color:#b8c8e0'>{title}</span>",
            x=0.0,
        ),
        xaxis=dict(range=[0, 100], showgrid=False, showticklabels=False),
        yaxis=dict(showgrid=False, showticklabels=False),
        showlegend=True,
        legend=dict(
            font=dict(family="Share Tech Mono", size=9, color="#b8c8e0"),
            bgcolor="rgba(0,0,0,0)",
            orientation="v",
        ),
        height=120,
        margin=dict(l=10, r=10, t=36, b=10),
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
#  SEVERITY DISTRIBUTION BAR
# ══════════════════════════════════════════════════════════════════════════════
def build_sev_bar(df: pd.DataFrame) -> go.Figure:
    counts = (
        df["severity"]
        .value_counts()
        .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], fill_value=0)
    )
    colors = [SEVERITY_COLOR[s] for s in counts.index]
    fig = go.Figure(go.Bar(
        x=counts.index.tolist(),
        y=counts.values.tolist(),
        marker=dict(color=colors, opacity=0.85,
                    line=dict(color=colors, width=1.5)),
        text=counts.values.tolist(),
        textposition="outside",
        textfont=dict(family="Orbitron", size=12, color="#b8c8e0"),
        hovertemplate="%{x}: %{y}<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(text="◈ SEVERITY DISTRIBUTION",
                   font=dict(family="Orbitron", size=12, color="#00ff88"), x=0.0),
        height=280,
        xaxis=dict(showgrid=False, zeroline=False),
        yaxis=dict(showgrid=True, gridcolor="#162035", zeroline=False),
        bargap=0.3,
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
#  HOST RISK SCATTER
# ══════════════════════════════════════════════════════════════════════════════
def build_host_scatter(df: pd.DataFrame) -> go.Figure:
    if df.empty:
        return go.Figure()
    host_agg = (
        df.groupby("host")
        .agg(
            vuln_count=("severity", "count"),
            avg_cvss=("cvss", "mean"),
            avg_prob_high=("rf_prob_high", "mean"),
            dominant_risk=("rf_risk", lambda x: x.value_counts().idxmax()),
        )
        .reset_index()
    )
    host_agg["avg_cvss"]     = host_agg["avg_cvss"].fillna(0).round(2)
    host_agg["avg_prob_high"] = host_agg["avg_prob_high"].fillna(0.3)
    host_agg["color"]        = host_agg["dominant_risk"].map(RISK_COLOR).fillna("#00ff88")

    fig = go.Figure(go.Scatter(
        x=host_agg["avg_cvss"],
        y=host_agg["avg_prob_high"] * 100,
        mode="markers+text",
        text=host_agg["host"],
        textposition="top center",
        textfont=dict(family="Share Tech Mono", size=9, color="#b8c8e0"),
        marker=dict(
            size=host_agg["vuln_count"] * 8 + 12,
            color=host_agg["color"],
            opacity=0.8,
            line=dict(width=1.5, color=host_agg["color"]),
        ),
        customdata=np.stack([host_agg["vuln_count"], host_agg["dominant_risk"]], axis=1),
        hovertemplate=(
            "<b>%{text}</b><br>"
            "Avg CVSS: %{x:.2f}<br>"
            "P(HIGH): %{y:.1f}%<br>"
            "Vulns: %{customdata[0]}<br>"
            "Risk: %{customdata[1]}<extra></extra>"
        ),
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_layout(
        title=dict(text="◈ HOST RISK SCATTER  (bubble size = vuln count)",
                   font=dict(family="Orbitron", size=12, color="#00ff88"), x=0.0),
        height=320,
        xaxis=dict(title="Avg CVSS Score", gridcolor="#162035"),
        yaxis=dict(title="P(HIGH RISK) %", gridcolor="#162035", range=[0, 105]),
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
#  HTML HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def kpi_card(label: str, value, color: str = "#00ff88", sub: str = "") -> str:
    return f"""
    <div class="kpi-card" style="--kpi-color:{color}">
      <div class="kpi-label">{label}</div>
      <div class="kpi-value">{value}</div>
      {"" if not sub else f'<div class="kpi-sub">{sub}</div>'}
    </div>"""


def sev_badge(s: str) -> str:
    s = str(s).upper()
    return f'<span class="sev sev-{s}">{s}</span>'


def risk_span(r: str) -> str:
    r = str(r).upper()
    return f'<span class="risk-{r}">{r}</span>'


def sec_label(text: str) -> None:
    st.markdown(f'<p class="sec-label">{text}</p>', unsafe_allow_html=True)


def remed_card(title: str, steps: list[str], refs: list[str],
               priority: str = "MEDIUM") -> str:
    p_color = {"HIGH": "#ff2d2d", "MEDIUM": "#ffb300", "LOW": "#00ff88"}.get(priority, "#ffb300")
    steps_html = "".join(f"<li style='margin:.3rem 0;color:#b8c8e0'>{s}</li>" for s in steps)
    refs_html  = " · ".join(
        f"<span style='color:#4a6080;font-size:.75rem'>{r}</span>" for r in refs
    )
    return f"""
    <div class="remed-card" style="--remed-color:{p_color}">
      <div class="remed-title">⬡ {title}
        <span style="float:right;font-size:.7rem;color:{p_color}">Priority: {priority}</span>
      </div>
      <ol style="margin:.4rem 0 .6rem 1.2rem;padding:0;font-size:.82rem">{steps_html}</ol>
      <div>{refs_html}</div>
    </div>"""


# ══════════════════════════════════════════════════════════════════════════════
#  ── SIDEBAR ─────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(
        """
        <div style="padding:.3rem 0 1rem">
          <div style="font-family:'Orbitron',monospace;font-size:1.1rem;font-weight:900;
                      color:#00ff88;text-shadow:0 0 20px rgba(0,255,136,.6);letter-spacing:.05em;line-height:1.2;">
            ⬡ VULNERABILITY SCANNER<br>&nbsp;&nbsp;USING AI
          </div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.62rem;
                      color:#4a6080;letter-spacing:.18em;text-transform:uppercase;margin-top:.4rem;">
            TM471 Graduation Project
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "<p style='font-family:Share Tech Mono;font-size:.65rem;color:#4a6080;"
        "letter-spacing:.14em;text-transform:uppercase;'>◈ DATA INPUT</p>",
        unsafe_allow_html=True,
    )

    up_csv = st.file_uploader("Scan CSV", type=["csv"],
                               help="report_from_scan_transfer_to_ai.csv")
    use_demo_csv = st.checkbox("Use demo scan data", value=True)

    st.markdown(
        "<p style='font-family:Share Tech Mono;font-size:.65rem;color:#4a6080;"
        "letter-spacing:.14em;text-transform:uppercase;margin-top:.8rem;'>◈ ML MODELS</p>",
        unsafe_allow_html=True,
    )
    up_rf  = st.file_uploader("RF Pipeline (.pkl)",  type=["pkl"])
    up_svm = st.file_uploader("SVM Classifier (.pkl)", type=["pkl"])
    use_demo_models = st.checkbox("Use bundled models", value=True)

    st.markdown(
        "<p style='font-family:Share Tech Mono;font-size:.65rem;color:#4a6080;"
        "letter-spacing:.14em;text-transform:uppercase;margin-top:.8rem;'>◈ FILTERS</p>",
        unsafe_allow_html=True,
    )
    filter_sev = st.multiselect(
        "Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    )
    filter_risk = st.multiselect(
        "AI Risk",
        ["HIGH", "MEDIUM", "LOW"],
        default=["HIGH", "MEDIUM", "LOW"],
    )

    host_filter_placeholder = st.empty()

    st.markdown("---")
    st.markdown(
        f"<div style='font-family:Share Tech Mono;font-size:.62rem;color:#162035;'>"
        f"SCAN TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>",
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  RESOLVE SOURCES
# ══════════════════════════════════════════════════════════════════════════════
if up_csv:
    raw_df = load_csv(up_csv.read())
elif use_demo_csv and DEFAULT_CSV.exists():
    raw_df = load_csv(DEFAULT_CSV)
else:
    raw_df = pd.DataFrame(columns=["host", "severity", "name", "plugin", "cvss", "description"])

if up_rf:
    _rf_tmp = Path("/tmp/rf_up.pkl")
    _rf_tmp.write_bytes(up_rf.read())
    rf_bundle = load_rf(_rf_tmp)
elif use_demo_models and DEFAULT_RF.exists():
    rf_bundle = load_rf(DEFAULT_RF)
else:
    rf_bundle = None

if up_svm:
    _svm_tmp = Path("/tmp/svm_up.pkl")
    _svm_tmp.write_bytes(up_svm.read())
    svm_bundle = load_svm(_svm_tmp)
elif use_demo_models and DEFAULT_SVM.exists():
    svm_bundle = load_svm(DEFAULT_SVM)
else:
    svm_bundle = None


# ══════════════════════════════════════════════════════════════════════════════
#  ENRICH DATA
# ══════════════════════════════════════════════════════════════════════════════
if not raw_df.empty:
    with st.spinner("Running ML inference …"):
        df_full = enrich_df(raw_df, rf_bundle)
else:
    df_full = pd.DataFrame()

if not df_full.empty and "host" in df_full.columns:
    all_hosts = sorted(df_full["host"].unique().tolist())
    filter_host = host_filter_placeholder.multiselect(
        "Host IP", all_hosts, default=all_hosts
    )
else:
    filter_host = []
    host_filter_placeholder.empty()

if not df_full.empty:
    df_view = df_full.copy()
    if filter_sev:
        df_view = df_view[df_view["severity"].isin(filter_sev)]
    if filter_risk:
        df_view = df_view[df_view["rf_risk"].isin(filter_risk)]
    if filter_host:
        df_view = df_view[df_view["host"].isin(filter_host)]
else:
    df_view = df_full.copy()


# ══════════════════════════════════════════════════════════════════════════════
#  HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:1.2rem;border-bottom:1px solid #162035;padding-bottom:.8rem;">
      <span class="term-header" style="font-size:1.6rem;">
        ⬡ BUILD VULNERABILITY SCANNER USING AI
      </span>
      <span style="font-family:'Share Tech Mono',monospace;font-size:.72rem;
                   color:#4a6080;margin-left:1.2rem;">
        RF + SVM ENSEMBLE PIPELINE
      </span>
    </div>
    """,
    unsafe_allow_html=True,
)

if df_full.empty:
    st.markdown(
        """
        <div style="background:#0b1220;border:1px dashed #1e3055;border-radius:4px;
                    padding:2rem;text-align:center;font-family:'Share Tech Mono',monospace;
                    color:#4a6080;letter-spacing:.1em;">
          ◈ NO SCAN DATA LOADED<br>
          <span style='font-size:.75rem'>Upload a CSV in the sidebar or check that
          report_from_scan_transfer_to_ai.csv exists next to this script.</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  KPI ROW
# ══════════════════════════════════════════════════════════════════════════════
total_hosts    = df_view["host"].nunique() if "host" in df_view else 0
total_vulns    = len(df_view)
critical_count = int((df_view["severity"] == "CRITICAL").sum())
high_count     = int((df_view["rf_risk"] == "HIGH").sum())
avg_risk_score = df_view["composite"].mean() if "composite" in df_view else 0.0
avg_prob_high  = df_view["rf_prob_high"].mean() if "rf_prob_high" in df_view else 0.0

kpi_html = (
    '<div class="kpi-row">'
    + kpi_card("Hosts Scanned",    total_hosts,       "#00e5ff",
               sub=f"{len(df_full['host'].unique())} total in dataset")
    + kpi_card("Total Findings",   total_vulns,       "#00ff88",
               sub="after active filters")
    + kpi_card("Critical Alerts",  critical_count,    "#ff2d2d",
               sub="CVSS severity = CRITICAL")
    + kpi_card("AI High-Risk",     high_count,        "#ff7a00",
               sub=f"RF model P(HIGH) avg {avg_prob_high*100:.0f}%")
    + kpi_card("Composite Score",  f"{avg_risk_score:.1f}",  "#ffb300",
               sub="weighted sev + rf_risk")
    + kpi_card("RF Model",  "LOADED" if rf_bundle else "OFF",
               "#00ff88" if rf_bundle else "#4a6080",
               sub="Vulcan_RF_Pipeline_Final")
    + "</div>"
)
st.markdown(kpi_html, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  TABS
# ══════════════════════════════════════════════════════════════════════════════
tab_net, tab_ml, tab_remed = st.tabs([
    "  ◈  LIVE NETWORK MAP  ",
    "  ◈  DEEP ML ANALYSIS  ",
    "  ◈  REMEDIATION PLANNER  ",
])


# ════════════════════════════════════════════════════════════════════════════
#  TAB 1 — LIVE NETWORK MAP
# ════════════════════════════════════════════════════════════════════════════
with tab_net:
    col_graph, col_right = st.columns([3, 1], gap="large")

    with col_graph:
        sec_label("INTERACTIVE TOPOLOGY GRAPH")
        with st.spinner("Generating network graph …"):
            fig_net = build_network_graph(df_view)
        st.plotly_chart(fig_net, use_container_width=True, config={"displayModeBar": False})

        st.markdown(
            """
            <div style="display:flex;gap:1.6rem;font-family:'Share Tech Mono',monospace;
                        font-size:.7rem;padding:.4rem 0;border-top:1px solid #162035;">
              <span>◈ <span style='color:#00e5ff'>CYAN HEX</span> = Scanner origin</span>
              <span>◈ <span style='color:#ff2d2d'>RED diamond</span> = Gateway (high risk)</span>
              <span>◈ <span style='color:#ffb300'>AMBER circle</span> = Host (medium risk)</span>
              <span>◈ <span style='color:#00ff88'>GREEN circle</span> = Host (low risk)</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_right:
        sec_label("SEVERITY BREAKDOWN")
        st.plotly_chart(build_sev_bar(df_view), use_container_width=True,
                        config={"displayModeBar": False})

        sec_label("HOST RANKING")
        if not df_view.empty:
            host_rank = (
                df_view.groupby("host")
                .agg(vulns=("severity", "count"), p_high=("rf_prob_high", "mean"))
                .sort_values("p_high", ascending=False)
                .reset_index()
            )
            for _, r in host_rank.iterrows():
                risk_lbl = "HIGH" if r["p_high"] >= 0.6 else ("MEDIUM" if r["p_high"] >= 0.35 else "LOW")
                col_bar = RISK_COLOR.get(risk_lbl, "#00ff88")
                pct = r["p_high"] * 100
                st.markdown(
                    f"""
                    <div style="margin:.3rem 0;font-family:'Share Tech Mono',monospace;">
                      <div style="display:flex;justify-content:space-between;
                                  font-size:.72rem;margin-bottom:.2rem;">
                        <span style="color:{col_bar}">{r['host']}</span>
                        <span style="color:#4a6080">{int(r['vulns'])} vulns</span>
                      </div>
                      <div style="background:#0b1220;border-radius:2px;height:6px;">
                        <div style="width:{pct:.0f}%;height:100%;background:{col_bar};
                                    border-radius:2px;transition:width .6s"></div>
                      </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    sec_label("HOST RISK SCATTER")
    st.plotly_chart(build_host_scatter(df_view), use_container_width=True,
                    config={"displayModeBar": False})

    sec_label("ACTIVE FINDINGS")
    disp_cols = [c for c in ["host", "severity", "name", "plugin", "cvss",
                              "rf_risk", "rf_prob_high", "composite"] if c in df_view.columns]
    sorted_view = df_view[disp_cols].sort_values(
        "severity", key=lambda s: s.map(SEVERITY_ORDER).fillna(99)
    )
    st.dataframe(
        sorted_view.style.format({"rf_prob_high": "{:.2%}", "composite": "{:.2f}",
                                   "cvss": lambda x: f"{x:.1f}" if pd.notna(x) else "N/A"}),
        use_container_width=True,
        height=320,
        hide_index=True,
    )

    csv_out = sorted_view.to_csv(index=False).encode()
    st.download_button(
        "⬇  EXPORT FILTERED CSV",
        data=csv_out,
        file_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
        mime="text/csv",
    )


# ════════════════════════════════════════════════════════════════════════════
#  TAB 2 — DEEP ML ANALYSIS
# ════════════════════════════════════════════════════════════════════════════
with tab_ml:
    col_sel, col_gauge = st.columns([1, 1], gap="large")

    with col_sel:
        sec_label("SELECT FINDING FOR DEEP ANALYSIS")

        if df_view.empty:
            st.info("No findings match active filters.")
        else:
            row_labels = [
                f"[{r['host']}]  {str(r.get('name',''))[:55]}  (CVSS {r['cvss'] if pd.notna(r['cvss']) else 'N/A'})"
                for _, r in df_view.iterrows()
            ]
            selected_idx = st.selectbox(
                "Finding", range(len(row_labels)),
                format_func=lambda i: row_labels[i],
                label_visibility="collapsed",
            )
            sel_row = df_view.iloc[selected_idx]

            sev_col = SEVERITY_COLOR.get(str(sel_row.get("severity","INFO")).upper(), "#4a6080")
            st.markdown(
                f"""
                <div style="background:#0b1220;border:1px solid #162035;border-left:3px solid {sev_col};
                            border-radius:3px;padding:1rem;margin-top:.8rem;
                            font-family:'Share Tech Mono',monospace;font-size:.78rem;line-height:1.9;">
                  <div style="color:{sev_col};margin-bottom:.4rem;text-transform:uppercase;
                              letter-spacing:.1em;font-size:.7rem;">◈ FINDING DETAILS</div>
                  <b style="color:#b8c8e0">Host&nbsp;&nbsp;&nbsp;:</b> {sel_row.get('host','N/A')}<br>
                  <b style="color:#b8c8e0">Severity:</b> {sev_badge(str(sel_row.get('severity','INFO')))}<br>
                  <b style="color:#b8c8e0">Plugin&nbsp; :</b> {sel_row.get('plugin','N/A')}<br>
                  <b style="color:#b8c8e0">CVSS&nbsp;&nbsp;&nbsp;:</b>
                    <span style="color:{sev_col}">{sel_row['cvss'] if pd.notna(sel_row.get('cvss')) else 'N/A'}</span><br>
                  <b style="color:#b8c8e0">AI Risk&nbsp;:</b> {risk_span(sel_row.get('rf_risk','LOW'))}<br>
                  <b style="color:#b8c8e0">Desc&nbsp;&nbsp;&nbsp;:</b>
                    <span style="color:#4a6080">{str(sel_row.get('description',''))}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with col_gauge:
        if not df_view.empty:
            sec_label("RF MODEL — CONFIDENCE GAUGE  (predict_proba)")
            prob_high = float(sel_row.get("rf_prob_high", 0.3))
            prob_low  = float(sel_row.get("rf_prob_low",  0.7))
            gauge_title = f"P(HIGH RISK) for {sel_row.get('host','')}"
            st.plotly_chart(
                build_gauge(prob_high, gauge_title),
                use_container_width=True,
                config={"displayModeBar": False},
            )
            st.markdown(
                f"""
                <div style="display:flex;gap:1rem;font-family:'Share Tech Mono',monospace;
                            font-size:.72rem;justify-content:center;margin-top:.2rem;">
                  <span style="color:#ff2d2d">P(HIGH) = {prob_high*100:.1f}%</span>
                  <span style="color:#4a6080">|</span>
                  <span style="color:#00ff88">P(LOW) = {prob_low*100:.1f}%</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

    sec_label("RF PROBABILITY DISTRIBUTION — ALL FINDINGS")
    if not df_view.empty:
        col_prob_bar, col_conf_table = st.columns([3, 2], gap="large")

        with col_prob_bar:
            sorted_probs = df_view.sort_values("rf_prob_high", ascending=True).tail(20)
            short_labels = [
                f"{r['host']} / {str(r.get('name',''))[:30]}…"
                for _, r in sorted_probs.iterrows()
            ]
            colors = [RISK_COLOR.get(r, "#00ff88") for r in sorted_probs["rf_risk"]]

            fig_hbar = go.Figure()
            fig_hbar.add_trace(go.Bar(
                y=short_labels,
                x=(sorted_probs["rf_prob_high"] * 100).round(1).tolist(),
                orientation="h",
                name="P(HIGH)",
                marker=dict(color=colors, opacity=0.85,
                            line=dict(color=colors, width=1)),
                text=(sorted_probs["rf_prob_high"] * 100).round(1).astype(str) + "%",
                textposition="outside",
                textfont=dict(family="Share Tech Mono", size=9, color="#b8c8e0"),
                hovertemplate="%{y}<br>P(HIGH): %{x:.1f}%<extra></extra>",
            ))
            fig_hbar.update_layout(**PLOTLY_LAYOUT)
            fig_hbar.update_layout(
                title=dict(
                    text="◈ P(HIGH RISK) per finding — top 20  [predict_proba]",
                    font=dict(family="Orbitron", size=11, color="#00ff88"), x=0.0,
                ),
                height=max(300, len(short_labels) * 22 + 60),
                xaxis=dict(range=[0, 115], showgrid=False, showticklabels=False),
                yaxis=dict(showgrid=False, tickfont=dict(size=9)),
                bargap=0.25,
                margin=dict(l=10, r=50, t=50, b=10),
            )
            st.plotly_chart(fig_hbar, use_container_width=True, config={"displayModeBar": False})

        with col_conf_table:
            sec_label("CONFIDENCE SUMMARY TABLE")
            conf_df = df_view[["host", "severity", "rf_risk", "rf_prob_high",
                                "rf_prob_low", "composite"]].copy()
            conf_df["rf_prob_high"] = (conf_df["rf_prob_high"] * 100).round(1)
            conf_df["rf_prob_low"]  = (conf_df["rf_prob_low"]  * 100).round(1)
            conf_df = conf_df.rename(columns={
                "rf_prob_high": "P(HIGH) %",
                "rf_prob_low":  "P(LOW) %",
                "rf_risk":      "AI Risk",
                "composite":    "Score",
            })
            conf_df = conf_df.sort_values("P(HIGH) %", ascending=False)
            st.dataframe(conf_df, use_container_width=True, height=380, hide_index=True)

    sec_label("SVM PAYLOAD CLASSIFIER — ATTACK-TYPE ANALYSIS")
    sv_col1, sv_col2 = st.columns([1, 1], gap="large")

    with sv_col1:
        st.markdown(
            """
            <div style="font-family:'Share Tech Mono',monospace;font-size:.72rem;
                        color:#4a6080;margin-bottom:.6rem;">
              Enter any payload or description to classify the attack type.
              Model: LinearSVC — TF-IDF char n-gram (3-5).<br>
              Decision confidence via softmax on decision_function scores.
            </div>
            """,
            unsafe_allow_html=True,
        )
        payload_txt = st.text_area(
            "Payload", height=90,
            placeholder="' OR '1'='1  |  <script>alert(1)</script>  |  ../../../etc/passwd",
            label_visibility="collapsed",
        )
        classify_btn = st.button("⬡  CLASSIFY PAYLOAD", use_container_width=True)

        if classify_btn and payload_txt.strip():
            if svm_bundle is None:
                st.warning("SVM model not loaded.")
            else:
                pred_cls, prob_cls = svm_predict_row(payload_txt, svm_bundle)
                top3 = sorted(prob_cls.items(), key=lambda x: x[1], reverse=True)[:3]
                palette = ["#00ff88", "#ffb300", "#4a6080"]
                st.markdown(
                    f"""
                    <div style="background:#0b1220;border:1px solid #162035;
                                border-top:2px solid #00ff88;border-radius:3px;
                                padding:1rem;margin-top:.6rem;">
                      <div style="font-family:'Share Tech Mono',monospace;font-size:.65rem;
                                  color:#4a6080;letter-spacing:.14em;text-transform:uppercase;">
                        ◈ CLASSIFICATION RESULT
                      </div>
                      <div style="font-family:'Orbitron',monospace;font-size:1.4rem;
                                  font-weight:900;color:#00ff88;margin:.4rem 0;">
                        {pred_cls.upper()}
                      </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                top_dict = dict(top3)
                st.plotly_chart(
                    build_prob_bar(top_dict, "TOP-3 CLASS DECISION CONFIDENCE (softmax)"),
                    use_container_width=True,
                    config={"displayModeBar": False},
                )

    with sv_col2:
        sec_label("BATCH CLASSIFICATION")
        if svm_bundle is not None and not df_view.empty:
            if st.button("⬡  RUN SVM ON ALL FINDINGS", use_container_width=True):
                with st.spinner("Classifying all descriptions …"):
                    svm_preds, svm_confs = [], []
                    for _, r in df_view.iterrows():
                        txt = str(r.get("description", ""))
                        cls, probs = svm_predict_row(txt, svm_bundle)
                        svm_preds.append(cls)
                        svm_confs.append(max(probs.values()) * 100)
                batch_df = df_view[["host", "severity", "name", "description"]].copy()
                batch_df["svm_class"]      = svm_preds
                batch_df["svm_confidence"] = [f"{c:.1f}%" for c in svm_confs]
                st.dataframe(batch_df, use_container_width=True, height=340, hide_index=True)

                cls_counts = pd.Series(svm_preds).value_counts()
                pal = ["#00ff88","#ffb300","#ff2d2d","#00e5ff","#a78bfa",
                       "#f472b6","#34d399","#60a5fa","#fbbf24","#818cf8","#ff7a00"]
                fig_cls = go.Figure(go.Bar(
                    x=cls_counts.index.tolist(),
                    y=cls_counts.values.tolist(),
                    marker=dict(color=pal[:len(cls_counts)], opacity=0.85),
                    text=cls_counts.values.tolist(),
                    textposition="outside",
                    textfont=dict(family="Share Tech Mono", size=9, color="#b8c8e0"),
                ))
                fig_cls.update_layout(**PLOTLY_LAYOUT)
                fig_cls.update_layout(
                    title=dict(text="◈ SVM CLASS DISTRIBUTION",
                               font=dict(family="Orbitron", size=11, color="#00ff88"), x=0),
                    height=240, bargap=0.3,
                    xaxis=dict(showgrid=False),
                    yaxis=dict(showgrid=True, gridcolor="#162035"),
                )
                st.plotly_chart(fig_cls, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown(
                "<div style='font-family:Share Tech Mono;font-size:.72rem;color:#4a6080;'>"
                "Load the SVM .pkl model to enable batch classification.</div>",
                unsafe_allow_html=True,
            )


# ════════════════════════════════════════════════════════════════════════════
#  TAB 3 — REMEDIATION PLANNER
# ════════════════════════════════════════════════════════════════════════════
with tab_remed:
    sec_label("AUTOMATED REMEDIATION PLAN")

    if df_view.empty:
        st.info("No findings loaded.")
    else:
        remed_queue: list[dict] = []
        seen_plugins: set[str] = set()

        for _, row in df_view.sort_values(
            "severity", key=lambda s: s.map(SEVERITY_ORDER).fillna(99)
        ).iterrows():
            plugin = str(row.get("plugin", "DEFAULT")).strip()
            name   = str(row.get("name", ""))
            if plugin in seen_plugins:
                continue
            seen_plugins.add(plugin)
            rdb = get_remediation(plugin, name)
            remed_queue.append({
                "host":     row.get("host", ""),
                "severity": str(row.get("severity", "INFO")).upper(),
                "name":     name,
                "plugin":   plugin,
                "cvss":     row.get("cvss"),
                "rf_risk":  row.get("rf_risk", "LOW"),
                "remed":    rdb,
            })

        prio_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in remed_queue:
            p = item["remed"].get("priority", "MEDIUM")
            prio_counts[p] = prio_counts.get(p, 0) + 1

        rc1, rc2, rc3, rc4 = st.columns(4)
        rc1.metric("Unique Findings", len(remed_queue))
        rc2.metric("🔴 High Priority",   prio_counts["HIGH"])
        rc3.metric("🟡 Medium Priority", prio_counts["MEDIUM"])
        rc4.metric("🔵 Low Priority",    prio_counts["LOW"])

        remed_filter = st.multiselect(
            "Filter by remediation priority",
            ["HIGH", "MEDIUM", "LOW"],
            default=["HIGH", "MEDIUM", "LOW"],
            label_visibility="visible",
        )

        sec_label("REMEDIATION STEPS")
        for item in remed_queue:
            rdb = item["remed"]
            priority = rdb.get("priority", "MEDIUM")
            if priority not in remed_filter:
                continue

            p_color = {"HIGH": "#ff2d2d", "MEDIUM": "#ffb300", "LOW": "#00e5ff"}.get(
                priority, "#ffb300"
            )
            sev_c = SEVERITY_COLOR.get(item["severity"], "#4a6080")
            cvss_str = f"{item['cvss']:.1f}" if pd.notna(item.get("cvss")) else "N/A"

            with st.expander(
                f"[Plugin {item['plugin']}]  {rdb['title']}  —  Priority: {priority}",
                expanded=(priority == "HIGH"),
            ):
                st.markdown(
                    f"""
                    <div style="display:flex;gap:2rem;font-family:'Share Tech Mono',monospace;
                                font-size:.72rem;color:#4a6080;margin-bottom:.8rem;
                                padding-bottom:.6rem;border-bottom:1px solid #162035;">
                      <span>HOST: <span style='color:#b8c8e0'>{item['host']}</span></span>
                      <span>PLUGIN: <span style='color:{sev_c}'>{item['plugin']}</span></span>
                      <span>SEVERITY: {sev_badge(item['severity'])}</span>
                      <span>CVSS: <span style='color:{sev_c}'>{cvss_str}</span></span>
                      <span>AI RISK: {risk_span(item['rf_risk'])}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div style='font-family:Share Tech Mono;font-size:.75rem;"
                    f"color:#b8c8e0;margin-bottom:.8rem;'>{item['name']}</div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    remed_card(
                        rdb["title"],
                        rdb["steps"],
                        rdb.get("refs", []),
                        priority,
                    ),
                    unsafe_allow_html=True,
                )

        st.markdown("---")
        sec_label("EXPORT REMEDIATION PLAN")
        plan_rows = []
        for item in remed_queue:
            rdb = item["remed"]
            for i, step in enumerate(rdb["steps"], 1):
                plan_rows.append({
                    "Priority":    rdb.get("priority", "MEDIUM"),
                    "Host":        item["host"],
                    "Plugin":      item["plugin"],
                    "Severity":    item["severity"],
                    "CVSS":        item["cvss"],
                    "AI Risk":     item["rf_risk"],
                    "Vuln Name":   item["name"],
                    "Remed Title": rdb["title"],
                    "Step #":      i,
                    "Step":        step,
                    "References":  "; ".join(rdb.get("refs", [])),
                })
        plan_df = pd.DataFrame(plan_rows)
        plan_csv = plan_df.to_csv(index=False).encode()
        st.download_button(
            "⬇  EXPORT FULL REMEDIATION PLAN (CSV)",
            data=plan_csv,
            file_name=f"remediation_plan_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            use_container_width=False,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-top:2.5rem;padding-top:.8rem;border-top:1px solid #162035;
                font-family:'Share Tech Mono',monospace;font-size:.62rem;color:#162035;
                display:flex;justify-content:space-between;">
      <span>BUILD VULNERABILITY SCANNER USING AI  ·  GRADUATION PROJECT</span>
      <span>⚠ AUTHORISED USE ONLY — SCAN ONLY NETWORKS YOU OWN OR HAVE EXPLICIT PERMISSION FOR</span>
    </div>
    """,
    unsafe_allow_html=True,
)
