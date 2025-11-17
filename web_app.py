#!/usr/bin/env python3
"""
StoltzCo SmartBuild Web App
- Local-first Flask service bridging SmartBuild's API with internal workflow tools
- Endpoints: / (home), /create, /outputs, /healthz
- Minimal deps: Flask, requests, python-dotenv, waitress
- Dry-run friendly: SMARTBUILD_TESTING_MODE=true simulates API calls
"""

import io
import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from flask import (
    Flask, flash, redirect, render_template_string, request, send_file, url_for
)
import requests

# ---------- Bootstrap ----------
load_dotenv(override=False)

APP_NAME = "StoltzCo SmartBuild Bridge • v0.2"
OUT_DIR = Path("out/outputs")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SMARTBUILD_BASE_URL = os.getenv("SMARTBUILD_BASE_URL", "https://postframesolver.azurewebsites.net")
SMARTBUILD_USERNAME = os.getenv("SMARTBUILD_USERNAME", "")
SMARTBUILD_PASSWORD = os.getenv("SMARTBUILD_PASSWORD", "")
SMARTBUILD_TEMPLATE_ID = os.getenv("SMARTBUILD_TEMPLATE_ID", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
TESTING_MODE = os.getenv("SMARTBUILD_TESTING_MODE", "false").lower() in ("1", "true", "yes")
APP_PORT = int(os.getenv("APP_PORT", "8080"))
# --- Simple Auth ---
ALLOWED_USERS = [u.strip().lower() for u in os.getenv("ALLOWED_USERS", "").split(",") if u.strip()]
REQUIRE_LOGIN = (os.getenv("REQUIRE_LOGIN", "true").lower() in ("1","true","yes"))

# Flask config
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-not-secret")  # replace in prod

# Logging: stdout, PowerShell-friendly, no colors
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ\t%(levelname)s\t%(name)s\t%(message)s",
)
log = logging.getLogger("smartbuild.web")

# ----------- Job Info ---------------
JOBINFO_JSON = Path("job_info.json")

def _load_job_info():
    data = _load_json_file(JOBINFO_JSON) or {}
    return {
        "sales_reps": data.get("sales_reps", []),
        "project_managers": data.get("project_managers", []),
        "ops_managers": data.get("ops_managers", []),
        "follow_up_types": data.get("follow_up_types", []),
        "defaults": data.get("defaults", {})
    }

# ----------- Helpers ---------------
def _slug(s: str) -> str:
    s = re.sub(r"[^\w\s.-]", "", s)
    s = re.sub(r"\s+", "-", s.strip())
    return s[:160] or "file"

def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def _load_json_file(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def _normalize_project_item(it: dict) -> dict:
    # Per GetProjectList docs: JobId, Name, Status, UserName, ...
    return {
        "JobId": str(it.get("JobId") or it.get("Id") or it.get("JobID") or ""),
        "Project": it.get("Name") or it.get("Project") or it.get("ProjectName") or it.get("Title") or "None",
        "CustomerName": it.get("CustomerName") or it.get("Customer") or it.get("Client") or it.get("UserName") or "",
    }

import difflib

def _client_side_filter(projects: List[Dict[str, Any]], needle: str) -> List[Dict[str, Any]]:
    if not needle:
        return projects
    n = (needle or "").strip().lower()
    # direct substring match across common fields
    base = []
    for p in projects:
        hay = f"{p.get('Project','')} {p.get('CustomerName','')} {p.get('JobId','')}".lower()
        if n in hay:
            base.append(p)
    if base:
        return base
    # fuzzy fallback on Project name only (keeps false-positives low)
    names = [p.get("Project","") for p in projects]
    close = set(difflib.get_close_matches(needle, names, n=10, cutoff=0.7))
    return [p for p in projects if p.get("Project","") in close]

def _normalize_outputters(items):
    """
    SmartBuild OutputterVM -> {Id, Name, Group, Slot}
    Docs: Slot (int), Group ("PDF Sections" or ""), Description (string), IsSelected (bool)
    """
    out = []
    for it in items or []:
        if isinstance(it, dict):
            slot = it.get("Slot")
            desc = (it.get("Description") or "").strip()
            group = (it.get("Group") or "").strip()
            if slot is not None:
                out.append({"Id": str(slot), "Slot": int(slot), "Name": desc or f"Output {slot}", "Group": group})
            else:
                out.append({"Id": str(it.get("Id") or "Unknown"), "Slot": None, "Name": desc or it.get("Name") or "Output", "Group": group})
        elif isinstance(it, str):
            out.append({"Id": it, "Slot": None, "Name": it, "Group": ""})
    return out

def _is_name_allowed(name: str) -> bool:
    if not ALLOWED_USERS:
        return True  # no list configured -> allow any name
    return name.strip().lower() in ALLOWED_USERS

# ---------- SmartBuildClient ----------
class SmartBuildError(Exception):
    pass

class SmartBuildClient:
    """
    Explicit client for SmartBuild API V2
    Implements:
      - login() -> OAuth2 token
      - get_version(), test()
      - get_project_list(filter, offset, count, user, status)
      - set_job_data_model(payload)
      - get_outputters(job_id)
      - get_outputs(job_id, slot) -> (bytes, headers)
      - get_outputs_multi(job_id, [slots]) -> (bytes, headers)
    Retries login on 401/403 once.
    """
    def __init__(self, base_url: str, username: str, password: str, testing: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.testing = testing
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"StoltzCoBridge/1.0"})
        self._token: Optional[str] = None
        self._token_ts: float = 0.0

    # ----- Public API -----
    def login(self) -> None:
        if self.testing:
            # Simulated token
            self._token = "TEST_TOKEN"
            self._token_ts = time.time()
            log.info("login(dry-run)=ok")
            return

        url = f"{self.base_url}/token"
        data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }
        try:
            r = self.session.post(url, data=data, timeout=20)
            r.raise_for_status()
            tok = r.json()
            self._token = tok.get("access_token")
            self._token_ts = time.time()
            if not self._token:
                raise SmartBuildError("No access_token in login response")
            self.session.headers.update({"Authorization": f"Bearer {self._token}"})
            log.info("login=ok")
        except requests.HTTPError as e:
            raise SmartBuildError(f"login_http_error: {e} body={e.response.text if e.response else ''}")
        except Exception as e:
            raise SmartBuildError(f"login_error: {e}")

    def get_version(self) -> Dict[str, Any]:
        return self._get_json("/api/V2/GetVersion")

    def test(self) -> Dict[str, Any]:
        return self._get_json("/api/V2/Test")

    def get_starting_models(self) -> List[Dict[str, Any]]:
        data = self._get_json("/api/V2/GetStartingModels")  # returns [{Id, Name, Iso1Link, Iso2Link}, ...]
        items = []
        for it in data if isinstance(data, list) else []:
            items.append({
                "Id": it.get("Id"),
                "Name": it.get("Name"),
                "Iso1Link": it.get("Iso1Link"),
                "Iso2Link": it.get("Iso2Link"),
            })
        return items

    def get_project_list(self, filter_text: str = "", offset: int = 0, count: int = 50,
                         user: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns a normalized dict: {"Projects": [...], "Count": int}
        Tries multiple param combos on 403, since some tenants require user/status.
        """
        def _normalize(resp: Any) -> Dict[str, Any]:
            if isinstance(resp, dict):
                projects = resp.get("Projects") or resp.get("projects") or []
                if isinstance(projects, list):
                    return {"Projects": projects, "Count": len(projects)}
                if resp and "JobId" in resp:
                    return {"Projects": [resp], "Count": 1}
                return {"Projects": [], "Count": 0}
            elif isinstance(resp, list):
                return {"Projects": resp, "Count": len(resp)}
            else:
                return {"Projects": [], "Count": 0}

        attempts: List[Tuple[Dict[str, Any], str]] = [
            ({"offset": offset, "count": count, **({"filter": filter_text} if filter_text else {})}, "minimal"),
            ({"offset": offset, "count": count, **({"filter": filter_text} if filter_text else {}), "status": "Active"}, "status_active"),
            ({"offset": offset, "count": count, **({"filter": filter_text} if filter_text else {}), **({"user": self.username} if self.username else {})}, "with_user"),
            ({"offset": offset, "count": count}, "no_filter"),
        ]

        last_err = None
        for params, label in attempts:
            try:
                resp = self._get_json("/api/V2/GetProjectList", params=params)
                norm = _normalize(resp)
                log.info("get_project_list attempt=%s ok count=%s", label, norm["Count"])
                return norm
            except SmartBuildError as e:
                last_err = e
                log.warning("get_project_list attempt=%s failed: %s", label, str(e))
                continue

        raise last_err or SmartBuildError("GetProjectList failed with all attempts")

    def set_job_data_model(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._post_json("/api/V2/SetJobDataModel", payload)

    def get_outputters(self, job_id: str) -> Dict[str, Any]:
        resp = self._get_json("/api/V2/GetOutputters", params={"JobId": job_id})
        items = resp.get("Outputters") if isinstance(resp, dict) else (resp if isinstance(resp, list) else [])
        try:
            log.info("outputters_raw job=%s sample=%s", job_id, json.dumps(items[:2]))
        except Exception:
            pass
        return {"Outputters": items}

    def get_outputs(self, job_id: str, outputter_id: str) -> Tuple[bytes, Dict[str, str]]:
        """
        Fetch a single slot's output as a file stream; return (bytes, headers).
        Preferred: POST body with [slot]; Fallback: legacy query OutputterId+Method.
        """
        slot_int: Optional[int] = None
        try:
            slot_int = int(str(outputter_id).strip())
        except Exception:
            slot_int = None

        # Preferred POST
        if slot_int is not None:
            url = f"{self.base_url}/api/V2/GetOutputs"
            resp = self.session.post(url, params={"JobId": job_id}, json=[slot_int], timeout=120)
            if resp.status_code == 200 and resp.content:
                return resp.content, resp.headers
            log.warning("get_outputs_body_fallback status=%s text=%s", resp.status_code, resp.text)

        # Fallback GET
        url = f"{self.base_url}/api/V2/GetOutputs"
        resp = self.session.get(url, params={"JobId": job_id, "OutputterId": outputter_id, "Method": "Download"}, timeout=120)
        if resp.status_code != 200:
            raise SmartBuildError(
                f"get_bytes_http_error: {resp.status_code} {resp.reason} for url: {resp.url} body={resp.text}"
            )
        return resp.content, resp.headers

    def get_outputs_multi(self, job_id: str, slots: List[int]) -> Tuple[bytes, Dict[str, str]]:
        """Fetch multiple slots at once; SmartBuild typically returns a ZIP."""
        url = f"{self.base_url}/api/V2/GetOutputs"
        resp = self.session.post(url, params={"JobId": job_id}, json=slots, timeout=180)
        if resp.status_code != 200:
            raise SmartBuildError(
                f"get_bytes_http_error: {resp.status_code} {resp.reason} for url: {resp.url} body={resp.text}"
            )
        return resp.content, resp.headers

    # ----- Internals -----
    def _ensure_auth(self) -> None:
        if not self._token or (time.time() - self._token_ts) > 60 * 60 * 20:  # ~20h safety
            self.login()

    def _get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self.testing and path.endswith("/GetProjectList"):
            filt = (params or {}).get("filter", "")
            return {
                "Projects": [
                    {"JobId": "J123", "Project": f"{filt or 'Sample'} Barn - 30x40", "CustomerName": filt or "Sample"},
                    {"JobId": "J124", "Project": f"{filt or 'Sample'} House - 40x60", "CustomerName": filt or "Sample"},
                ],
                "Count": 2,
            }
        if self.testing and path.endswith("/GetOutputters"):
            return {
                "Outputters": [
                    {"Slot": 1, "Group": "PDF Sections", "Description": "Summary Sheet", "IsSelected": False},
                    {"Slot": 2, "Group": "PDF Sections", "Description": "Wall Layout PDF", "IsSelected": False},
                ]
            }
        if self.testing and path.endswith("/GetStartingModels"):
            return [
                {"Id": 100, "Name": "Baseline 30x40", "Iso1Link": "", "Iso2Link": ""},
                {"Id": 200, "Name": "Pole Barn 40x60", "Iso1Link": "", "Iso2Link": ""}
            ]
        if self.testing and path.endswith("/Test"):
            return {"ok": True, "utc": _now_iso()}
        if self.testing and path.endswith("/GetVersion"):
            return {"version": "TEST-0.0.0", "utc": _now_iso()}

        self._ensure_auth()
        url = f"{self.base_url}{path}"
        try:
            r = self.session.get(url, params=params or {}, timeout=30)
            if r.status_code in (401, 403):
                log.warning("auth_retry status=%s path=%s", r.status_code, path)
                self.login()
                r = self.session.get(url, params=params or {}, timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as e:
            body = e.response.text if e.response is not None else ""
            raise SmartBuildError(f"get_json_http_error: {e} url={url} body={body}")
        except Exception as e:
            raise SmartBuildError(f"get_json_error: {e} url={url}")

    def _post_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.testing and path.endswith("/SetJobDataModel"):
            return {"JobId": "J999", "Status": "Created", "utc": _now_iso()}

        self._ensure_auth()
        url = f"{self.base_url}{path}"
        try:
            r = self.session.post(url, json=payload, timeout=60)
            if r.status_code in (401, 403):
                log.warning("auth_retry_post status=%s path=%s", r.status_code, path)
                self.login()
                r = self.session.post(url, json=payload, timeout=60)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as e:
            body = e.response.text if e.response is not None else ""
            raise SmartBuildError(f"post_json_http_error: {e} url={url} body={body}")
        except Exception as e:
            raise SmartBuildError(f"post_json_error: {e} url={url}")

# Singleton client
client = SmartBuildClient(
    base_url=SMARTBUILD_BASE_URL,
    username=SMARTBUILD_USERNAME,
    password=SMARTBUILD_PASSWORD,
    testing=TESTING_MODE,
)

# ---------- Template (inline Jinja) ----------
BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
  :root { --b:#0f172a; --ink:#0b1320; --muted:#64748b; --border:#e5e7eb; --bg:#f8fafc; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: var(--ink); }
  header { margin: 1rem 0 2rem; }
  .container { max-width: 980px; margin: 0 auto; padding: 0 1rem; }
  nav a { margin-right: 1rem; text-decoration: none; color: #2563eb; }
  h1 { margin: .25rem 0 1.25rem; }
  .flash { padding: .75rem 1rem; margin: .75rem 0; border:1px solid #fecaca; background:#fee2e2; color:#991b1b; border-radius: .75rem; }
  .ok { border-color:#bbf7d0; background:#dcfce7; color:#166534; }
  label { display:block; margin:.5rem 0 .25rem; color: var(--muted); font-weight:600; }
  input[type="text"], select, textarea {
    width:100%; padding:.6rem .7rem; border:1px solid var(--border); border-radius:.75rem; outline:none;
  }
  input[type="text"]:focus, select:focus, textarea:focus { border-color:#94a3b8; box-shadow: 0 0 0 3px #e2e8f0; }
  button, .btn {
    display:inline-block; padding:.5rem .9rem; border:1px solid var(--border); border-radius:.75rem; background:white; cursor:pointer;
  }
  button:hover, .btn:hover { background:#f5f5f5; }
  .row { display:flex; gap:.75rem; align-items:center; flex-wrap:wrap; }
  .table { width:100%; border:1px solid var(--border); border-radius: .75rem; border-collapse: collapse; overflow:hidden; }
  .table th, .table td { padding:.55rem .7rem; border-top:1px solid var(--border); vertical-align: top; }
  .table thead th { background: var(--bg); text-align:left; border-top: none;}
  .actions a { display:inline-block; padding:.25rem .5rem; border:1px solid var(--border); border-radius:.5rem; margin-right:.25rem; text-decoration:none; }
  .muted { color: var(--muted); }
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>{{ app_name }}</h1>
    <nav>
      <a href="{{ url_for('home') }}">Home</a>
      <a href="{{ url_for('outputs') }}">Outputs</a>
      <a href="{{ url_for('healthz') }}">Health</a>
    </nav>
  </div>
</header>

<div class="container">
  {% for m,c in messages %}
    <div class="flash {{ c }}">{{ m }}</div>
  {% endfor %}

  <section>
    {{ body|safe }}
  </section>

  <footer style="margin-top:2rem;color:#777">
    <small>{{ footer }}</small>
  </footer>
</div>
</body>
</html>
"""

def render_page(title: str, body_html: str) -> str:
    messages = []
    from flask import get_flashed_messages
    for m in get_flashed_messages(with_categories=True):
        cat, text = m
        css = "ok" if cat == "success" else ("error" if cat == "error" else "")
        messages.append((text, css))

    return render_template_string(
        BASE_HTML,
        title=title,
        app_name=APP_NAME + (" (TESTING)" if TESTING_MODE else ""),
        body=body_html,
        footer=f"{_now_iso()} • waitress-ready • TEST={'on' if TESTING_MODE else 'off'}",
        messages=messages,
    )

# ---------- Helpers for Create defaults ----------

def _pick_default_model(models: List[Dict[str, Any]], defaults: Dict[str, Any]) -> Optional[int]:
    key = (defaults or {}).get("starting_model_name_contains", "30x40").lower()
    for m in models:
        if key in (m.get("Name", "").lower()):
            return m.get("Id")
    return models[0]["Id"] if models else None

# ---------- Route: Home (Create Job form) ----------
@app.route("/", methods=["GET"])
def home():
    opts = _load_job_info()
    models: List[Dict[str, Any]] = []
    try:
        _assert_api_ready()
        models = client.get_starting_models()
    except Exception:
        models = []

    default_model_id = _pick_default_model(models, opts.get("defaults", {}))

    body = """
<h2>Create Job</h2>
<p>Fill the primary job fields. Defaults are preselected.</p>
<form method="post" action="{{ url_for('create') }}">
  <div class="row">
    <div style="flex:1">
      <label>Project Name</label>
      <input type="text" name="ProjectName" placeholder="e.g., Chris Webb" required>
    </div>
    <div style="flex:1">
      <label>Customer Name</label>
      <input type="text" name="CustomerName" placeholder="e.g., Chris Webb">
    </div>
  </div>

  <div class="row">
    <div style="flex:1">
      <label>Email</label>
      <input type="text" name="Email" placeholder="name@example.com">
    </div>
    <div style="flex:1">
      <label>Phone</label>
      <input type="text" name="Phone" placeholder="555-555-5555">
    </div>
  </div>

  <div class="row">
    <div style="flex:1">
      <label>Build Site Address</label>
      <input type="text" name="BuildSiteAddress" placeholder="123 Main St, City, ST">
    </div>
    <div style="flex:1">
      <label>Billing Address</label>
      <input type="text" name="BillingAddress" placeholder="123 Main St, City, ST">
    </div>
  </div>

  <div class="row">
    <div style="flex:1">
      <label>ZIP</label>
      <input type="text" name="BuildingZIP" placeholder="12345">
    </div>
    <div style="flex:1">
      <label>Lead Source</label>
      <input type="text" name="LeadSource" placeholder="google / referral / ...">
    </div>
  </div>

  <div class="row">
    <div style="flex:1">
      <label>Follow Up Date</label>
      <input type="date" name="FollowUpDate">
    </div>
    <div style="flex:1">
      <label>Follow Up Start Time</label>
      <input type="time" name="FollowUpStartTime">
    </div>
  </div>

  <div class="row">
    <div style="flex:1">
      <label>Valid Until</label>
      <input type="date" name="ValidUntil">
    </div>
    <div style="flex:1">
      <label>Job Notes (required)</label>
      <textarea name="JobNotes" rows="5" required placeholder="internal notes"></textarea>
    </div>
  </div>

  <label>Sales Rep</label>
  <select name="SalesRep">
    {% for s in sales_reps %}
      <option value="{{ s.name }}" {% if s.default %}selected{% endif %}>{{ s.name }}</option>
    {% endfor %}
  </select>

  <div class="row">
    <div style="flex:1">
      <label>Sales Rep Number</label>
      <select name="SalesRepNumber">
        {% for s in sales_reps %}
          <option value="{{ s.phone }}" {% if s.default %}selected{% endif %}>{{ s.phone }}</option>
        {% endfor %}
      </select>
    </div>
    <div style="flex:1">
      <label>Sales Rep Email</label>
      <select name="SalesRepEmail">
        {% for s in sales_reps %}
          <option value="{{ s.email }}" {% if s.default %}selected{% endif %}>{{ s.email }}</option>
        {% endfor %}
      </select>
    </div>
  </div>

  <label>Project Manager</label>
  <select name="ProjectManager">
    {% for p in project_managers %}
      <option value="{{ p.name }}" {% if p.default %}selected{% endif %}>{{ p.name }}</option>
    {% endfor %}
  </select>

  <div class="row">
    <div style="flex:1">
      <label>PM Number</label>
      <select name="ProjectManagerNumber">
        {% for p in project_managers %}
          <option value="{{ p.phone }}" {% if p.default %}selected{% endif %}>{{ p.phone }}</option>
        {% endfor %}
      </select>
    </div>
    <div style="flex:1">
      <label>PM Email</label>
      <select name="ProjectManagerEmail">
        {% for p in project_managers %}
          <option value="{{ p.email }}" {% if p.default %}selected{% endif %}>{{ p.email }}</option>
        {% endfor %}
      </select>
    </div>
  </div>

  <label>Operations Manager</label>
  <select name="OperationsManager">
    {% for o in ops_managers %}
      <option value="{{ o.name }}" {% if o.default %}selected{% endif %}>{{ o.name }}</option>
    {% endfor %}
  </select>

  <div class="row">
    <div style="flex:1">
      <label>Ops Number</label>
      <select name="OperationsManagerNumber">
        {% for o in ops_managers %}
          <option value="{{ o.phone }}" {% if o.default %}selected{% endif %}>{{ o.phone }}</option>
        {% endfor %}
      </select>
    </div>
    <div style="flex:1">
      <label>Ops Email</label>
      <select name="OperationsManagerEmail">
        {% for o in ops_managers %}
          <option value="{{ o.email }}" {% if o.default %}selected{% endif %}>{{ o.email }}</option>
        {% endfor %}
      </select>
    </div>
  </div>

  <label>Follow Up Type</label>
  <select name="FollowUpType">
    {% for t in follow_up_types %}
      <option value="{{ t }}">{{ t }}</option>
    {% endfor %}
  </select>

  <label>Starting Model</label>
  <select name="StartingModelId">
    {% for m in models %}
      <option value="{{ m['Id'] }}" {% if m['Id'] == default_model_id %}selected{% endif %}>{{ m['Name'] }}</option>
    {% endfor %}
  </select>

  <div class="row" style="margin-top:1rem">
    <div style="flex:1">
      <label>Template Id (optional)</label>
      <input type="text" name="TemplateId" value="{{ default_template_id }}">
    </div>
    <div style="flex:1">
      <label>Answers JSON (optional; overrides fields)</label>
      <textarea name="answers_json" rows="6" placeholder='[{"Id":"ProjectName","Value":"30x40"}]'></textarea>
    </div>
  </div>

  <div style="margin-top:1rem">
    <button type="submit">Create Job</button>
  </div>
</form>
"""
    return render_page(
        "Home",
        render_template_string(
            body,
            sales_reps=opts["sales_reps"],
            project_managers=opts["project_managers"],
            ops_managers=opts["ops_managers"],
            follow_up_types=opts["follow_up_types"],
            models=models,
            default_model_id=default_model_id,
            default_template_id=SMARTBUILD_TEMPLATE_ID,
        ),
    )

from flask import session

@app.route("/enter", methods=["GET", "POST"])
def enter():
    next_url = request.args.get("next") or url_for("home")

    # Convenience: allow ?as=Name to set quickly (only if allowed)
    as_name = (request.args.get("as") or "").strip()
    if as_name:
        if _is_name_allowed(as_name):
            session["user_name"] = as_name
            return redirect(next_url)
        else:
            flash("Name not allowed.", "error")
            return redirect(url_for("enter", next=next_url))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Name is required.", "error")
            return redirect(url_for("enter", next=next_url))
        if not _is_name_allowed(name):
            flash("You’re not on the allowed users list.", "error")
            return redirect(url_for("enter", next=next_url))

        # Session is *not* permanent → expires on browser close
        session["user_name"] = name
        return redirect(next_url)

    # GET
    body = """
<h2>Enter</h2>
<form method="post" action="{{ url_for('enter', next=next_url) }}">
  <label>Your Name</label>
  <input type="text" name="name" placeholder="" autofocus required>
  <div style="margin-top:.75rem">
    <button type="submit">Continue</button>
  </div>
</form>
"""
    return render_page("Enter", render_template_string(body, next_url=next_url))

# ---------- Route: Create Job ----------
@app.route("/create", methods=["POST"])
def create():
    template_id = (request.form.get("TemplateId") or "").strip() or SMARTBUILD_TEMPLATE_ID
    answers_json = (request.form.get("answers_json") or "").strip()

    try:
        # From form fields -> Answer IDs (only if answers_json not provided)
        if answers_json:
            answers = json.loads(answers_json)
            if not isinstance(answers, list):
                raise ValueError("Answers JSON must be a list")
        else:
            field_ids = [
                "ProjectName","CustomerName","Email","Phone","BuildSiteAddress","BillingAddress",
                "BuildingZIP","LeadSource","ValidUntil","FollowUpDate","FollowUpType","FollowUpStartTime",
                "JobType","JobNotes","Personnel",
                "SalesRep","SalesRepNumber","SalesRepEmail",
                "ProjectManager","ProjectManagerNumber","ProjectManagerEmail",
                "OperationsManager","OperationsManagerNumber","OperationsManagerEmail",
            ]
            answers = []
            for fid in field_ids:
                val = (request.form.get(fid) or "").strip()
                if val != "":
                    answers.append({"Id": fid, "Value": val})
            smid = (request.form.get("StartingModelId") or "").strip()
            if smid:
                answers.append({"Id": "StartingModelId", "Value": smid})

        # Enforce required JobNotes server-side too
        if not any((a.get("Id") == "JobNotes") and str(a.get("Value","")) .strip() for a in answers):
            flash("Job Notes is required.", "error")
            return redirect(url_for("home"))

        # Project name: prefer explicit, else from Answers
        project = (request.form.get("ProjectName") or "").strip()
        if not project and isinstance(answers, list):
            for a in answers:
                if a.get("Id") == "ProjectName":
                    project = a.get("Value", "").strip()
                    break
        if not project:
            flash("Project name is required.", "error")
            return redirect(url_for("home"))

        payload = {
            "TemplateId": template_id,
            "Answers": answers,
            "Project": project,
        }

        _assert_api_ready()
        result = client.set_job_data_model(payload)
        job_id = result.get("JobId") or "UNKNOWN"
        flash(f"✅ Created job: {job_id} for '{project}'", "success")
        log.info("create_job ok project=%s template=%s job_id=%s", project, template_id, job_id)
        return redirect(url_for("outputs", q=project))

    except ValueError as e:
        flash(f"Invalid answers_json: {e}", "error")
        return redirect(url_for("home"))
    except SmartBuildError as e:
        flash(f"❌ Error creating job: {e}", "error")
        log.error("create_job_error err=%s", e)
        return redirect(url_for("home"))
    except Exception as e:
        flash(f"❌ Unexpected error: {e}", "error")
        log.exception("create_job_exception")
        return redirect(url_for("home"))

# ---------- Route: Outputs ----------
@app.route("/outputs", methods=["GET", "POST"])
def outputs():
    q = (request.values.get("q") or "").strip()
    job_id = (request.values.get("job_id") or "").strip()
    if request.method == "POST":
        q = (request.form.get("q") or "").strip()
        job_id = ""

    try:
        _assert_api_ready()

        # Resolve job(s)
        if job_id:
            search_results = [{"JobId": job_id, "Project": "(by id)", "CustomerName": ""}]
        else:
            jobs = client.get_project_list(filter_text=q, offset=0, count=200)
            raw = jobs["Projects"]
            search_results = [_normalize_project_item(x) for x in raw]
            search_results = _client_side_filter(search_results, q)

        choose_html = """
<h2>Fetch Outputs</h2>
<form method="post" action="{{ url_for('outputs') }}">
  <label>Search by Customer / Project Name</label>
  <input type="text" name="q" placeholder="e.g., Chris Webb" value="{{ q }}" autofocus>
  <button type="submit">Search</button>
</form>
"""
        choose_html_rendered = render_template_string(choose_html, q=q)

        if not search_results:
            flash("No jobs found. Try a different name.", "error")
            return render_page("Outputs", choose_html_rendered)

        if len(search_results) > 1 and not job_id:
            rows = "".join(
                f"<tr><td>{j.get('JobId')}</td>"
                f"<td>{j.get('Project')}</td>"
                f"<td><a href='{url_for('outputs', job_id=j.get('JobId'))}'>Select</a></td></tr>"
                for j in search_results
            )
            table = f"""{choose_html_rendered}
<h3>Multiple matches</h3>
<table class="table">
  <thead><tr><th>JobId</th><th>Project</th><th>Action</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
"""
            return render_page("Outputs", table)

        # Single match (or direct id)
        active_job = search_results[0]
        job_id = active_job["JobId"]
        project_label = active_job.get("Project") or ""

        # Fetch available outputs
        outs = client.get_outputters(job_id)
        items = outs.get("Outputters") if isinstance(outs, dict) else (outs or [])
        outputters = _normalize_outputters(items)

        # Normalize unknown IDs to sequential for safety
        if any(o["Id"] == "Unknown" for o in outputters):
            for idx, o in enumerate(outputters, start=1):
                if o["Id"] == "Unknown":
                    o["Id"] = str(o.get("Slot") or idx)

        rows = "".join(
            f"<tr>"
            f"<td><input class='slotbox' type='checkbox' name='slots' value='{o['Slot'] or o['Id']}'></td>"
            f"<td>{o['Id']}</td>"
            f"<td>{o['Name']}</td>"
            f"<td>{o.get('Group','')}</td>"
            f"<td class='actions'>"
            f"  <a href='{url_for('download_output', job_id=job_id, outputter_id=o['Id'], project=project_label)}'>Download</a>"
            f"</td>"
            f"</tr>"
            for o in outputters
        )

        body = f"""{choose_html_rendered}
<h3>Job: {job_id} — {project_label}</h3>
<form method=\"post\" action=\"{url_for('outputs_bulk')}?job_id={job_id}\">
  <div class=\"row\" style=\"justify-content:space-between;margin:.5rem 0 1rem;\">
    <div class=\"muted\">Tick the outputs you want. “Download Selected” bundles a ZIP when needed.</div>
    <div>
      <button type=\"submit\" name=\"op\" value=\"selected\">Download Selected</button>
      <button type=\"submit\" name=\"op\" value=\"all\">Download All</button>
    </div>
  </div>

  <table class=\"table\">
    <thead>
      <tr>
        <th><input type=\"checkbox\" onclick=\"for(const c of document.querySelectorAll('.slotbox')) c.checked=this.checked\"></th>
        <th>OutputterId</th>
        <th>Name</th>
        <th>Group</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</form>
"""
        return render_page("Outputs", body)

    except SmartBuildError as e:
        flash(f"❌ Error: {e}", "error")
        log.error("outputs_error q=%s job_id=%s err=%s", q, job_id, e)
        return render_page("Outputs", "<p>Could not load outputs.</p>")
    except Exception as e:
        flash(f"❌ Unexpected error: {e}", "error")
        log.exception("outputs_exception q=%s job_id=%s", q, job_id)
        return render_page("Outputs", "<p>Unexpected error.</p>")

# ---------- Route: Outputs/Bulk and Checkboxes ----------
@app.route("/outputs/bulk", methods=["POST"])
def outputs_bulk():
    job_id = (request.args.get("job_id") or "").strip()
    if not job_id:
        flash("Missing job_id.", "error"); return redirect(url_for("outputs"))

    op = request.form.get("op")  # "selected" or "all"
    try:
        _assert_api_ready()
        # determine slots
        slots: List[int] = []
        if op == "all":
            outs = client.get_outputters(job_id)
            items = outs.get("Outputters") if isinstance(outs, dict) else (outs or [])
            for it in items:
                if isinstance(it, dict) and it.get("Slot") is not None:
                    try:
                        slots.append(int(it.get("Slot")))
                    except Exception:
                        pass
        else:
            slots = [int(s) for s in request.form.getlist("slots") if str(s).isdigit()]

        if not slots:
            flash("No outputs selected.", "error")
            return redirect(url_for("outputs", job_id=job_id))

        # Fetch multi: server returns a single file or a ZIP
        content, headers = client.get_outputs_multi(job_id, slots)

        disp = headers.get("Content-Disposition", "")
        ctype = (headers.get("Content-Type") or "application/octet-stream").lower()
        fname = None
        if "filename=" in disp:
            fname = disp.split("filename=", 1)[1].strip('"; ')
        if not fname:
            if "zip" in ctype:
                fname = f"Job{job_id}-outputs.zip"
            else:
                fname = f"Job{job_id}-outputs.bin"

        dest = OUT_DIR / fname
        with dest.open("wb") as f: f.write(content)
        return send_file(
            io.BytesIO(content),
            as_attachment=True,
            download_name=fname,
            mimetype=ctype or "application/octet-stream",
        )
    except SmartBuildError as e:
        flash(f"❌ Error fetching outputs: {e}", "error")
        log.error("bulk_outputs_error job_id=%s err=%s", job_id, e)
        return redirect(url_for("outputs", job_id=job_id))
    except Exception as e:
        flash(f"❌ Unexpected error: {e}", "error")
        log.exception("bulk_outputs_exception job_id=%s", job_id)
        return redirect(url_for("outputs", job_id=job_id))

# ---------- Route: Download/Preview Output ----------
@app.route("/outputs/download", methods=["GET"])
def download_output():
    job_id = (request.args.get("job_id") or "").strip()
    outputter_id = (request.args.get("outputter_id") or "").strip()
    _ = (request.args.get("method") or "Download").strip()
    project_label = _slug((request.args.get("project") or f"Job{job_id}"))

    if not job_id or not outputter_id:
        flash("Missing job_id or outputter_id.", "error")
        return redirect(url_for("outputs"))

    try:
        content, headers = client.get_outputs(job_id, outputter_id)

        disp = headers.get("Content-Disposition", "")
        fname = None
        if "filename=" in disp:
            fname = disp.split("filename=", 1)[1].strip('"; ')

        ctype = (headers.get("Content-Type") or "application/octet-stream").lower()
        ext = ""
        if not fname:
            if "pdf" in ctype:
                ext = ".pdf"
            elif "zip" in ctype:
                ext = ".zip"
            elif "spreadsheetml" in ctype:
                ext = ".xlsx"
            elif "wordprocessingml" in ctype:
                ext = ".docx"
            elif "json" in ctype:
                ext = ".json"
            elif "csv" in ctype:
                ext = ".csv"
            elif "dxf" in ctype or "cad" in ctype:
                ext = ".dxf"

        slot_label = outputter_id
        try:
            outs = client.get_outputters(job_id)
            meta = _normalize_outputters(outs.get("Outputters") if isinstance(outs, dict) else outs)
            m = next((x for x in meta if x["Id"] == outputter_id), None)
            if m and m.get("Name"):
                slot_label = _slug(m["Name"])
        except Exception:
            pass

        if not fname:
            fname = f"{project_label}-{slot_label}{ext or ''}"

        return send_file(
            io.BytesIO(content),
            as_attachment=True,
            download_name=fname,
            mimetype=ctype or "application/octet-stream",
        )

    except SmartBuildError as e:
        flash(f"❌ Error fetching output: {e}", "error")
        log.error("download_output_error job_id=%s outputter_id=%s err=%s", job_id, outputter_id, e)
        return redirect(url_for("outputs"))
    except Exception:
        flash("❌ Unexpected error.", "error")
        log.exception("download_output_exception job_id=%s outputter_id=%s", job_id, outputter_id)
        return redirect(url_for("outputs"))

# ---------- Route: Health ----------
@app.route("/healthz", methods=["GET"])
def healthz():
    try:
        v = client.get_version()
        t = client.test()
        body = f"""
<h2>Health</h2>
<table class=table>
  <tr><th>Version</th><td><code>{v}</code></td></tr>
  <tr><th>Test</th><td><code>{t}</code></td></tr>
  <tr><th>Time (UTC)</th><td>{_now_iso()}</td></tr>
  <tr><th>Testing Mode</th><td>{'true' if TESTING_MODE else 'false'}</td></tr>
</table>
"""
        return render_page("Health", body)
    except SmartBuildError as e:
        flash(f"❌ SmartBuild error: {e}", "error")
        return render_page("Health", "<p>Service reachable but SmartBuild failing.</p>")
    except Exception as e:
        flash(f"❌ Unexpected error: {e}", "error")
        return render_page("Health", "<p>Unexpected error.</p>")

# ---------- Guard: API readiness ----------

def _assert_api_ready() -> None:
    """
    403/expired token handling: always verify /Test + /GetVersion before project list or create.
    On failure, force re-login and retry once silently.
    """
    try:
        client.test()
        client.get_version()
    except SmartBuildError:
        log.warning("api_ready_first_attempt_failed -> re-login")
        client.login()
        client.test()
        client.get_version()

@app.before_request
def _require_name_gate():
    if not REQUIRE_LOGIN:
        return
    # Let these through:
    open_paths = {"/enter", "/healthz"}
    if request.path in open_paths or request.path.startswith("/static"):
        return
    if not session.get("user_name"):
        return redirect(url_for("enter", next=(request.full_path if request.query_string else request.path)))

# ---------- Main ----------

def create_app() -> Flask:
    return app

# waitress entrypoint: waitress-serve --listen=0.0.0.0:8080 web_app:app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=APP_PORT, debug=False)