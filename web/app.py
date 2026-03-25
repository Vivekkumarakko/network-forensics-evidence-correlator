from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from uuid import uuid4

from flask import Flask, abort, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.correlator.pipeline import run_analysis
from src.correlator.utils import ensure_directory


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("NFEC_SECRET_KEY", "nfec-demo-secret")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("NFEC_SECURE_COOKIE", "0") == "1"
app.permanent_session_lifetime = timedelta(hours=8)

UPLOAD_ROOT = ROOT / "uploads"
RUNS_ROOT = ROOT / "reports" / "runs"

DEFAULT_USERNAME = os.environ.get("NFEC_USERNAME", "analyst")
DEFAULT_PASSWORD = os.environ.get("NFEC_PASSWORD", "correlator123")
SHOW_DEMO_HINT = "NFEC_USERNAME" not in os.environ and "NFEC_PASSWORD" not in os.environ
ALLOWED_UPLOADS = {
    "pcap": {".csv"},
    "firewall": {".csv"},
    "ids": {".json"},
}


def _new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]


def _safe_redirect_target(target: str | None) -> str:
    if not target:
        return url_for("index")
    if target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("index")


def _recent_runs(limit: int = 8) -> list[str]:
    recent_runs = []
    if RUNS_ROOT.exists():
        for path in sorted(RUNS_ROOT.iterdir(), reverse=True):
            if path.is_dir():
                recent_runs.append(path.name)
    return recent_runs[:limit]


def _metrics(result: dict) -> dict:
    techniques = set()
    highest_risk = 0
    for incident in result["incidents"]:
        highest_risk = max(highest_risk, incident["risk_score"])
        techniques.update(incident["mitre_techniques"])
    return {
        "event_count": len(result["events"]),
        "incident_count": len(result["incidents"]),
        "highest_risk": highest_risk,
        "mitre_total": len(techniques),
    }


def _artifact_urls(run_id: str) -> dict:
    return {
        "report_url": f"/reports/runs/{run_id}/forensic_report.md",
        "dashboard_url": f"/reports/runs/{run_id}/dashboard.html",
        "json_url": f"/reports/runs/{run_id}/analysis.json",
        "timeline_csv_url": f"/reports/runs/{run_id}/timeline.csv",
        "incidents_csv_url": f"/reports/runs/{run_id}/incidents.csv",
        "executive_summary_url": f"/reports/runs/{run_id}/executive_summary.html",
    }


def _validate_upload(kind: str, filename: str) -> bool:
    suffix = Path(filename).suffix.lower()
    return suffix in ALLOWED_UPLOADS.get(kind, set())


def _notes_path(run_id: str) -> Path:
    return RUNS_ROOT / run_id / "case_notes.md"


def _load_run_result(run_id: str) -> dict | None:
    json_path = RUNS_ROOT / run_id / "analysis.json"
    if not json_path.exists():
        return None
    return json.loads(json_path.read_text(encoding="utf-8"))


def _load_case_notes(run_id: str) -> str:
    note_path = _notes_path(run_id)
    if not note_path.exists():
        return ""
    return note_path.read_text(encoding="utf-8")


def _save_case_notes(run_id: str, notes: str) -> None:
    note_path = _notes_path(run_id)
    note_path.write_text(notes, encoding="utf-8")


def _comparison_data(run_ids: list[str]) -> list[dict]:
    rows = []
    for run_id in run_ids:
        result = _load_run_result(run_id)
        if result is None:
            continue
        metrics = _metrics(result)
        rows.append(
            {
                "run_id": run_id,
                "metrics": metrics,
                "result": result,
                "notes": _load_case_notes(run_id),
            }
        )
    return rows


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
            session.permanent = True
            session["authenticated"] = True
            session["username"] = username
            destination = _safe_redirect_target(request.args.get("next"))
            return redirect(destination)
        return render_template("login.html", error="Invalid username or password.", show_demo_hint=SHOW_DEMO_HINT)

    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html", show_demo_hint=SHOW_DEMO_HINT)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    return render_template("index.html", recent_runs=_recent_runs(), username=session.get("username", DEFAULT_USERNAME))


@app.post("/analyze")
@login_required
def analyze():
    use_sample = request.form.get("use_sample") == "on"
    run_id = _new_run_id()
    upload_dir = ensure_directory(UPLOAD_ROOT / run_id)
    output_dir = ensure_directory(RUNS_ROOT / run_id)

    if use_sample:
        result = run_analysis(sample=True, output_dir=output_dir)
    else:
        required_files = {
            "pcap": request.files.get("pcap"),
            "firewall": request.files.get("firewall"),
            "ids": request.files.get("ids"),
        }
        missing = [name for name, file in required_files.items() if file is None or not file.filename]
        if missing:
            return render_template(
                "index.html",
                error=f"Missing required uploads: {', '.join(missing)}",
                recent_runs=_recent_runs(),
                username=session.get("username", DEFAULT_USERNAME),
            ), 400

        invalid = [
            name
            for name, file in required_files.items()
            if file is not None and file.filename and not _validate_upload(name, file.filename)
        ]
        if invalid:
            return render_template(
                "index.html",
                error=f"Invalid upload type for: {', '.join(invalid)}. Expected CSV for PCAP/firewall and JSON for IDS.",
                recent_runs=_recent_runs(),
                username=session.get("username", DEFAULT_USERNAME),
            ), 400

        saved_paths: dict[str, Path] = {}
        for key, file in required_files.items():
            filename = secure_filename(file.filename)
            target = upload_dir / filename
            file.save(target)
            saved_paths[key] = target

        result = run_analysis(
            pcap_path=saved_paths["pcap"],
            firewall_path=saved_paths["firewall"],
            ids_path=saved_paths["ids"],
            output_dir=output_dir,
        )

    return redirect(url_for("show_result", run_id=run_id))


@app.get("/runs/<run_id>")
@login_required
def show_run(run_id: str):
    output_dir = RUNS_ROOT / run_id
    if not output_dir.exists():
        return redirect(url_for("index"))

    return render_template(
        "saved_run.html",
        run_id=run_id,
        report_path=(output_dir / "forensic_report.md").relative_to(ROOT),
        dashboard_path=(output_dir / "dashboard.html").relative_to(ROOT),
        json_path=(output_dir / "analysis.json").relative_to(ROOT),
        timeline_csv_path=(output_dir / "timeline.csv").relative_to(ROOT),
        incidents_csv_path=(output_dir / "incidents.csv").relative_to(ROOT),
        executive_summary_path=(output_dir / "executive_summary.html").relative_to(ROOT),
        notes=_load_case_notes(run_id),
    )


@app.get("/runs/<run_id>/result")
@login_required
def show_result(run_id: str):
    result = _load_run_result(run_id)
    if result is None:
        return redirect(url_for("index"))
    return render_template(
        "result.html",
        result=result,
        run_id=run_id,
        metrics=_metrics(result),
        artifacts=_artifact_urls(run_id),
        notes=_load_case_notes(run_id),
    )


@app.post("/runs/<run_id>/notes")
@login_required
def save_notes(run_id: str):
    if not (RUNS_ROOT / run_id).exists():
        return redirect(url_for("index"))
    notes = request.form.get("notes", "").strip()
    _save_case_notes(run_id, notes)
    redirect_target = request.form.get("next") or url_for("show_result", run_id=run_id)
    return redirect(redirect_target)


@app.get("/compare")
@login_required
def compare_runs():
    selected = request.args.getlist("run_id")
    comparisons = _comparison_data(selected)
    return render_template(
        "compare.html",
        recent_runs=_recent_runs(limit=12),
        selected=selected,
        comparisons=comparisons,
    )


@app.get("/healthz")
def healthcheck():
    return {"status": "ok", "service": "network-forensics-evidence-correlator"}


@app.get("/reports/<path:relative_path>")
@login_required
def serve_report_artifact(relative_path: str):
    artifact_root = ROOT / "reports"
    target = artifact_root / relative_path
    if not target.exists():
        abort(404)
    return send_from_directory(artifact_root, relative_path)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
