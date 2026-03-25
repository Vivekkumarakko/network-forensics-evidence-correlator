from __future__ import annotations

from web import app as web_app


def login(client):
    return client.post("/login", data={"username": "analyst", "password": "correlator123"})


def test_login_required_redirects_to_login():
    client = web_app.app.test_client()
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_healthcheck():
    client = web_app.app.test_client()
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"


def test_sample_analysis_and_notes_flow():
    client = web_app.app.test_client()
    login(client)

    response = client.post("/analyze", data={"use_sample": "on"}, follow_redirects=False)
    assert response.status_code == 302
    result_path = response.headers["Location"]
    assert "/runs/" in result_path and result_path.endswith("/result")

    run_id = result_path.split("/")[2]

    result_page = client.get(result_path)
    assert result_page.status_code == 200
    assert "Case Notes" in result_page.get_data(as_text=True)

    save_notes = client.post(
        f"/runs/{run_id}/notes",
        data={"notes": "Containment complete", "next": f"/runs/{run_id}/result"},
        follow_redirects=True,
    )
    assert save_notes.status_code == 200
    assert "Containment complete" in save_notes.get_data(as_text=True)

    artifact = client.get(f"/reports/runs/{run_id}/executive_summary.html")
    assert artifact.status_code == 200
    assert "Executive Attack Summary" in artifact.get_data(as_text=True)
