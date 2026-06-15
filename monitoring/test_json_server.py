import json
from pathlib import Path

import json_server


def test_api_endpoints_return_analysis_data(tmp_path, monkeypatch):
    analysis = {
        "summary": {
            "total_requests": 3,
            "action_counts": {"ALLOW": 1, "BLOCK": 2},
            "attack_type_counts": {"SQLi": 2},
        },
        "top_ips": [{"ip": "192.0.2.1", "request_count": 3}],
        "rule_hits": {"AWSManagedRulesSQLiRuleSet": 2},
        "time_buckets": [{"hour": "2026-06-16 00:00", "count": 3}],
    }
    (tmp_path / "analysis_20260616_000000.json").write_text(
        json.dumps(analysis), encoding="utf-8"
    )
    monkeypatch.setattr(json_server, "DATA_DIR", str(tmp_path))

    client = json_server.app.test_client()

    assert client.get("/summary").get_json()["total_requests"] == 3
    assert client.get("/top-ips").get_json()[0]["ip"] == "192.0.2.1"
    assert client.get("/rule-hits").get_json() == [
        {"rule": "AWSManagedRulesSQLiRuleSet", "count": 2}
    ]
    assert client.get("/time-buckets").get_json()[0]["count"] == 3
    assert client.get("/attack-types").get_json() == [
        {"type": "SQLi", "count": 2}
    ]
    assert client.get("/action-counts").get_json() == [
        {"action": "ALLOW", "count": 1},
        {"action": "BLOCK", "count": 2},
    ]


def test_api_returns_404_without_analysis_data(tmp_path, monkeypatch):
    monkeypatch.setattr(json_server, "DATA_DIR", str(tmp_path))
    client = json_server.app.test_client()

    assert client.get("/summary").status_code == 404
    assert client.get("/top-ips").status_code == 404
