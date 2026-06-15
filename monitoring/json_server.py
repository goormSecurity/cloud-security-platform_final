"""
analyzer가 만든 JSON 결과를 Grafana가 읽을 수 있게
HTTP API로 노출하는 작은 서버
"""
from flask import Flask, jsonify
from flask_cors import CORS
import json
import glob
import os

app = Flask(__name__)
CORS(app)  # Grafana(다른 포트)에서 접근 허용

DATA_DIR = "./data"


def load_latest_json():
    """data 폴더에서 가장 최신 analysis_*.json 파일을 읽음"""
    files = sorted(glob.glob(os.path.join(DATA_DIR, "analysis_*.json")))
    if not files:
        return None
    with open(files[-1], encoding="utf-8") as f:
        return json.load(f)


@app.route("/")
def index():
    return "JSON Server running. Try /summary, /top-ips, /rule-hits, /time-buckets, /attack-types"


@app.route("/summary")
def summary():
    data = load_latest_json()
    if not data:
        return jsonify({"error": "no data"}), 404
    return jsonify(data.get("summary", {}))


@app.route("/top-ips")
def top_ips():
    """IP별 요청 수 (Bar 차트용)"""
    data = load_latest_json()
    if not data:
        return jsonify([]), 404
    return jsonify(data.get("top_ips", []))


@app.route("/rule-hits")
def rule_hits():
    """WAF 룰별 탐지 (Bar 차트용)"""
    data = load_latest_json()
    if not data:
        return jsonify([]), 404
    rules = data.get("rule_hits", {})
    # Grafana가 그리기 좋은 형태로 변환
    return jsonify([{"rule": k, "count": v} for k, v in rules.items()])


@app.route("/time-buckets")
def time_buckets():
    """시간대별 요청 (Time series용)"""
    data = load_latest_json()
    if not data:
        return jsonify([]), 404
    return jsonify(data.get("time_buckets", []))


@app.route("/attack-types")
def attack_types():
    """공격 유형 분포 (Pie 차트용)"""
    data = load_latest_json()
    if not data:
        return jsonify([]), 404
    types = data.get("summary", {}).get("attack_type_counts", {})
    return jsonify([{"type": k, "count": v} for k, v in types.items()])


@app.route("/action-counts")
def action_counts():
    """ALLOW/BLOCK/COUNT 비율 (Pie 차트용)"""
    data = load_latest_json()
    if not data:
        return jsonify([]), 404
    actions = data.get("summary", {}).get("action_counts", {})
    return jsonify([{"action": k, "count": v} for k, v in actions.items()])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)