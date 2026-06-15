from pathlib import Path
import sys


ANALYZER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_DIR))

import waf_analyzer


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_sample_log_analysis():
    records = list(waf_analyzer.iter_records(str(FIXTURE_DIR)))
    result = waf_analyzer.analyze(records)

    assert result["summary"]["total_requests"] == 8
    assert result["summary"]["unique_ips"] == 4
    assert result["summary"]["block_rate"] == 0.625
    assert result["summary"]["attack_type_counts"] == {
        "SQLi": 2,
        "XSS": 1,
        "PathTraversal": 1,
        "Scanner": 1,
        "CommandInjection": 1,
    }
    assert len(result["top_ips"]) == 4
    assert len(result["time_buckets"]) == 3


def test_attack_classification_uses_rule_and_request_data():
    records = list(waf_analyzer.iter_records(str(FIXTURE_DIR)))

    assert [waf_analyzer.classify_attack(record) for record in records] == [
        "SQLi",
        "SQLi",
        "XSS",
        "PathTraversal",
        "Other",
        "Other",
        "Scanner",
        "CommandInjection",
    ]


def test_configured_rule_groups_are_not_counted_as_matches():
    record = {
        "action": "ALLOW",
        "terminatingRuleId": "Default_Action",
        "ruleGroupList": [
            {
                "ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
                "terminatingRule": None,
                "nonTerminatingMatchingRules": [],
            },
            {
                "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
                "terminatingRule": None,
                "nonTerminatingMatchingRules": [],
            },
        ],
        "httpRequest": {
            "clientIp": "203.0.113.10",
            "uri": "/",
            "args": "",
            "headers": [{"name": "User-Agent", "value": "Mozilla/5.0"}],
        },
    }

    result = waf_analyzer.analyze([record])

    assert waf_analyzer.classify_attack(record) == "Other"
    assert result["rule_hits"] == {}
    assert result["summary"]["attack_type_counts"] == {}


def test_count_mode_match_is_classified_and_counted():
    record = {
        "action": "ALLOW",
        "terminatingRuleId": "Default_Action",
        "nonTerminatingMatchingRules": [
            {
                "ruleId": "AWSManagedRulesSQLiRuleSet",
                "action": "COUNT",
                "ruleMatchDetails": [{"conditionType": "SQL_INJECTION"}],
            }
        ],
        "ruleGroupList": [
            {
                "ruleGroupId": "AWS#AWSManagedRulesSQLiRuleSet",
                "terminatingRule": {
                    "ruleId": "SQLi_QUERYARGUMENTS",
                    "action": "BLOCK",
                },
                "nonTerminatingMatchingRules": [],
            }
        ],
        "labels": [
            {"name": "awswaf:managed:aws:sql-database:SQLi_QueryArguments"}
        ],
        "httpRequest": {
            "clientIp": "203.0.113.11",
            "uri": "/",
            "args": "id=1%27%20OR%201=1",
            "headers": [{"name": "User-Agent", "value": "attack-sim/1.0"}],
        },
    }

    result = waf_analyzer.analyze([record])

    assert waf_analyzer.classify_attack(record) == "SQLi"
    assert result["rule_hits"] == {
        "AWSManagedRulesSQLiRuleSet": 1,
    }


def test_command_injection_takes_priority_over_path_text():
    record = {
        "httpRequest": {
            "uri": "/",
            "args": "host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd",
            "headers": [],
        }
    }

    assert waf_analyzer.classify_attack(record) == "CommandInjection"
