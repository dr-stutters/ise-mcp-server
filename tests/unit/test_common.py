import pytest
from stutters_mcp_core import InvalidRequest

from ise_mcp.knowledge import decode_steps
from ise_mcp.tools._common import normalize_mac, render_condition, summarize_rule
from ise_mcp.tools.sessions import parse_other_attrs


@pytest.mark.parametrize(
    "raw", ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AABBCCDDEEFF", " aa bb cc dd ee ff "]
)
def test_normalize_mac(raw: str) -> None:
    assert normalize_mac(raw) == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize("raw", ["aa:bb:cc", "zz:bb:cc:dd:ee:ff", "10.1.1.1", "../aa:bb:cc:dd:ee:ff"])
def test_normalize_mac_rejects(raw: str) -> None:
    with pytest.raises(InvalidRequest):
        normalize_mac(raw)


def test_render_condition_nested() -> None:
    cond = {
        "conditionType": "ConditionAndBlock",
        "children": [
            {"conditionType": "ConditionReference", "name": "Wired_MAB"},
            {
                "conditionType": "ConditionOrBlock",
                "isNegate": True,
                "children": [
                    {
                        "conditionType": "ConditionAttributes",
                        "dictionaryName": "IdentityGroup",
                        "attributeName": "Name",
                        "operator": "equals",
                        "attributeValue": "Blocked",
                    },
                    {"conditionType": "ConditionReference", "name": "X"},
                ],
            },
        ],
    }
    assert render_condition(cond) == "(Wired_MAB AND NOT (IdentityGroup:Name equals Blocked OR X))"
    assert render_condition(None) == "ANY"


def test_summarize_rule_default() -> None:
    row = summarize_rule(
        {"rule": {"name": "Default", "default": True, "rank": 3, "hitCounts": 2}, "profile": ["DenyAccess"]}
    )
    assert row["condition"] == "DEFAULT"
    assert row["profile"] == ["DenyAccess"]


def test_decode_steps() -> None:
    steps = decode_steps("11001, 22040,99999", {"22040": {"reason": "Wrong password"}})
    assert steps == ["11001 Received RADIUS Access-Request", "22040 Wrong password", "99999"]


def test_parse_other_attrs() -> None:
    attrs = parse_other_attrs("StepLatency=1=0:!:ISEPolicySetName=Default:!:Name=a:!:Name=b:!:junk")
    assert attrs == {"ISEPolicySetName": "Default", "Name": ["a", "b"]}
