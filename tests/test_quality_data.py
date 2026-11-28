import os
import tempfile
from scripts.quality_data import check_data_quality


def test_quality_data_on_sample_file():
    sample_path = os.path.join(os.path.dirname(__file__), "sample.jsonl")
    result = check_data_quality(sample_path)
    assert result["overall_passed"] is True
    assert result["lines"] == 33
    assert result["events"] == 33
    assert result["duplicates"] == 0
    assert result["errors"] == 0
    assert result["balance_passed"] is True
    assert result["utc_passed"] is True
    assert result["continuity_passed"] is True


def test_quality_data_with_duplicates_and_corrupt_lines():
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
        # Valid event 1
        f.write('{"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1", "timestamp": "2026-10-24T00:00:01Z"}\n')
        # Duplicate of event 1 (identical raw line)
        f.write('{"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1", "timestamp": "2026-10-24T00:00:01Z"}\n')
        # Corrupt JSON line
        f.write('{"invalid json line here\n')
        # Blank line
        f.write('   \n')
        tmp_name = f.name

    try:
        res = check_data_quality(tmp_name)
        assert res["lines"] == 4
        assert res["events"] == 1
        assert res["duplicates"] == 1
        assert res["errors"] == 2
        assert res["balance_passed"] is True
    finally:
        os.remove(tmp_name)


def test_quality_data_flags_gap_over_two_hours():
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
        f.write('{"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1", "timestamp": "2026-10-24T00:00:00Z"}\n')
        # 3 hours gap
        f.write('{"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1", "timestamp": "2026-10-24T03:00:00Z"}\n')
        tmp_name = f.name

    try:
        res = check_data_quality(tmp_name)
        assert res["continuity_passed"] is False
        assert len(res["gap_violations"]) == 1
        assert res["overall_passed"] is False
    finally:
        os.remove(tmp_name)
