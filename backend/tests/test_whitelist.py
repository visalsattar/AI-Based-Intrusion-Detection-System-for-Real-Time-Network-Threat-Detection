import json

from ids_pipeline import _load_whitelist


def test_file_and_environment_whitelists_are_combined(tmp_path, monkeypatch):
    config = tmp_path / "whitelist.json"
    config.write_text(json.dumps({"whitelist": ["192.0.2.10", "not-an-ip"]}), encoding="utf-8")
    monkeypatch.setenv("IDS_WHITELIST", "198.51.100.7, 192.0.2.11")
    assert _load_whitelist(config) == {"192.0.2.10", "192.0.2.11", "198.51.100.7"}
