"""Tests for local PKGBUILD directory scanning via ``--local``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import aurscan.cli as cli
import aurscan.pipeline as pipeline

FIXTURES = Path(__file__).parent / "fixtures"
INSTALL_PKGBUILD = """\
pkgname=hooks-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
install=hooks.install
"""


def _copy_fixture(tmp_path: Path, relative: str, target: str = "PKGBUILD") -> Path:
    path = tmp_path / target
    path.write_text((FIXTURES / relative).read_text(encoding="utf-8"), encoding="utf-8")
    return path


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if a local scan reaches for the network or a clone."""

    def unexpected(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("local scans must not use the network or clone")

    monkeypatch.setattr(cli, "fetch_meta", unexpected)
    monkeypatch.setattr(pipeline, "clone_package", unexpected)


def test_local_scan_reports_findings_and_risky_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _forbid_network(monkeypatch)
    _copy_fixture(tmp_path, "suspicious/download.PKGBUILD")

    assert cli.main(["--local", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "aurscan: download-demo" in out
    assert "version 1.0-1" in out
    assert "R01" in out
    assert "Local scan" in out
    assert str(tmp_path.resolve()) in out
    assert "maintainer" not in out
    assert "orphaned" not in out


def test_local_json_report_uses_parsed_package_and_synthetic_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _forbid_network(monkeypatch)
    _copy_fixture(tmp_path, "suspicious/download.PKGBUILD")

    assert cli.main(["--local", str(tmp_path), "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)

    assert payload["package"]["name"] == "download-demo"
    assert payload["package"]["version"] == "1.0-1"
    assert payload["package"]["maintainer"] is None
    assert payload["package"]["num_votes"] == 0
    assert payload["dependencies"] == []
    assert payload["errors"] == [
        "local scan: AUR metadata and history are not available"
    ]

    rule_ids = {finding["rule_id"] for finding in payload["findings"]}
    assert "R01" in rule_ids
    assert "M02" not in rule_ids
    assert "M04" not in rule_ids


def test_local_scan_reads_install_scripts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _forbid_network(monkeypatch)
    (tmp_path / "PKGBUILD").write_text(INSTALL_PKGBUILD, encoding="utf-8")
    _copy_fixture(tmp_path, "suspicious/hooks.install", "hooks.install")

    assert cli.main(["--local", str(tmp_path), "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)

    hooks = [item for item in payload["findings"] if item["file"] == "hooks.install"]
    assert hooks
    assert any(item["rule_id"] == "R11" for item in hooks)


def test_local_missing_path_exits_3(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--local", str(tmp_path / "missing")]) == 3
    err = capsys.readouterr().err
    assert "aurscan: error:" in err
    assert "not a directory" in err


def test_local_directory_without_pkgbuild_exits_3(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--local", str(tmp_path)]) == 3
    assert "could not read PKGBUILD" in capsys.readouterr().err


def test_local_conflicts_with_package_argument(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["demo", "--local", str(tmp_path)]) == 3
    assert "cannot be combined" in capsys.readouterr().err


def test_local_rejects_dependency_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _forbid_network(monkeypatch)
    _copy_fixture(tmp_path, "suspicious/download.PKGBUILD")

    assert cli.main(["--local", str(tmp_path), "--deps"]) == 3
    assert "not supported with --local" in capsys.readouterr().err
