from __future__ import annotations

import hashlib
import sys

import pytest

from crypted_mail.core.exceptions import (
    UpdateCheckError,
    UpdateInstallError,
    UpdateVerificationError,
)
from crypted_mail.services import update_service as us
from crypted_mail.services.update_service import (
    UpdateChannel,
    UpdateInfo,
    UpdateService,
    parse_sha256sums,
    parse_version,
)


DOWNLOAD_BASE = (
    "https://github.com/maliozturk/Crypted-Data-Share-Through-GMAIL/releases/download/v0.3.0"
)
SETUP_NAME = "CryptedMail-Setup-0.3.0.exe"


def _release(**overrides):
    asset = {
        "name": SETUP_NAME,
        "state": "uploaded",
        "size": 75_000_000,
        "digest": "sha256:" + "ab" * 32,
        "browser_download_url": f"{DOWNLOAD_BASE}/{SETUP_NAME}",
    }
    asset.update(overrides.pop("asset", {}))
    release = {
        "tag_name": "v0.3.0",
        "html_url": "https://github.com/maliozturk/Crypted-Data-Share-Through-GMAIL/releases/tag/v0.3.0",
        "assets": [
            asset,
            {
                "name": "SHA256SUMS.txt",
                "state": "uploaded",
                "size": 200,
                "browser_download_url": f"{DOWNLOAD_BASE}/SHA256SUMS.txt",
            },
        ],
    }
    release.update(overrides)
    return release


@pytest.fixture()
def service(app_paths, monkeypatch) -> UpdateService:
    monkeypatch.delenv(us.DISABLE_ENV_VAR, raising=False)
    return UpdateService(app_paths, current_version="0.2.0", channel=UpdateChannel.GITHUB)


def _stub_network(monkeypatch, release, sums_text: str | None = None):
    if sums_text is None:
        sums_text = f"{'cd' * 32}  {SETUP_NAME}\r\n"
    monkeypatch.setattr(us, "_get_json", lambda url, **kwargs: release)
    monkeypatch.setattr(us, "_get_text", lambda url, **kwargs: sums_text)


# -- version parsing ---------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0.2.0", (0, 2, 0)),
        ("v0.2.0", (0, 2, 0)),
        ("v10.20.30", (10, 20, 30)),
        ("0.2.0rc1", None),
        ("0.3.0-rc1", None),
        ("0.2", None),
        ("1.2.3.4", None),
        ("latest", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_version_accepts_and_rejects(text, expected):
    assert parse_version(text) == expected


def test_parse_sha256sums_handles_crlf_and_bom():
    text = "﻿" + f"{'aa' * 32}  {SETUP_NAME}\r\n" + f"{'bb' * 32}  other.exe\n"
    sums = parse_sha256sums(text)
    assert sums[SETUP_NAME] == "aa" * 32
    assert sums["other.exe"] == "bb" * 32


# -- checking ----------------------------------------------------------


def test_check_reports_newer_release(service, monkeypatch):
    _stub_network(monkeypatch, _release())
    info = service.check()
    assert info is not None
    assert info.version == "0.3.0"
    assert info.asset_name == SETUP_NAME
    assert info.expected_sha256 == "cd" * 32
    assert info.api_digest_sha256 == "ab" * 32
    assert info.installable


def test_check_returns_none_when_up_to_date(service, monkeypatch):
    _stub_network(monkeypatch, _release(tag_name="v0.2.0"))
    assert service.check() is None


def test_check_refuses_downgrade(service, monkeypatch, app_paths):
    _stub_network(monkeypatch, _release(tag_name="v0.1.0"))
    assert service.check() is None
    assert "downgrade" in app_paths.update_log_file.read_text(encoding="utf-8")


def test_check_ignores_prerelease_tag(service, monkeypatch):
    _stub_network(monkeypatch, _release(tag_name="v0.4.0-rc1"))
    assert service.check() is None


def test_check_treats_404_as_no_update(service, monkeypatch):
    def raise_404(url, **kwargs):
        raise us._NotFound(url)

    monkeypatch.setattr(us, "_get_json", raise_404)
    assert service.check() is None
    assert service.check_quiet() is None


def test_check_quiet_swallows_network_error(service, monkeypatch, app_paths):
    def boom(url, **kwargs):
        raise OSError("name resolution failed")

    monkeypatch.setattr(us, "_get_json", boom)
    assert service.check_quiet() is None
    assert "check failed" in app_paths.update_log_file.read_text(encoding="utf-8")


def test_rate_limit_raises_check_error(service, monkeypatch):
    def limited(url, **kwargs):
        raise us._RateLimited("2026-08-24T12:00:00+00:00")

    monkeypatch.setattr(us, "_get_json", limited)
    with pytest.raises(UpdateCheckError):
        service.check()
    assert service.check_quiet() is None


def test_asset_rejected_from_foreign_host(service, monkeypatch):
    _stub_network(
        monkeypatch,
        _release(asset={"browser_download_url": "https://evil.example.com/setup.exe"}),
    )
    info = service.check()
    assert info is not None and not info.installable


def test_asset_rejected_when_not_uploaded(service, monkeypatch):
    _stub_network(monkeypatch, _release(asset={"state": "starter"}))
    info = service.check()
    assert info is not None and not info.installable


@pytest.mark.parametrize("size", [500, 500 * 1024 * 1024])
def test_asset_rejected_on_implausible_size(service, monkeypatch, size):
    _stub_network(monkeypatch, _release(asset={"size": size}))
    info = service.check()
    assert info is not None and not info.installable


def test_missing_checksum_degrades_to_notify_only(service, monkeypatch):
    _stub_network(monkeypatch, _release(), sums_text="")
    info = service.check()
    assert info is not None
    assert not info.installable
    assert info.release_url.endswith("/tag/v0.3.0")


def test_check_disabled_by_env(service, monkeypatch):
    monkeypatch.setenv(us.DISABLE_ENV_VAR, "1")
    assert not service.is_enabled()
    assert service.check() is None


def test_check_disabled_by_sentinel_file(service, app_paths):
    app_paths.updates_dir.mkdir(parents=True, exist_ok=True)
    (app_paths.updates_dir / us.DISABLE_SENTINEL).touch()
    assert not service.is_enabled()


# -- verification ------------------------------------------------------


def _info(expected: str, digest: str | None = None) -> UpdateInfo:
    return UpdateInfo(
        version="0.3.0",
        version_tuple=(0, 3, 0),
        channel=UpdateChannel.GITHUB,
        release_url="https://example.invalid",
        asset_name=SETUP_NAME,
        asset_url=f"{DOWNLOAD_BASE}/{SETUP_NAME}",
        asset_size=10,
        expected_sha256=expected,
        api_digest_sha256=digest,
    )


def test_verify_accepts_matching_hash(service, tmp_path):
    path = tmp_path / SETUP_NAME
    path.write_bytes(b"installer bytes")
    digest = hashlib.sha256(b"installer bytes").hexdigest()
    service.verify(path, _info(digest, digest))
    assert path.exists()


def test_verify_rejects_mismatch_and_deletes(service, tmp_path):
    path = tmp_path / SETUP_NAME
    path.write_bytes(b"installer bytes")
    with pytest.raises(UpdateVerificationError):
        service.verify(path, _info("cd" * 32))
    assert not path.exists()


def test_verify_rejects_missing_checksum(service, tmp_path):
    path = tmp_path / SETUP_NAME
    path.write_bytes(b"x")
    with pytest.raises(UpdateVerificationError):
        service.verify(path, _info(None))


def test_verify_rejects_digest_disagreement(service, tmp_path):
    path = tmp_path / SETUP_NAME
    path.write_bytes(b"installer bytes")
    real = hashlib.sha256(b"installer bytes").hexdigest()
    with pytest.raises(UpdateVerificationError):
        service.verify(path, _info(real, "ab" * 32))
    assert not path.exists()


def test_target_path_rejects_traversal(service):
    info = UpdateInfo(
        version="0.3.0",
        version_tuple=(0, 3, 0),
        channel=UpdateChannel.GITHUB,
        release_url="https://example.invalid",
        asset_name="..\\..\\evil.exe",
        asset_url=f"{DOWNLOAD_BASE}/x",
        expected_sha256="ab" * 32,
    )
    with pytest.raises(UpdateVerificationError):
        service._target_path(info)


def test_download_rejects_foreign_host(service):
    info = UpdateInfo(
        version="0.3.0",
        version_tuple=(0, 3, 0),
        channel=UpdateChannel.GITHUB,
        release_url="https://example.invalid",
        asset_name=SETUP_NAME,
        asset_url="https://evil.example.com/setup.exe",
        expected_sha256="ab" * 32,
    )
    with pytest.raises(UpdateVerificationError):
        service.download(info)


# -- install hand-off ---------------------------------------------------


def test_launch_installer_flags(service, monkeypatch, app_paths):
    monkeypatch.setattr(sys, "platform", "win32")
    recorded = {}

    class FakePopen:
        def __init__(self, args, **kwargs):
            recorded["args"] = args
            recorded["kwargs"] = kwargs

    monkeypatch.setattr(us.subprocess, "Popen", FakePopen)

    installer = app_paths.updates_dir / "0.3.0" / SETUP_NAME
    installer.parent.mkdir(parents=True, exist_ok=True)
    installer.write_bytes(b"setup")
    service.launch_installer(installer, "0.3.0")

    args = recorded["args"]
    assert "/VERYSILENT" in args
    assert "/SUPPRESSMSGBOXES" in args
    assert "/NORESTART" in args
    assert "/relaunch=1" in args
    flags = recorded["kwargs"]["creationflags"]
    assert flags & us._DETACHED_PROCESS
    assert flags & us._CREATE_NEW_PROCESS_GROUP
    assert "_MEIPASS2" not in recorded["kwargs"]["env"]


def test_launch_installer_refuses_outside_updates_dir(service, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    called = {}
    monkeypatch.setattr(
        us.subprocess, "Popen", lambda *a, **k: called.setdefault("ran", True)
    )
    stray = tmp_path / "elsewhere.exe"
    stray.write_bytes(b"setup")
    with pytest.raises(UpdateInstallError):
        service.launch_installer(stray, "0.3.0")
    assert "ran" not in called


# -- pypi channel --------------------------------------------------------


def test_pypi_channel_is_notify_only(app_paths, monkeypatch):
    monkeypatch.delenv(us.DISABLE_ENV_VAR, raising=False)
    service = UpdateService(app_paths, current_version="0.2.0", channel=UpdateChannel.PYPI)
    monkeypatch.setattr(
        us,
        "_get_json",
        lambda url, **kwargs: {"releases": {"0.2.0": [{}], "0.3.0": [{}]}},
    )
    info = service.check()
    assert info is not None
    assert info.version == "0.3.0"
    assert not info.installable
    assert UpdateService.pip_upgrade_command() == "pip install -U crypted-mail"


def test_pypi_skips_fully_yanked_release(app_paths, monkeypatch):
    monkeypatch.delenv(us.DISABLE_ENV_VAR, raising=False)
    service = UpdateService(app_paths, current_version="0.1.0", channel=UpdateChannel.PYPI)
    monkeypatch.setattr(
        us,
        "_get_json",
        lambda url, **kwargs: {
            "releases": {
                "0.2.0": [{"yanked": False}],
                "0.3.0": [{"yanked": True}, {"yanked": True}],
            }
        },
    )
    assert service.check().version == "0.2.0"


# -- housekeeping ---------------------------------------------------------


def test_cleanup_removes_stale_version_dirs(service, app_paths):
    for name in ("0.1.9", "0.3.0", "0.2.0"):
        (app_paths.updates_dir / name).mkdir(parents=True, exist_ok=True)
    service.cleanup_downloads(keep_version="0.3.0")
    remaining = {child.name for child in app_paths.updates_dir.iterdir() if child.is_dir()}
    # 0.2.0 is the running version and is also preserved.
    assert remaining == {"0.3.0", "0.2.0"}


def test_log_rotates_when_large(service, app_paths, monkeypatch):
    monkeypatch.setattr(us, "MAX_LOG_BYTES", 100)
    for index in range(40):
        service.log(f"line {index} " + "x" * 20)
    assert app_paths.update_log_file.exists()
    assert app_paths.update_log_file.with_suffix(".log.1").exists()


def test_is_check_due_respects_interval_and_backoff(service):
    from datetime import datetime, timedelta, timezone

    from crypted_mail.core.models import AppState

    state = AppState()
    assert service.is_check_due(state)

    state.last_update_check_at = datetime.now(timezone.utc).isoformat()
    assert not service.is_check_due(state)

    state.last_update_check_at = (
        datetime.now(timezone.utc) - timedelta(hours=12)
    ).isoformat()
    assert service.is_check_due(state)

    state.update_check_backoff_until = (
        datetime.now(timezone.utc) + timedelta(hours=1)
    ).isoformat()
    assert not service.is_check_due(state)


def test_is_allowed_url_rejects_plain_http():
    assert not us._is_allowed_url("http://github.com/x")
    assert us._is_allowed_url("https://github.com/x")
    assert not us._is_allowed_url("https://github.com.evil.test/x")
