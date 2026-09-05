"""Update checking, download, verification and hand-off to the installer.

The packaged Windows build installs updates silently. That is a deliberate
choice, and it puts this module in the position of downloading a binary and
executing it with no user interaction - so every step here fails *closed*:

* the owner/repo is hardcoded and nothing may redirect it,
* download URLs come only from the release's own ``assets`` array,
* redirects are followed one hop at a time against a host allowlist,
* a published SHA-256 must match, or the file is deleted and never run,
* downgrades and equal versions are refused,
* every attempt is written to an append-only log.

What none of that buys, stated plainly: SHA-256 proves **integrity, not
authenticity**. Anyone able to publish a release can publish a matching
checksum. See ``UPDATE_SIGNING_PUBLIC_KEY`` below for the cheap fix.

A pip-installed copy never self-installs; it only reports the upgrade command.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

import requests

from crypted_mail import __version__
from crypted_mail.config import AppPaths
from crypted_mail.core.exceptions import (
    UpdateCheckError,
    UpdateInstallError,
    UpdateVerificationError,
)


GITHUB_OWNER = "maliozturk"
GITHUB_REPO = "Crypted-Data-Share-Through-GMAIL"
GITHUB_LATEST_URL = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
GITHUB_RELEASES_PAGE = f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
PYPI_JSON_URL = "https://pypi.org/pypi/crypted-mail/json"
PYPI_PACKAGE = "crypted-mail"
CHECKSUM_ASSET_NAME = "SHA256SUMS.txt"

ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "pypi.org",
    }
)

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
DOWNLOAD_READ_TIMEOUT = 60.0
MAX_ASSET_BYTES = 200 * 1024 * 1024
MIN_ASSET_BYTES = 1 * 1024 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_REDIRECTS = 3
CHECK_INTERVAL_HOURS = 6
MAX_LOG_BYTES = 1024 * 1024
DOWNLOAD_CHUNK = 256 * 1024

DISABLE_ENV_VAR = "CRYPTED_MAIL_DISABLE_UPDATES"
DISABLE_SENTINEL = "DISABLED"

USER_AGENT = f"CryptedMail/{__version__} (+{GITHUB_RELEASES_PAGE})"

UNINSTALL_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    r"\{28868F7D-EF74-4171-A3C8-A0D486CEDE23}_is1"
)

# Strict on purpose: pre-releases, four-part versions and tags like "nightly"
# all fail to parse and are therefore ignored, with no extra filtering.
_VERSION_RE = re.compile(r"^v?(\d{1,5})\.(\d{1,5})\.(\d{1,5})$")
_SUM_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S.*)$")
_SAFE_ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")

# Windows process creation flags (subprocess exposes these only on Windows).
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


class UpdateChannel(str, Enum):
    GITHUB = "github"
    PYPI = "pypi"


@dataclass(frozen=True, slots=True)
class UpdateInfo:
    version: str
    version_tuple: tuple[int, int, int]
    channel: UpdateChannel
    release_url: str
    asset_name: str | None = None
    asset_url: str | None = None
    asset_size: int | None = None
    expected_sha256: str | None = None
    api_digest_sha256: str | None = None

    @property
    def installable(self) -> bool:
        """True only when there is a verified path to an installer."""
        return bool(self.asset_url and self.expected_sha256)


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    match = _VERSION_RE.match((text or "").strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse coreutils-style ``<hash>  <name>`` lines into ``{name: hash}``."""
    sums: dict[str, str] = {}
    for line in text.lstrip("﻿").splitlines():
        match = _SUM_LINE_RE.match(line.strip())
        if match:
            sums[match.group(2).strip()] = match.group(1).lower()
    return sums


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def executable_path() -> Path | None:
    """The real launcher path for a frozen build.

    In a PyInstaller onefile build ``__file__`` and ``sys._MEIPASS`` point into
    a temp tree that is deleted on exit. Only ``sys.executable`` is the
    installed exe.
    """
    return Path(sys.executable).resolve() if is_frozen() else None


def install_dir() -> Path | None:
    executable = executable_path()
    return executable.parent if executable else None


def registered_install_location() -> Path | None:
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
            value, _ = winreg.QueryValueEx(key, "InstallLocation")
    except (OSError, ImportError):
        return None
    return Path(value).resolve() if value else None


def is_managed_install() -> bool:
    """True only when this exe is the one our per-user installer placed.

    Without this check, running a portable copy out of Downloads would trigger
    an install into a *different* directory, leaving the user on the stale copy.
    """
    here = install_dir()
    registered = registered_install_location()
    return bool(here and registered and here == registered)


class UpdateService:
    def __init__(
        self,
        paths: AppPaths | None = None,
        current_version: str = __version__,
        *,
        channel: UpdateChannel | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.paths = paths or AppPaths.default()
        self.current_version = current_version
        self._channel = channel or (UpdateChannel.GITHUB if is_frozen() else UpdateChannel.PYPI)
        self._session = session

    # -- configuration ------------------------------------------------

    @property
    def channel(self) -> UpdateChannel:
        return self._channel

    def is_enabled(self) -> bool:
        """Three independent kill switches, any of which stops all checking."""
        if os.environ.get(DISABLE_ENV_VAR, "").strip() not in ("", "0", "false", "False"):
            return False
        if (self.paths.updates_dir / DISABLE_SENTINEL).exists():
            return False
        return True

    def can_self_install(self) -> bool:
        return self.is_enabled() and is_frozen() and is_managed_install()

    @staticmethod
    def pip_upgrade_command() -> str:
        return f"pip install -U {PYPI_PACKAGE}"

    def is_check_due(self, state) -> bool:
        now = datetime.now(timezone.utc)
        backoff = _parse_timestamp(getattr(state, "update_check_backoff_until", None))
        if backoff and now < backoff:
            return False
        last = _parse_timestamp(getattr(state, "last_update_check_at", None))
        if last and now - last < timedelta(hours=CHECK_INTERVAL_HOURS):
            return False
        return True

    # -- checking -----------------------------------------------------

    def check(self) -> UpdateInfo | None:
        if not self.is_enabled():
            return None
        if self._channel is UpdateChannel.PYPI:
            return self._check_pypi()
        return self._check_github()

    def check_quiet(self) -> UpdateInfo | None:
        """Check without ever raising.

        A DNS failure, a captive portal returning HTML, a proxy 407 or clock
        skew breaking TLS must never surface a dialog or delay app start.
        """
        try:
            return self.check()
        except Exception as exc:  # noqa: BLE001 - see docstring
            self.log(f"check failed: {type(exc).__name__}: {exc}")
            return None

    def _check_github(self) -> UpdateInfo | None:
        try:
            release = _get_json(GITHUB_LATEST_URL, session=self._session)
        except _NotFound:
            # No releases published yet. Not an error.
            self.log("no releases published yet")
            return None
        except _RateLimited as exc:
            self.log(f"rate limited until {exc.reset_at}")
            raise UpdateCheckError(f"GitHub rate limit reached; retrying after {exc.reset_at}.") from exc

        tag = release.get("tag_name")
        remote = parse_version(tag)
        if remote is None:
            self.log(f"ignoring unparseable tag: {tag!r}")
            return None
        current = parse_version(self.current_version)
        if current is None:
            self.log(f"local version {self.current_version!r} is not X.Y.Z; refusing to update")
            return None
        if remote <= current:
            if remote < current:
                self.log(f"refusing downgrade: remote {tag} < local {self.current_version}")
            return None

        version = ".".join(str(part) for part in remote)
        release_url = release.get("html_url") or GITHUB_RELEASES_PAGE
        info = UpdateInfo(
            version=version,
            version_tuple=remote,
            channel=UpdateChannel.GITHUB,
            release_url=release_url,
        )

        asset = _select_asset(release, version)
        if asset is None:
            self.log(f"{version}: no usable installer asset; notify-only")
            return info

        checksums = self._fetch_checksums(release)
        expected = checksums.get(asset["name"])
        if not expected:
            self.log(f"{version}: no published checksum for {asset['name']}; notify-only")
            return info

        return UpdateInfo(
            version=version,
            version_tuple=remote,
            channel=UpdateChannel.GITHUB,
            release_url=release_url,
            asset_name=asset["name"],
            asset_url=asset["browser_download_url"],
            asset_size=int(asset.get("size") or 0),
            expected_sha256=expected,
            api_digest_sha256=_parse_digest(asset.get("digest")),
        )

    def _fetch_checksums(self, release: dict) -> dict[str, str]:
        for asset in release.get("assets") or []:
            if asset.get("name") != CHECKSUM_ASSET_NAME:
                continue
            url = asset.get("browser_download_url") or ""
            if not _is_allowed_url(url):
                return {}
            try:
                return parse_sha256sums(
                    _get_text(url, session=self._session, max_bytes=MAX_CHECKSUM_BYTES)
                )
            except Exception as exc:  # noqa: BLE001
                self.log(f"could not read {CHECKSUM_ASSET_NAME}: {exc}")
                return {}
        return {}

    def _check_pypi(self) -> UpdateInfo | None:
        data = _get_json(PYPI_JSON_URL, session=self._session)
        current = parse_version(self.current_version)
        if current is None:
            return None
        best: tuple[int, int, int] | None = None
        for raw, files in (data.get("releases") or {}).items():
            parsed = parse_version(raw)
            if parsed is None:
                continue
            if files and all(item.get("yanked") for item in files):
                continue
            if best is None or parsed > best:
                best = parsed
        if best is None or best <= current:
            return None
        version = ".".join(str(part) for part in best)
        # Never installable: pip-upgrading the running interpreter's own
        # package is unreliable, so the UI only shows the command.
        return UpdateInfo(
            version=version,
            version_tuple=best,
            channel=UpdateChannel.PYPI,
            release_url=f"https://pypi.org/project/{PYPI_PACKAGE}/{version}/",
        )

    # -- download and verify -------------------------------------------

    def download(self, info: UpdateInfo, progress=None) -> Path:
        if not info.asset_url or not _is_allowed_url(info.asset_url):
            raise UpdateVerificationError("Refusing to download an update from an unexpected host.")
        target = self._target_path(info)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_suffix(target.suffix + ".part")
        self.log(f"downloading {info.asset_name} from {info.asset_url}")
        try:
            _stream_to_file(
                info.asset_url,
                staging,
                session=self._session,
                max_bytes=min(MAX_ASSET_BYTES, (info.asset_size or MAX_ASSET_BYTES) + DOWNLOAD_CHUNK),
                progress=progress,
            )
            os.replace(staging, target)
        except BaseException:
            staging.unlink(missing_ok=True)
            raise
        return target

    def verify(self, path: Path, info: UpdateInfo) -> None:
        path = Path(path)
        if not info.expected_sha256:
            path.unlink(missing_ok=True)
            raise UpdateVerificationError(
                "No published checksum for this release; refusing to install."
            )
        actual = sha256_file(path)
        self.log(
            f"verify {info.asset_name} expected={info.expected_sha256} "
            f"digest={info.api_digest_sha256} actual={actual}"
        )
        ok = hmac.compare_digest(actual, info.expected_sha256)
        if ok and info.api_digest_sha256:
            # Same TLS channel, so no independent trust - but a disagreement
            # between CI's checksum file and GitHub's stored digest is an
            # unambiguous abort signal.
            ok = hmac.compare_digest(actual, info.api_digest_sha256)
        if not ok:
            path.unlink(missing_ok=True)
            raise UpdateVerificationError(
                "The downloaded update failed its integrity check and was deleted."
            )

    def _target_path(self, info: UpdateInfo) -> Path:
        name = info.asset_name or ""
        if not _SAFE_ASSET_NAME_RE.match(name) or name != Path(name).name:
            raise UpdateVerificationError("Rejected update asset with an unsafe filename.")
        root = self.paths.updates_dir.resolve()
        target = (root / info.version / name).resolve()
        if root not in target.parents:
            raise UpdateVerificationError("Rejected update path outside the updates directory.")
        return target

    # -- install --------------------------------------------------------

    def launch_installer(self, installer: Path, version: str) -> None:
        if sys.platform != "win32":
            raise UpdateInstallError("Silent updates are only supported on Windows.")
        installer = Path(installer).resolve()
        root = self.paths.updates_dir.resolve()
        if root not in installer.parents:
            raise UpdateInstallError(
                "Refusing to run an installer from outside the updates directory."
            )

        setup_log = self.paths.updates_dir / version / "inno-setup.log"
        args = [
            str(installer),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/NOCANCEL",
            "/SP-",
            "/relaunch=1",
            f"/LOG={setup_log}",
        ]
        # Leaking the PyInstaller bootloader's state into a child is a known
        # footgun, so scrub it.
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"_MEIPASS2", "_PYI_ARCHIVE_FILE", "_PYI_APPLICATION_HOME_DIR"}
        }

        primary = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_BREAKAWAY_FROM_JOB
        fallback = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP
        for flags in (primary, fallback):
            try:
                subprocess.Popen(  # noqa: S603 - fixed argv, never shell=True
                    args,
                    creationflags=flags,
                    close_fds=True,
                    cwd=str(self.paths.updates_dir),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                break
            except OSError as exc:
                if flags is primary:
                    # The job object may forbid breakaway; retry without it.
                    self.log(f"breakaway failed, retrying without: {exc}")
                    continue
                raise UpdateInstallError(f"Could not start the update installer: {exc}") from exc
        self.log(f"launched installer {installer.name} for {version}")

    # -- housekeeping ---------------------------------------------------

    def cleanup_downloads(self, keep_version: str | None = None) -> None:
        try:
            root = self.paths.updates_dir
            if not root.is_dir():
                return
            for child in root.iterdir():
                if child.name in {"update.log", "update.log.1", DISABLE_SENTINEL}:
                    continue
                if child.is_dir() and child.name in {keep_version, self.current_version}:
                    continue
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
        except OSError as exc:
            self.log(f"cleanup failed: {exc}")

    def absorb_setup_log(self, version: str) -> None:
        """Fold the Inno Setup log from a completed update into our own."""
        setup_log = self.paths.updates_dir / version / "inno-setup.log"
        try:
            if setup_log.exists():
                self.log(f"--- inno setup log for {version} ---")
                self.log(setup_log.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            self.log(f"could not read setup log: {exc}")

    def log(self, message: str) -> None:
        """Append-only audit trail.

        If a user ever reports "my app changed on its own", this file is the
        only artefact that can say what happened.
        """
        try:
            path = self.paths.update_log_file
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
                os.replace(path, path.with_suffix(".log.1"))
            stamp = datetime.now(timezone.utc).isoformat()
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"{stamp} v{self.current_version} {message}\n")
        except OSError:
            pass


# ---------------------------------------------------------------------
# HTTP helpers. Module level so tests can monkeypatch them by string path.
# ---------------------------------------------------------------------


class _NotFound(Exception):
    pass


class _RateLimited(Exception):
    def __init__(self, reset_at: str) -> None:
        super().__init__(f"rate limited until {reset_at}")
        self.reset_at = reset_at


def _headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }


def _is_allowed_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == "https" and (parts.hostname or "") in ALLOWED_HOSTS


def _session_for(session: requests.Session | None) -> requests.Session:
    return session or requests.Session()


def _request(url: str, *, session, stream: bool, timeout):
    """Follow redirects one hop at a time, validating the host at each.

    Blindly following redirects is how a single compromised URL turns into
    "download from anywhere".
    """
    current = url
    http = _session_for(session)
    for _ in range(MAX_REDIRECTS + 1):
        if not _is_allowed_url(current):
            raise UpdateCheckError(f"Refusing to contact an unexpected host: {current}")
        response = http.get(
            current,
            headers=_headers(),
            timeout=timeout,
            stream=stream,
            allow_redirects=False,
        )
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            response.close()
            if not location:
                raise UpdateCheckError("Update server sent a redirect with no destination.")
            current = location
            continue
        if response.status_code == 404:
            response.close()
            raise _NotFound(url)
        if response.status_code in (403, 429) and response.headers.get("X-RateLimit-Remaining") == "0":
            reset = response.headers.get("X-RateLimit-Reset", "")
            response.close()
            raise _RateLimited(_reset_to_iso(reset))
        if response.status_code >= 400:
            code = response.status_code
            response.close()
            raise UpdateCheckError(f"Update server returned HTTP {code}.")
        return response
    raise UpdateCheckError("Too many redirects while contacting the update server.")


def _get_json(url: str, *, session=None, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT)) -> dict:
    response = _request(url, session=session, stream=False, timeout=timeout)
    try:
        if len(response.content) > MAX_JSON_BYTES:
            raise UpdateCheckError("Update server returned an implausibly large response.")
        return response.json()
    finally:
        response.close()


def _get_text(url: str, *, session=None, max_bytes: int = MAX_CHECKSUM_BYTES) -> str:
    response = _request(
        url, session=session, stream=False, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT)
    )
    try:
        content = response.content[: max_bytes + 1]
        if len(content) > max_bytes:
            raise UpdateCheckError("Checksum file is larger than expected.")
        return content.decode("utf-8", errors="replace")
    finally:
        response.close()


def _stream_to_file(url: str, dest: Path, *, session=None, max_bytes: int, progress=None) -> int:
    response = _request(
        url, session=session, stream=True, timeout=(CONNECT_TIMEOUT, DOWNLOAD_READ_TIMEOUT)
    )
    total = int(response.headers.get("Content-Length") or 0)
    written = 0
    try:
        with Path(dest).open("wb") as handle:
            for block in response.iter_content(chunk_size=DOWNLOAD_CHUNK):
                if not block:
                    continue
                written += len(block)
                if written > max_bytes:
                    raise UpdateVerificationError("The update download exceeded its declared size.")
                handle.write(block)
                if progress is not None:
                    progress(written, total)
    finally:
        response.close()
    return written


def _select_asset(release: dict, version: str) -> dict | None:
    """Pick the installer asset by exact name. URLs are never constructed."""
    wanted = f"CryptedMail-Setup-{version}.exe"
    for asset in release.get("assets") or []:
        if asset.get("name") != wanted:
            continue
        if asset.get("state") != "uploaded":
            return None
        size = int(asset.get("size") or 0)
        if not MIN_ASSET_BYTES <= size <= MAX_ASSET_BYTES:
            return None
        if not _is_allowed_url(asset.get("browser_download_url") or ""):
            return None
        return asset
    return None


def _parse_digest(value: str | None) -> str | None:
    if not value or not value.startswith("sha256:"):
        return None
    digest = value.split(":", 1)[1].strip().lower()
    return digest if len(digest) == 64 and _is_hex(digest) else None


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _reset_to_iso(reset: str) -> str:
    try:
        return datetime.fromtimestamp(int(reset), timezone.utc).isoformat()
    except (TypeError, ValueError):
        return datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
