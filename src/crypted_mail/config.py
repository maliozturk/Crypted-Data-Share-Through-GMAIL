from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


APP_NAME = "Crypted Mail"
APP_DIR_NAME = "CryptedMail"


@dataclass(frozen=True)
class AppPaths:
    base_dir: Path
    state_file: Path
    profile_file: Path
    recipients_file: Path
    token_cache_file: Path

    # Derived paths are properties, not fields: AppPaths is frozen with five
    # required fields and is constructed explicitly in the tests, and a
    # derived path cannot drift out of base_dir.
    @property
    def updates_dir(self) -> Path:
        return self.base_dir / "updates"

    @property
    def update_log_file(self) -> Path:
        return self.updates_dir / "update.log"

    @classmethod
    def default(cls) -> "AppPaths":
        appdata = Path.home() / "AppData" / "Local" / APP_DIR_NAME
        return cls(
            base_dir=appdata,
            state_file=appdata / "state.json",
            profile_file=appdata / "profile.json",
            recipients_file=appdata / "recipients.json",
            token_cache_file=appdata / "tokens.json",
        )
