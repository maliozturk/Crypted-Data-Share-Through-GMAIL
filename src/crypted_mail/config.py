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
