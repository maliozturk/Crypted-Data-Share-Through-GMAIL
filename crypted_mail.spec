# -*- mode: python ; coding: utf-8 -*-

import re
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

root = Path.cwd()
assets_dir = root / "src" / "crypted_mail" / "assets"

# Same single source of truth as pyproject.toml and the Inno Setup script.
_init_text = (root / "src" / "crypted_mail" / "__init__.py").read_text(encoding="utf-8")
app_version = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', _init_text, re.M).group(1)
_core = re.split(r"[-+]", app_version, maxsplit=1)[0].split(".")
_numbers = [int(part) for part in _core if part.isdigit()][:3]
while len(_numbers) < 3:
    _numbers.append(0)
# A Windows FILEVERSION resource must be exactly four integers.
file_version = tuple(_numbers) + (0,)

version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=file_version,
        prodvers=file_version,
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    "040904B0",
                    [
                        StringStruct("CompanyName", "Crypted Mail"),
                        StringStruct("FileDescription", "Crypted Mail"),
                        StringStruct("FileVersion", app_version),
                        StringStruct("InternalName", "CryptedMail"),
                        StringStruct("OriginalFilename", "Crypted Mail.exe"),
                        StringStruct("ProductName", "Crypted Mail"),
                        StringStruct("ProductVersion", app_version),
                    ],
                )
            ]
        ),
        VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
    ],
)

datas = [
    (str(assets_dir / "crypted_mail.ico"), "crypted_mail/assets"),
    (str(assets_dir / "crypted_mail_icon.svg"), "crypted_mail/assets"),
    (str(assets_dir / "crypted_mail.png"), "crypted_mail/assets"),
]

a = Analysis(
    ["src/crypted_mail/desktop/main.py"],
    pathex=[str(root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Crypted Mail",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(assets_dir / "crypted_mail.ico"),
    version=version_info,
)
