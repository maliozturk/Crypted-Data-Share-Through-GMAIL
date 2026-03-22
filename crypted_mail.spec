# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

root = Path.cwd()
assets_dir = root / "src" / "crypted_mail" / "assets"

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
)
