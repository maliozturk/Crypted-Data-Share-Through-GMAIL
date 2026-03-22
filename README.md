# Crypted Mail

Crypted Mail is a Windows-first Python desktop app that encrypts text for a recipient, sends the armored ciphertext through Gmail, and decrypts messages locally for the intended recipient.

The default workflow uses a shared passphrase (Model A). A legacy public-key mode remains available in the Advanced tab for backward compatibility.

## Development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
pytest
python -m crypted_mail.desktop.main
```

## Windows packaging

```powershell
python scripts/generate_icon.py
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

`build_installer.ps1` requires Inno Setup (`iscc`) to be installed and available on `PATH`.
