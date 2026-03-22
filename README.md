# Crypted Mail

Crypted Mail is a Python library for encrypting message text with a shared passphrase and sending the encrypted payload through Gmail from a Python script or a Jupyter notebook.

## What This Library Does

- Encrypts plaintext with a shared passphrase
- Sends the encrypted payload through the Gmail API
- Lets you decrypt the payload later with the same passphrase
- Works from normal Python scripts and notebooks without any UI

## Before You Start

You need:

1. Python 3.11 or newer
2. A Gmail account you will send from
3. A Google Cloud project with the Gmail API enabled
4. An OAuth client secret JSON file downloaded from Google Cloud

## Step 1: Install The Package

Install from PyPI:

```powershell
pip install crypted-mail
```

If you want to test from TestPyPI instead:

```powershell
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple crypted-mail
```

## Step 2: Create Google OAuth Credentials

To send email through Gmail, you need a Google OAuth client secret JSON file.

1. Open Google Cloud Console.
2. Create a new project or select an existing one.
3. Enable the Gmail API for that project.
4. Open `APIs & Services` -> `Credentials`.
5. Create an OAuth client ID.
6. Choose `Desktop app` as the application type.
7. Download the client secret JSON file.
8. Place that JSON file somewhere your script or notebook can read, for example:
   - `client_secret.json`

The first time you authenticate, Google will open a browser window so you can log in and approve Gmail access.

## Step 3: Authenticate Once And Save The Gmail Token

Run this once to complete the OAuth flow and save the returned token JSON for later reuse:

```python
from pathlib import Path

from crypted_mail import CryptedMailClient

client = CryptedMailClient()

credentials_json = client.connect_gmail_oauth("client_secret.json")

Path("gmail-token.json").write_text(credentials_json, encoding="utf-8")

print("Saved Gmail token to gmail-token.json")
```

What this does:

- Opens the Google OAuth flow in your browser
- Returns your Gmail credentials as a JSON string
- Saves those credentials into `gmail-token.json`

You can reuse that file in later runs so you do not need to authenticate every time.

## Step 4: Send An Encrypted Email

Once you have `gmail-token.json`, use it to encrypt a message and send it:

```python
from pathlib import Path

from crypted_mail import CryptedMailClient

client = CryptedMailClient()

credentials_json = Path("gmail-token.json").read_text(encoding="utf-8")

payload = client.encrypt_with_passphrase(
    plaintext="Hello Bob, here is the private update.",
    passphrase="correct horse battery staple",
    sender_hint="alice@example.com",
    note="Use the passphrase we agreed on by phone.",
)

message_id = client.send_encrypted_email(
    sender="alice@gmail.com",
    recipient_email="bob@example.com",
    subject="Encrypted message",
    armored_payload=payload,
    credentials_or_token=credentials_json,
)

print(f"Sent Gmail message: {message_id}")
print(payload)
```

What the recipient needs:

- The encrypted payload you sent
- The same shared passphrase

## Step 5: Encrypt And Send In One Call

If you prefer one step instead of separate encryption and send calls:

```python
from pathlib import Path

from crypted_mail import CryptedMailClient

client = CryptedMailClient()

credentials_json = Path("gmail-token.json").read_text(encoding="utf-8")

message_id = client.encrypt_and_send_with_passphrase(
    sender="alice@gmail.com",
    recipient_email="bob@example.com",
    subject="Encrypted message",
    plaintext="Hello Bob, here is the private update.",
    passphrase="correct horse battery staple",
    credentials_or_token=credentials_json,
    sender_hint="alice@example.com",
    note="Use the passphrase we agreed on by phone.",
)

print(f"Sent Gmail message: {message_id}")
```

## Step 6: Decrypt A Message

To decrypt an encrypted payload later, you only need the encrypted text and the shared passphrase:

```python
from crypted_mail import CryptedMailClient

client = CryptedMailClient()

armored_text = "cm1:..."  # paste the encrypted payload here

plaintext = client.decrypt_with_passphrase(
    armored_text=armored_text,
    passphrase="correct horse battery staple",
)

print(plaintext)
```

## Jupyter Notebook Example

If you want to use the package from a notebook, the flow is the same:

```python
from pathlib import Path

from crypted_mail import CryptedMailClient

client = CryptedMailClient()

credentials_json = Path("gmail-token.json").read_text(encoding="utf-8")

payload = client.encrypt_with_passphrase(
    plaintext="Notebook message",
    passphrase="correct horse battery staple",
)

client.send_encrypted_email(
    sender="alice@gmail.com",
    recipient_email="bob@example.com",
    subject="Encrypted notebook message",
    armored_payload=payload,
    credentials_or_token=credentials_json,
)
```

## API Summary

Main import:

```python
from crypted_mail import CryptedMailClient
```

Main methods:

- `connect_gmail_oauth(client_secret_path, account_email=None) -> str`
- `encrypt_with_passphrase(plaintext, passphrase, sender_hint=None, note=None) -> str`
- `decrypt_with_passphrase(armored_text, passphrase) -> str`
- `send_encrypted_email(sender, recipient_email, subject, armored_payload, credentials_or_token) -> str`
- `encrypt_and_send_with_passphrase(sender, recipient_email, subject, plaintext, passphrase, credentials_or_token, sender_hint=None, note=None) -> str`

## Security Notes

- The library uses Argon2id for key derivation and XSalsa20-Poly1305 authenticated encryption through NaCl `SecretBox`.
- The most important security factor is the strength of the shared passphrase.
- Use long, hard-to-guess passphrases and share them through a different communication channel than email.
- Anyone who has both the encrypted payload and the correct passphrase can decrypt the message.

## Common Workflow For New Users

1. Install the package.
2. Create Google OAuth desktop credentials.
3. Download the Google client secret JSON file.
4. Run `connect_gmail_oauth(...)` once.
5. Save the returned token JSON to a file like `gmail-token.json`.
6. Reuse that saved token JSON in your scripts or notebooks.
7. Encrypt text with `encrypt_with_passphrase(...)`.
8. Send it with `send_encrypted_email(...)` or `encrypt_and_send_with_passphrase(...)`.
9. Decrypt later with `decrypt_with_passphrase(...)`.

## Development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -U pip build twine
pip install -e .[dev]
pytest
python -m build
python -m twine check dist/*
```

## Publish To PyPI

Build the distributions:

```powershell
python -m build
python -m twine check dist/*
```

Upload to TestPyPI:

```powershell
python -m twine upload --repository testpypi dist/*
```

Upload to the real PyPI:

```powershell
python -m twine upload dist/*
```

After publishing, verify with a clean environment:

```powershell
pip install crypted-mail
```
