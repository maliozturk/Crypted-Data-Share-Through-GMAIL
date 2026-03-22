# Crypted Mail

Crypted Mail is a Windows desktop app for encrypting message text, sending the encrypted payload through Gmail, and decrypting messages locally on your machine.

The normal workflow uses a shared passphrase. A legacy public-key workflow is also available in the `Advanced` tab for older messages and compatibility.

## What This App Is For

Use Crypted Mail when you want to:

- write a message in the Windows app
- encrypt it before it is sent
- send it through your Gmail account
- share the secret passphrase separately by phone, chat, or in person
- decrypt encrypted messages later inside the app

## Who This README Is For

This guide is for Windows users running the packaged `.exe` version of the app.

## Before You Start

You need:

1. A Windows machine
2. A Gmail account you will send from
3. A Google Cloud OAuth client secret JSON file for Gmail API access
4. The Crypted Mail Windows `.exe` or installer build

## Step 1: Get The App

Use the packaged Windows release provided for this project.

- a standalone `setup.exe` at setup_exe folder.
- or run build_installer.ps1 powershell script through a powershell.

If Windows SmartScreen appears, review the prompt and continue only if you trust the build source.

## Step 2: Create Your Google OAuth File

Crypted Mail sends mail through the Gmail API, so you must first create a Google OAuth desktop credential file.

In Google Cloud Console:

1. Create or open a project.
2. Enable the Gmail API.
3. Open `APIs & Services` -> `Credentials`.
4. Create an `OAuth client ID`.
5. Choose `Desktop app`.
6. Download the client secret JSON file.
7. Keep that file somewhere easy to browse to from the app.

Example filename:

- `client_secret.json`

## Step 3: Open The App And Complete Setup

When you launch Crypted Mail, start on the `Setup` tab.

Fill in:

- `Sender Gmail`
  Enter the Gmail address that will send messages.
- `OAuth secret JSON`
  Select the Google client secret JSON file you downloaded.

Then click:

- `Browse OAuth JSON` to pick the file
- `Connect Gmail` to start the Google sign-in flow

What happens next:

- Your browser opens for Google sign-in.
- You log into your Gmail account.
- You approve Gmail send access.
- The app stores the Gmail token locally on your Windows machine.

If setup succeeds, the app will show that Gmail is connected.

## Step 4: Optional Passphrase Memory

Still in the `Setup` tab, you can optionally configure a default passphrase:

- Enter a passphrase in `Default passphrase`
- Enable `Remember my default sender passphrase securely on this Windows machine`

If enabled, the app tries to store that passphrase using Windows credential storage so you can reuse it while composing messages.

This is optional. You can also type a passphrase manually each time.

## Step 5: Send Your First Encrypted Email

Open the `Compose` tab.

Fill in:

- `Recipient email`
- `Subject`
- `Passphrase`
- `Confirm passphrase`
- `Optional note`
- the main plaintext message box

Then click:

- `Encrypt And Send`

What the app does:

1. Encrypts your plaintext locally with the shared passphrase
2. Wraps the encrypted content into the email body
3. Sends the email through your connected Gmail account

If you saved a default passphrase earlier, you can click:

- `Use Remembered Passphrase`

That loads the remembered passphrase into the form automatically.

## Step 6: Tell The Recipient What They Need

The recipient needs:

- the email you sent
- the encrypted content inside it
- the same shared passphrase

Important:

- Do not send the passphrase in the same email.
- Share the passphrase through a different channel such as a phone call, Signal, WhatsApp, or in person.

## Step 7: Decrypt A Message

Open the `Decrypt` tab.

Then:

1. Paste the encrypted message block into the large input box.
2. If it is a shared-passphrase message, enter the passphrase into `Shared passphrase`.
3. Click `Decrypt`.

The app detects the message type automatically and shows the decrypted plaintext in the output box.

## The Normal User Workflow

For most users, only these tabs matter:

- `Setup`
- `Compose`
- `Decrypt`

That is the main desktop workflow.

## What The Advanced Tab Is For

The `Advanced` tab is for the older public-key workflow.

Use it only if:

- you already used older versions of Crypted Mail
- you need to decrypt old public-key messages
- you want to exchange public keys manually with recipients

The normal passphrase-based workflow does not require the `Advanced` tab.

## Legacy Public-Key Workflow

If you need the older public-key mode, the `Advanced` tab lets you:

- create a legacy local profile
- export your public key
- import recipient public keys
- send a legacy public-key encrypted message

Typical legacy flow:

1. Create a legacy local profile.
2. Export your public key and share it with the other person.
3. Import their public key into your app.
4. Send using `Encrypt And Send With Public Key`.
5. Decrypt legacy public-key messages in the `Decrypt` tab using `Legacy profile passphrase`.

If you do not already know you need this mode, you probably do not need it.

## Where The App Stores Data On Windows

The app stores its local files under:

```text
%USERPROFILE%\AppData\Local\CryptedMail
```

This includes items such as:

- app state
- Gmail token cache
- legacy profile data
- saved recipient keys

If passphrase remembering is enabled, the app also tries to use secure Windows credential storage.

## Security Notes

- The app uses Argon2id for key derivation and XSalsa20-Poly1305 authenticated encryption through NaCl `SecretBox`.
- A strong passphrase matters a lot. Use a long, hard-to-guess passphrase.
- Share the passphrase separately from the email itself.
- Anyone with both the encrypted message and the passphrase can decrypt it.

## Troubleshooting

If `Connect Gmail` fails:

- make sure the OAuth JSON file is the correct Google desktop client secret file
- make sure Gmail API is enabled in your Google Cloud project
- make sure the sender Gmail address is the account you authenticate with

If sending fails:

- reconnect Gmail in the `Setup` tab
- verify that the Gmail account is still connected
- verify the recipient email address is valid

If decrypting fails:

- confirm you pasted the full encrypted block
- confirm you entered the correct shared passphrase
- for old public-key messages, use the `Legacy profile passphrase` field instead

## Development

If you are developing the app from source:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
pytest
python -m crypted_mail.desktop.main
```

## Build The Windows App

To build the Windows executable and installer from source:

```powershell
python scripts/generate_icon.py
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

`build_installer.ps1` requires Inno Setup (`iscc`) to be installed and available on `PATH`.
