# Crypted Mail

Crypted Mail is a Windows desktop app for encrypting message text and file attachments, sending the encrypted payload through Gmail, and decrypting everything locally on your machine.

The normal workflow uses a shared passphrase. A legacy public-key workflow is also available in the `Advanced` tab for older messages and compatibility.

## What This App Is For

Use Crypted Mail when you want to:

- write a message in the Windows app
- attach `.zip` or `.tar.gz` archives
- encrypt the message and every attachment before anything is sent
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

Download the latest installer from the releases page:

<https://github.com/maliozturk/Crypted-Data-Share-Through-GMAIL/releases/latest>

- `CryptedMail-Setup-<version>.exe` - the installer (recommended)
- `CryptedMail-Portable-<version>.exe` - a single executable, no install
- `SHA256SUMS.txt` - checksums for both

Or build it yourself with `scripts/build_installer.ps1`.

Crypted Mail installs **per user**, into `%LOCALAPPDATA%\Programs\Crypted Mail`. It never asks for administrator rights.

To check your download before running it:

```powershell
Get-FileHash -Algorithm SHA256 .\CryptedMail-Setup-0.2.0.exe
```

Compare the result with `SHA256SUMS.txt`. If Windows SmartScreen appears, review the prompt and continue only if you trust the build source - these builds are not code-signed.

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

## Attaching Encrypted Files

In the `Compose` tab, the `Encrypted Attachments` box takes `.zip` and `.tar.gz` (or `.tgz`) archives.

1. Click `Add Archive...` and pick one or more archives.
2. Fill in the passphrase as usual and click `Encrypt And Send`.

Each archive is encrypted **on your machine** into its own `.cmenc` file - for example `report.zip` becomes `report.zip.cmenc` - and attached to the email. The message body still holds the encrypted text, plus a list of what was attached.

Notes:

- The same passphrase protects the message and every attachment.
- Total attachments are limited to about 18 MB, because Gmail caps a message at 25 MB.
- Only `.zip` and `.tar.gz` are accepted. This is a convenience check, not a security boundary.
- Large files are encrypted in a streaming fashion, so a big archive does not exhaust memory. The progress bar shows how far along it is and the window stays responsive.
- The *filename* of each attachment is visible to Gmail. The contents are not. If a filename itself is sensitive, rename the archive before attaching it.

## Step 6: Tell The Recipient What They Need

The recipient needs:

- the email you sent
- the encrypted content inside it
- any `.cmenc` attachments, saved to their machine
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

### Decrypting an attachment

If the email carried a `.cmenc` file, save it somewhere first, then in the same `Decrypt` tab:

1. Enter the shared passphrase in `Shared passphrase`.
2. Click `Open Encrypted File...` and pick the `.cmenc` file.
3. Click `Decrypt And Save As...` and choose where to write the recovered archive.

The app checks the recovered file against the SHA-256 recorded when it was encrypted and tells you when it verifies. If the passphrase is wrong, or the file was damaged or altered in transit, it refuses and writes nothing.

The filename shown before you decrypt comes from the file itself and is **not** verified until decryption succeeds, so treat it as a hint until then.

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

## Updates

Crypted Mail keeps itself up to date. On startup it checks the project's GitHub releases, and if a newer version is available it downloads the installer, verifies its SHA-256 against the published `SHA256SUMS.txt`, installs it silently and restarts. Because the app installs per user, this never raises a UAC prompt.

If the checksum does not match, the download is deleted and nothing is installed.

You can turn this off in the `Setup` tab by unchecking `Automatically install updates`, and you can check on demand with `Check for updates now`. Two other ways to disable updates entirely:

- set the environment variable `CRYPTED_MAIL_DISABLE_UPDATES=1`
- create an empty file at `%LOCALAPPDATA%\CryptedMail\updates\DISABLED`

Every update attempt is recorded in `%LOCALAPPDATA%\CryptedMail\updates\update.log`, including the expected and actual checksums.

The portable `.exe` does not install updates over itself; it tells you when a new version exists and links to the releases page.

### If you installed with pip

`pip install crypted-mail` gives you the Python library; `pip install crypted-mail[desktop]` adds the desktop app. In that case the app never installs anything itself - it checks PyPI and shows you the command to run:

```powershell
pip install -U crypted-mail
```

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

- Message text uses Argon2id for key derivation and XSalsa20-Poly1305 authenticated encryption through NaCl `SecretBox`.
- Attachments use Argon2id plus XChaCha20-Poly1305 in libsodium's *secretstream* mode, encrypted in 256 KiB chunks. Every chunk is authenticated, the chunk order is fixed, and the end of the stream is marked - so a truncated or edited `.cmenc` file is detected rather than silently producing partial output. The file header (filename, size, checksum, key-derivation settings) is authenticated too.
- A strong passphrase matters a lot. Use a long, hard-to-guess passphrase.
- Share the passphrase separately from the email itself.
- Anyone with both the encrypted message and the passphrase can decrypt it.
- Attachment filenames are visible to Gmail; their contents are not.
- Updates are verified by SHA-256 over HTTPS. That proves the download was not corrupted or swapped in transit, but the builds are **not code-signed**, so it does not prove who produced them. If you need a stronger guarantee, disable automatic updates and install releases manually after checking them yourself.
- While a message with attachments is being sent, the encrypted `.cmenc` copies live briefly in your temp folder and are deleted afterwards. Only ciphertext is written there, never your original files.

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

If an attachment will not decrypt:

- make sure you saved the whole `.cmenc` file, not a partial download
- confirm the passphrase matches the one used to send it
- a "damaged or modified" error means the file failed its authentication check; ask the sender to send it again

If sending fails with a size error:

- Gmail allows about 25 MB per message; Crypted Mail stops you at roughly 18 MB of attachments
- split the archive into smaller parts and send them separately

If updates are not installing:

- check `%LOCALAPPDATA%\CryptedMail\updates\update.log`
- confirm `Automatically install updates` is checked in the `Setup` tab
- the portable `.exe` never self-installs; use the installer build instead

## Development

If you are developing the app from source:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
$env:QT_QPA_PLATFORM = "offscreen"; pytest
python -m crypted_mail.desktop.main
```

The version lives in exactly one place, `src/crypted_mail/__init__.py`. `pyproject.toml`, the installer and the executable's version resource all derive from it, and CI refuses to publish a tag that disagrees with it. To release, bump that one line and push a matching `vX.Y.Z` tag.

## Build The Windows App

To build the Windows executable and installer from source:

```powershell
python scripts/generate_icon.py
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

`build_installer.ps1` requires Inno Setup (`iscc`) to be installed and available on `PATH`.
