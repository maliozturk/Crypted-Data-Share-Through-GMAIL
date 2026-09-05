; Crypted Mail installer.
;
; Built by scripts/build_installer.ps1, which passes the version in from
; src/crypted_mail/__init__.py. The #ifndef guards let a bare `iscc` still
; compile for local experiments - the 0.0.0-dev name makes it obvious that the
; result is not shippable.

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef AppFileVersion
  #define AppFileVersion "0.0.0.0"
#endif
#define AppExeName "Crypted Mail.exe"
#define RepoUrl "https://github.com/maliozturk/Crypted-Data-Share-Through-GMAIL"

[Setup]
AppId={{28868F7D-EF74-4171-A3C8-A0D486CEDE23}
AppName=Crypted Mail
AppVersion={#AppVersion}
AppVerName=Crypted Mail {#AppVersion}
AppPublisher=Crypted Mail
AppPublisherURL={#RepoUrl}
AppSupportURL={#RepoUrl}/issues
AppUpdatesURL={#RepoUrl}/releases
VersionInfoVersion={#AppFileVersion}
VersionInfoProductVersion={#AppFileVersion}

; Per-user install. {autopf} resolves to %LOCALAPPDATA%\Programs under
; PrivilegesRequired=lowest, so silent auto-updates never raise a UAC prompt.
; Keeping {autopf} (rather than hardcoding the path) preserves the /ALLUSERS
; escape hatch for managed deployments.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
DefaultDirName={autopf}\Crypted Mail
DefaultGroupName=Crypted Mail
DisableProgramGroupPage=yes
UninstallDisplayName=Crypted Mail
UninstallDisplayIcon={app}\{#AppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

OutputDir=..\dist\installer
OutputBaseFilename=CryptedMail-Setup-{#AppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\src\crypted_mail\assets\crypted_mail.ico

; Use the Restart Manager to close a running copy so the exe can be replaced.
; AppMutex is deliberately NOT set: combined with /VERYSILENT and
; /SUPPRESSMSGBOXES its "please close the application" prompt is suppressed and
; the default answer aborts the install. CloseApplications waits instead.
CloseApplications=yes
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
SetupMutex=CryptedMailSetupMutex

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\dist\Crypted Mail.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Crypted Mail"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\Crypted Mail"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Interactive install: the usual "Launch Crypted Mail" checkbox.
Filename: "{app}\{#AppExeName}"; Description: "Launch Crypted Mail"; \
    Flags: nowait postinstall skipifsilent

; Silent auto-update: skipifsilent means the entry above never fires, so this
; non-postinstall entry handles the relaunch. It runs only when the updating
; app passed /relaunch=1.
Filename: "{app}\{#AppExeName}"; Parameters: "--updated"; \
    Flags: nowait runasoriginaluser; Check: RelaunchRequested

[Code]
const
  { Kept forever: 0.1.0 installed machine-wide under this string AppId. }
  LegacyUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\CryptedMail_is1';

function RelaunchRequested(): Boolean;
begin
  Result := ExpandConstant('{param:relaunch|0}') = '1';
end;

function GetLegacyUninstaller(var Path: String): Boolean;
begin
  Result := RegQueryStringValue(HKLM, LegacyUninstallKey, 'UninstallString', Path);
  if not Result then
    Result := RegQueryStringValue(HKLM32, LegacyUninstallKey, 'UninstallString', Path);
  if Result and (Path <> '') then
    Path := RemoveQuotes(Path)
  else
    Result := False;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  UninstallPath: String;
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;

  if not GetLegacyUninstaller(UninstallPath) then
    Exit;

  { A silent auto-update must never raise UAC, so leave the old copy alone and
    let the app surface a notice instead. In practice this branch is a no-op:
    0.1.0 has no updater, so upgrading from it is always interactive. }
  if WizardSilent() then
  begin
    RegWriteStringValue(HKCU, 'Software\CryptedMail', 'LegacyInstallPending', UninstallPath);
    Exit;
  end;

  if MsgBox('An older machine-wide copy of Crypted Mail was found in Program Files.'#13#10 +
            'Remove it now? Windows will ask for administrator permission once.',
            mbConfirmation, MB_YESNO) = IDYES then
  begin
    if Exec(UninstallPath, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART',
            '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
      RegDeleteValue(HKCU, 'Software\CryptedMail', 'LegacyInstallPending');
  end;
end;
