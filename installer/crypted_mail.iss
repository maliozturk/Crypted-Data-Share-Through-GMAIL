[Setup]
AppId=CryptedMail
AppName=Crypted Mail
AppVersion=0.1.0
DefaultDirName={autopf}\Crypted Mail
DefaultGroupName=Crypted Mail
UninstallDisplayIcon={app}\Crypted Mail.exe
OutputDir=..\dist\installer
OutputBaseFilename=setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\src\crypted_mail\assets\crypted_mail.ico

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\dist\Crypted Mail.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Crypted Mail"; Filename: "{app}\Crypted Mail.exe"
Name: "{autodesktop}\Crypted Mail"; Filename: "{app}\Crypted Mail.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Crypted Mail.exe"; Description: "Launch Crypted Mail"; Flags: nowait postinstall skipifsilent
