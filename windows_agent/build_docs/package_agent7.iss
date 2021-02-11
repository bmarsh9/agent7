; Author: Brendan Marshall

#define MyAppName "agent7" ;must match svc_name in program
#define MyAppVersion "1.0.0" ;UPDATE THIS WHEN COMPILING NEW CODE
#define MyAppPublisher "agent7"
#define MyAppURL "https://sec-eng.tech"
#define MyAppExeName "agent7.exe" ;must remain the same between updates
#define CompileProgramPath "C:\Users\bmarshall\Desktop\ww\ww_agent_source\dist\agent7.exe" ;path of program to compile on local system

#define Key "737e079a-6170-4aae-91a6-60aca1f213aa" ;command line switch: /key=value
#define Server "localhost" ;command line switch: /server=value
#define Group "default" ; group that the agent self-registers to on server: /group=value
#define VerifyTls "yes" ; verify server TLS cert (highly recommended!): /verifytls=<yes:no>
 
[Setup]
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{A122A84F-3B53-42A5-901A-369BD5F970D2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf64}\{#MyAppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputBaseFilename=agent7_installer
Compression=lzma
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Dirs]
Name: "{app}\temp"
Name: "{app}\data"
Name: "{app}\logs"

[Registry]                                        
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#MyAppName}"; ValueType: string; ValueName: "server"; ValueData: "{param:Server|{#Server}}"
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#MyAppName}"; ValueType: string; ValueName: "key"; ValueData: "{param:Key|{#Key}}"
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#MyAppName}"; ValueType: string; ValueName: "version"; ValueData: "{#MyAppVersion}"
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#MyAppName}"; ValueType: string; ValueName: "aid"; ValueData: {code:CreateAID}; Flags: createvalueifdoesntexist
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#MyAppName}"; ValueType: string; ValueName: "group"; ValueData: "{param:Group|{#Group}}"
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\{#MyAppName}"; ValueType: string; ValueName: "verifytls"; ValueData: "{param:VerifyTls|{#VerifyTls}}"



[Files]
Source: "{#CompileProgramPath}"; DestDir: "{app}"; BeforeInstall: UpdateService;Flags: ignoreversion

[InstallDelete]
Type: files ;Name: "{app}\{#MyAppExeName}_old"

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "install"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "start"; Flags: runhidden
Filename: "schtasks"; Parameters: "/Create /RU ""SYSTEM"" /F /SC HOURLY /TN ""{#MyAppName} Task"" /TR ""'{app}\{#MyAppExeName}' start"""; Flags: runhidden

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "remove"; Flags: runhidden
Filename: {sys}\sc.exe; Parameters: "stop {#MyAppExeName}" ; Flags: runhidden
Filename: {sys}\sc.exe; Parameters: "delete {#MyAppExeName}" ; Flags: runhidden
Filename: "schtasks"; Parameters: "/Delete /TN ""{#MyAppName} Task"" /F"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}\temp"
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\{#MyAppExeName}"

[Code]
var
  ResultCode: integer;

//Stop Service on updates so that we can backup/update the exe
procedure UpdateService;
begin
  sleep(5000);
  if FileExists(ExpandConstant('{app}\{#MyAppExeName}')) then begin //if exe exists
    Log('[DEBUG] Updating the service');
    if Exec(ExpandConstant('{app}\{#MyAppExeName}'),'stop','',SW_HIDE, ewWaitUntilTerminated,ResultCode) then begin
      Log(Format('[INFO] Successfully stopped the service. Exit code: %d', [ResultCode]));
      Log('[INFO] Replacing existing executable. Appending _old.');  
      RenameFile(ExpandConstant('{app}\{#MyAppExeName}'),ExpandConstant('{app}\{#MyAppExeName}_old'))
      Exec(ExpandConstant('{app}\{#MyAppExeName}'),'update','',SW_HIDE, ewWaitUntilTerminated,ResultCode)
    end
    else begin
      Log(Format('[ERROR] Unable to stop the service. Exit code: %d', [ResultCode]));
    end
  end;
  Log('[DEBUG] Existing executable not found. Likely the first install.');
  //Result:= True;
end;

function CreateAID(Param: String): String;
begin
  Result := IntToStr(+Random(100000000)+999999999)
end;
