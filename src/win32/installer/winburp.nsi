; winburp.nsi

!define PRODUCT "Burp"

;
; Include the Modern UI
;

!include "MUI.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "Sections.nsh"
!include "StrFunc.nsh"
!include "WinMessages.nsh"
;
; Basics
;
Name "Burp"
OutFile "${OUT_DIR}\burp-win${BITS}-installer-${VERSION}.exe"
SetCompressor lzma
InstallDir "C:\Program Files\Burp"
InstallDirRegKey HKLM "Software\Burp" "InstallLocation"

InstType "Burp"
InstType "Client"
;InstType "Server"
;InstType "Full"

!insertmacro GetParent

${StrCase}
${StrTok}
${StrTrimNewLines}

;
; Pull in pages
;

!define      MUI_COMPONENTSPAGE_SMALLDESC

!define      MUI_HEADERIMAGE
!define      MUI_BGCOLOR                FFFFFF
;!define      MUI_HEADERIMAGE_BITMAP     "burp-logo.bmp"

!define      MUI_WELCOMEPAGE_TITLE      "Welcome to the Burp setup wizard, version ${VERSION}."
!InsertMacro MUI_PAGE_WELCOME
!define      MUI_PAGE_CUSTOMFUNCTION_SHOW PageComponentsShow
; !InsertMacro MUI_PAGE_COMPONENTS
!define      MUI_PAGE_CUSTOMFUNCTION_PRE PageDirectoryPre
!InsertMacro MUI_PAGE_DIRECTORY
Page custom EnterConfigPage1
Page custom EnterConfigPage2
; Page custom EnterConfigPage2 LeaveConfigPage2
!Define      MUI_PAGE_CUSTOMFUNCTION_LEAVE LeaveInstallPage
!InsertMacro MUI_PAGE_INSTFILES
!InsertMacro MUI_PAGE_FINISH

!InsertMacro MUI_UNPAGE_WELCOME
!InsertMacro MUI_UNPAGE_CONFIRM
!InsertMacro MUI_UNPAGE_INSTFILES
!InsertMacro MUI_UNPAGE_FINISH

!define      MUI_ABORTWARNING

!InsertMacro MUI_LANGUAGE "English"

!InsertMacro GetParameters
!InsertMacro GetOptions

DirText "Setup will install Burp ${VERSION} to the directory specified below. To install in a different folder, click Browse and select another folder."

!InsertMacro MUI_RESERVEFILE_INSTALLOPTIONS
;
; Global Variables
;
Var OptService
Var OptStart
Var OptSilent

Var CommonFilesDone

Var OsIsNT

Var HostName
Var DNSDomain

Var ConfigClientPassword
Var ConfigClientInstallService
Var ConfigClientStartService

Var ConfigServerAddress
Var ConfigServerPort
Var ConfigClientName
Var ConfigPassword
Var ConfigPoll
Var ConfigAutoupgrade

Var ConfigMonitorPassword

Var LocalHostAddress

Var AutomaticInstall

Var OldInstallDir
Var PreviousComponents
Var NewComponents

; Bit 0 = File Service
;     1 = Storage Service
;     2 = Director Service
;     3 = Command Console
;     4 = Graphical Console
;     5 = Documentation (PDF)
;     6 = Documentation (HTML)

!define ComponentFile                   1
!define ComponentStorage                2
!define ComponentDirector               4
!define ComponentTextConsole            8
!define ComponentGUIConsole             16
!define ComponentPDFDocs                32
!define ComponentHTMLDocs               64

!define ComponentsRequiringUserConfig           31
!define ComponentsFileAndStorage                3
!define ComponentsFileAndStorageAndDirector     7
!define ComponentsDirectorAndTextGuiConsoles    28
!define ComponentsTextAndGuiConsoles            24

Function .onInit
  Push $R0
  Push $R1

  ; Process Command Line Options
  StrCpy $OptService 1
  StrCpy $OptStart 1
  StrCpy $OptSilent 0
  StrCpy $CommonFilesDone 0
  StrCpy $OsIsNT 0
  StrCpy $AutomaticInstall 1
  StrCpy $OldInstallDir ""
  StrCpy $PreviousComponents 0
  StrCpy $NewComponents 0

  ${GetParameters} $R0

  ClearErrors
  ${GetOptions} $R0 "/noservice" $R1
  IfErrors +2
    StrCpy $OptService 0

  ClearErrors
  ${GetOptions} $R0 "/nostart" $R1
  IfErrors +2
    StrCpy $OptStart 0

  IfSilent 0 +2
    StrCpy $OptSilent 1

  ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  ${If} $R0 != ""
    StrCpy $OsIsNT 1
  ${EndIf}

  Call GetComputerName
  Pop $HostName

  Call GetHostName
  Pop $LocalHostAddress

  StrCpy $DNSDomain ""
  Call GetDNSDomain
  Pop $DNSDomain

  Call GetUserName

  ; Configuration Defaults

  StrCpy $ConfigClientInstallService     "$OptService"
  StrCpy $ConfigClientStartService       "$OptStart"

  StrCpy $ConfigServerAddress		"10.0.0.1"
  StrCpy $ConfigServerPort              "4971"
  StrCpy $ConfigClientName              "clientname"
  StrCpy $ConfigPassword                "password"
  StrCpy $ConfigPoll                    "20"
  StrCpy $ConfigAutoupgrade		"1"

  InitPluginsDir

  File "/oname=$PLUGINSDIR\libeay32.dll" "${SRC_DIR}\libeay32.dll"
  File "/oname=$PLUGINSDIR\ssleay32.dll" "${SRC_DIR}\ssleay32.dll"
  File "/oname=$PLUGINSDIR\libpcre-1.dll" "${SRC_DIR}\libpcre-1.dll"
  File "/oname=$PLUGINSDIR\libpcreposix-0.dll" "${SRC_DIR}\libpcreposix-0.dll"

  !InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage1.ini"
  !InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage2.ini"

  SetPluginUnload alwaysoff

;  nsExec::Exec '"$PLUGINSDIR\openssl.exe" rand -base64 -out $PLUGINSDIR\pw.txt 33'
  pop $R0
  ${If} $R0 = 0
   FileOpen $R1 "$PLUGINSDIR\pw.txt" r
   IfErrors +4
     FileRead $R1 $R0
     ${StrTrimNewLines} $ConfigClientPassword $R0
     FileClose $R1
  ${EndIf}

  SetPluginUnload manual

;  nsExec::Exec '"$PLUGINSDIR\openssl.exe" rand -base64 -out $PLUGINSDIR\pw.txt 33'
  pop $R0
  ${If} $R0 = 0
   FileOpen $R1 "$PLUGINSDIR\pw.txt" r
   IfErrors +4
     FileRead $R1 $R0
     ${StrTrimNewLines} $ConfigMonitorPassword $R0
     FileClose $R1
  ${EndIf}

  Pop $R1
  Pop $R0
FunctionEnd

Function .onSelChange
  Call UpdateComponentUI
FunctionEnd

Function InstallCommonFiles
  ${If} $CommonFilesDone = 0
    SetOutPath "$INSTDIR"
    ; File "Readme.txt"

    SetOutPath "$INSTDIR\bin"
    File "${SRC_DIR}\libeay32.dll"
    File "${SRC_DIR}\ssleay32.dll"

    File "${SRC_DIR}\libpcreposix-0.dll"
    File "${SRC_DIR}\libpcre-1.dll"
    File "${SRC_DIR}\zlib1.dll"
    File "${SRC_DIR}\libgcc_s_sjlj-1.dll"

    File "${SRC_DIR}\burp.dll"

    File "${SRC_DIR}\openssl.exe"

    File "${SRC_DIR}\burp_ca.bat"

    StrCpy $CommonFilesDone 1
  ${EndIf}
FunctionEnd

Section "-Initialize"

  WriteRegStr   HKLM Software\Burp InstallLocation "$INSTDIR"

  Call GetSelectedComponents
  Pop $R2
  WriteRegDWORD HKLM Software\Burp Components $R2

  ; remove start menu items
  SetShellVarContext all

  Delete /REBOOTOK "$SMPROGRAMS\Burp\Configuration\*"
  Delete /REBOOTOK "$SMPROGRAMS\Burp\Documentation\*"
  Delete /REBOOTOK "$SMPROGRAMS\Burp\*"
  RMDir "$SMPROGRAMS\Burp\Configuration"
  RMDir "$SMPROGRAMS\Burp\Documentation"
  RMDir "$SMPROGRAMS\Burp"
  CreateDirectory "$SMPROGRAMS\Burp"
  ; CreateDirectory "$SMPROGRAMS\Burp\Configuration"
  ; CreateDirectory "$SMPROGRAMS\Burp\Documentation"

  CreateDirectory "$INSTDIR"
  CreateDirectory "$INSTDIR\bin"
  CreateDirectory "$INSTDIR\CA"

  SetOutPath "$INSTDIR"

  IfFileExists $INSTDIR\burp.conf end
  FileOpen $R1 $INSTDIR\burp.conf w

!If "$BITS" == "32"
  StrCpy $R2 "32"
!Else
  StrCpy $R2 "64"
!EndIf

  Call GetHostName
  Exch $R3
  Pop $R3

  FileWrite $R1 "mode = client$\r$\n"
  FileWrite $R1 "server = $ConfigServerAddress$\r$\n"
  FileWrite $R1 "port = $ConfigServerPort$\r$\n"
  FileWrite $R1 "cname = $ConfigClientName$\r$\n"
  FileWrite $R1 "password = $ConfigPassword$\r$\n"
  ${If} ${FileExists} "C:/Users"
    FileWrite $R1 "include = C:/Users$\r$\n"
  ${Else}
    ${If} ${FileExists} "C:/Documents and Settings"
      FileWrite $R1 "include = C:/Documents and Settings$\r$\n"
    ${Else}
      FileWrite $R1 "include = C:/$\r$\n"
    ${EndIf}
  ${EndIf}
  FileWrite $R1 "nobackup = .nobackup$\r$\n"
  FileWrite $R1 "lockfile = C:/Program Files/Burp/lockfile$\r$\n"
  FileWrite $R1 "ca_burp_ca = C:/Program Files/Burp/bin/burp_ca.bat$\r$\n"
  FileWrite $R1 "ca_csr_dir = C:/Program Files/Burp/CA$\r$\n"
  FileWrite $R1 "ssl_cert_ca = C:/Program Files/Burp/ssl_cert_ca.pem$\r$\n"
  FileWrite $R1 "ssl_cert = C:/Program Files/Burp/ssl_cert-client.pem$\r$\n"
  FileWrite $R1 "ssl_key = C:/Program Files/Burp/ssl_cert-client.key$\r$\n"
  FileWrite $R1 "ssl_key_password = password$\r$\n"
  FileWrite $R1 "ssl_peer_cn = burpserver$\r$\n"
!if "${BITS}" == "32"
  FileWrite $R1 "autoupgrade_os = win32$\r$\n"
!endif
!if "${BITS}" == "64"
  FileWrite $R1 "autoupgrade_os = win64$\r$\n"
!endif
  ${If} $ConfigAutoupgrade == "0"
    FileWrite $R1 "# autoupgrade_dir = C:/Program Files/Burp/autoupgrade$\r$\n"
  ${EndIf}
  ${If} $ConfigAutoupgrade != "0"
    FileWrite $R1 "autoupgrade_dir = C:/Program Files/Burp/autoupgrade$\r$\n"
  ${EndIf}

  FileClose $R1

  ${If} $ConfigPoll != 0
    nsExec::ExecToLog 'schtasks /CREATE /RU SYSTEM /TN "burp cron" /TR "\"C:\Program Files\Burp\bin\burp.exe\" -a t" /SC MINUTE /MO $ConfigPoll'
  ${EndIf}

end:
  DetailPrint "$INSTDIR\burp.conf already exists. Not overwriting."

SectionEnd

SectionGroup "Client" SecGroupClient

Section "File Service" SecFileDaemon
  SectionIn 1 2 3

  Call InstallCommonFiles
  File "${SRC_DIR}\burp.exe"
SectionEnd

SectionGroupEnd

Section "-Finish"
  Push $R0

  ; Write the uninstall keys for Windows & create Start Menu entry
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "DisplayName" "Burp"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "DisplayVersion" "${VERSION}"
  ${StrTok} $R0 "${VERSION}" "." 0 0
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "VersionMajor" $R0
  ${StrTok} $R0 "${VERSION}" "." 1 0
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "VersionMinor" $R0
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "NoRepair" 1
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "URLUpdateInfo" "http://sourceforge.net/project/showfiles.php?group_id=50727"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "URLInfoAbout" "http://www.burp.org"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "HelpLink" "http://www.burp.org/?page=support"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortCut "$SMPROGRAMS\Burp\Uninstall Burp.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0
  Pop $R0
SectionEnd

; Extra Page descriptions

LangString DESC_SecFileDaemon ${LANG_ENGLISH} "Install Burp on this system."

LangString TITLE_ConfigPage1 ${LANG_ENGLISH} "Configuration"
LangString SUBTITLE_ConfigPage1 ${LANG_ENGLISH} "Set installation configuration."

LangString TITLE_ConfigPage2 ${LANG_ENGLISH} "Configuration (continued)"
LangString SUBTITLE_ConfigPage2 ${LANG_ENGLISH} "Set installation configuration."

!InsertMacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !InsertMacro MUI_DESCRIPTION_TEXT ${SecFileDaemon} $(DESC_SecFileDaemon)
!InsertMacro MUI_FUNCTION_DESCRIPTION_END

; Uninstall section

UninstallText "This will uninstall Burp. Click Uninstall to continue."

Section "Uninstall"
  ; Shutdown any baculum that could be running
;  nsExec::ExecToLog '"$INSTDIR\bin\burp.exe" /kill'
;  Sleep 3000

  ReadRegDWORD $R0 HKLM "Software\Burp" "Service_Burp"
  ${If} $R0 = 1
    ; Remove burp service
;    nsExec::ExecToLog '"$INSTDIR\bin\burp.exe" /remove'
  ${EndIf}
  
  ; remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Burp"
  DeleteRegKey HKLM "Software\Burp"

  ; remove start menu items
  SetShellVarContext all
  Delete /REBOOTOK "$SMPROGRAMS\Burp\*"
  RMDir "$SMPROGRAMS\Burp"
  Delete /REBOOTOK "$SMPROGRAMS\Startup\Burp Update.lnk"

  ; remove files and uninstaller (preserving config for now)
  Delete /REBOOTOK "$INSTDIR\autoupgrade\*"
  Delete /REBOOTOK "$INSTDIR\bin\*"
  Delete /REBOOTOK "$INSTDIR\*"

  ; stop and delete the burp service
  ;nsExec::Exec "sc stop burp"
  ;nsExec::Exec "sc delete burp"

  nsExec::Exec 'schtasks /DELETE /TN "burp cron" /F'

  Delete /REBOOTOK "$PLUGINSDIR\burp*.conf"
  Delete /REBOOTOK "$PLUGINSDIR\openssl.exe"
  Delete /REBOOTOK "$PLUGINSDIR\libeay32.dll"
  Delete /REBOOTOK "$PLUGINSDIR\ssleay32.dll"

  ; remove directories used
  RMDir "$INSTDIR\autoupgrade"
  RMDir "$INSTDIR\bin"
  RMDir "$INSTDIR"
SectionEnd

Function GetComputerName
  Push $R0
  Push $R1
  Push $R2

  System::Call "kernel32::GetComputerNameA(t .R0, *i ${NSIS_MAX_STRLEN} R1) i.R2"

  ${StrCase} $R0 $R0 "L"

  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

!define ComputerNameDnsFullyQualified   3

Function GetHostName
  Push $R0
  Push $R1
  Push $R2

  ${If} $OsIsNT = 1
    System::Call "kernel32::GetComputerNameExA(i ${ComputerNameDnsFullyQualified}, t .R0, *i ${NSIS_MAX_STRLEN} R1) i.R2 ?e"
    ${If} $R2 = 0
      Pop $R2
      DetailPrint "GetComputerNameExA failed - LastError = $R2"
      Call GetComputerName
      Pop $R0
    ${Else}
      Pop $R2
    ${EndIf}
  ${Else}
    Call GetComputerName
    Pop $R0
  ${EndIf}

  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

!define ComputerNameDnsDomain   2

Function GetDNSDomain
  Push $R0
  Push $R1
  Push $R2

  System::Call "kernel32::GetComputerNameExA(i ${ComputerNameDnsDomain}, t .R0, *i ${NSIS_MAX_STRLEN} R1) i.R2 ?e"

  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

!define NameUserPrincipal 8

Function GetUserName
  Push $R0
  Push $R1
  Push $R2

  ${If} $OsIsNT = 1
    System::Call "secur32::GetUserNameExA(i ${NameUserPrincipal}, t .R0, *i ${NSIS_MAX_STRLEN} R1) i.R2 ?e"
    ${If} $R2 = 0
      Pop $R2
      DetailPrint "GetUserNameExA failed - LastError = $R2"
      Pop $R0
      StrCpy $R0 ""
    ${Else}
      Pop $R2
    ${EndIf}
  ${Else}
      StrCpy $R0 ""
  ${EndIf}

  ${If} $R0 == ""
    System::Call "advapi32::GetUserNameA(t .R0, *i ${NSIS_MAX_STRLEN} R1) i.R2 ?e"
    ${If} $R2 = 0
      Pop $R2
      DetailPrint "GetUserNameA failed - LastError = $R2"
      StrCpy $R0 ""
    ${Else}
      Pop $R2
    ${EndIf}
  ${EndIf}

  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

Function GetSelectedComponents
  Push $R0
  StrCpy $R0 0
  ${If} ${SectionIsSelected} ${SecFileDaemon}
    IntOp $R0 $R0 | ${ComponentFile}
    IntOp $R0 $R0 | ${SF_SELECTED}
  ${EndIf}
  Exch $R0
FunctionEnd

Function PageComponentsShow

  Call UpdateComponentUI
FunctionEnd

Function PageDirectoryPre
  ${If} $AutomaticInstall = 1
    Abort
  ${EndIf}
FunctionEnd

Function LeaveInstallPage
  Push "$INSTDIR\install.log"
  Call DumpLog
FunctionEnd

Function UpdateComponentUI
  Push $R0
  Push $R1

  Call GetSelectedComponents
  Pop $R0

  IntOp $R1 $R0 ^ $PreviousComponents
  IntOp $NewComponents $R0 & $R1

  GetDlgItem $R0 $HWNDPARENT 1

  IntOp $R1 $NewComponents & ${ComponentsRequiringUserConfig}
  ${If} $R1 = 0
    SendMessage $R0 ${WM_SETTEXT} 0 "STR:Install"
  ${Else}
    SendMessage $R0 ${WM_SETTEXT} 0 "STR:&Next >"
  ${EndIf}

  Pop $R1
  Pop $R0
FunctionEnd

Function EnterConfigPage1
;  IntOp $R0 $NewComponents & ${ComponentsRequiringUserConfig}

;  ${If} $R0 = 0
;    Abort
;  ${EndIf}

  CreateDirectory "$INSTDIR\autoupgrade"
  IfFileExists $INSTDIR\Burp.conf end

  !insertmacro MUI_HEADER_TEXT "Install burp (page 1 of 2)" ""
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 2" "State" "$ConfigServerAddress"
;  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 5" "State" "$ConfigServerPort"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 5" "State" "$ConfigClientName"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 8" "State" "$ConfigPassword"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "ConfigPage1.ini"
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigServerAddress "ConfigPage1.ini" "Field 2" State
;  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigServerPort "ConfigPage1.ini" "Field 5" State
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigClientName "ConfigPage1.ini" "Field 5" State
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigPassword "ConfigPage1.ini" "Field 8" State

end:
  DetailPrint "$INSTDIR\burp.conf already exists. Not overwriting."

FunctionEnd

Function EnterConfigPage2
;  IntOp $R0 $NewComponents & ${ComponentsRequiringUserConfig}

;  ${If} $R0 = 0
;    Abort
;  ${EndIf}

  IfFileExists $INSTDIR\Burp.conf end

  !insertmacro MUI_HEADER_TEXT "Install burp (page 2 of 2)" ""
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage2.ini" "Field 2" "State" "$ConfigPoll"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage2.ini" "Field 5" "State" "$ConfigAutoupgrade"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "ConfigPage2.ini"
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigPoll "ConfigPage2.ini" "Field 2" State
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigAutoupgrade "ConfigPage2.ini" "Field 5" State

end:
  DetailPrint "$INSTDIR\burp.conf already exists. Not overwriting."

FunctionEnd


!include "DumpLog.nsh"
