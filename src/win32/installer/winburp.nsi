; winburp.nsi

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
!If "$BITS" == "32"
  InstallDir "$PROGRAMFILES\Burp"
!Else
  InstallDir "$PROGRAMFILES64\Burp"
!EndIf

InstType "Burp"
InstType "Client"

!insertmacro GetParent

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
Var ConfDir

Var OptSilent
Var Overwrite
Var SkipPages

Var CommonFilesDone

Var ConfigServerAddress
Var ConfigServerPort
Var ConfigClientName
Var ConfigPassword
Var ConfigPoll
Var ConfigAutoupgrade
Var ConfigMinuteText

Var AutomaticInstall

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

; All this gash just to replace backslashes with forward slashes.
Function StrRep
  Exch $R4 ; $R4 = Replacement String
  Exch
  Exch $R3 ; $R3 = String to replace (needle)
  Exch 2
  Exch $R1 ; $R1 = String to do replacement in (haystack)
  Push $R2 ; Replaced haystack
  Push $R5 ; Len (needle)
  Push $R6 ; len (haystack)
  Push $R7 ; Scratch reg
  StrCpy $R2 ""
  StrLen $R5 $R3
  StrLen $R6 $R1
loop:
  StrCpy $R7 $R1 $R5
  StrCmp $R7 $R3 found
  StrCpy $R7 $R1 1 ; - optimization can be removed if U know len needle=1
  StrCpy $R2 "$R2$R7"
  StrCpy $R1 $R1 $R6 1
  StrCmp $R1 "" done loop
found:
  StrCpy $R2 "$R2$R4"
  StrCpy $R1 $R1 $R6 $R5
  StrCmp $R1 "" done loop
done:
  StrCpy $R3 $R2
  Pop $R7
  Pop $R6
  Pop $R5
  Pop $R2
  Pop $R1
  Pop $R4
  Exch $R3
FunctionEnd

Function .onInit
  Push $R0
  Push $R1

  StrCpy $ConfDir "$INSTDIR"

  Push "$ConfDir" ; String to do replacement in (haystack)
  Push "\"        ; String to replace (needle)
  Push "/"       ; Replacement
  Call StrRep
  Pop "$R0"
  StrCpy $ConfDir "$R0"

  ; Process Command Line Options
  StrCpy $OptSilent 0
  StrCpy $Overwrite 0
  StrCpy $SkipPages 0
  StrCpy $CommonFilesDone 0
  StrCpy $AutomaticInstall 1
  StrCpy $PreviousComponents 0
  StrCpy $NewComponents 0

  ${GetParameters} $R0

  IfSilent 0 +2
    StrCpy $OptSilent 1

  ; Configuration Defaults

  StrCpy $ConfigServerAddress		"10.0.0.1"
  StrCpy $ConfigServerPort              "4971"
  StrCpy $ConfigClientName              "clientname"
  StrCpy $ConfigPassword                "password"
  StrCpy $ConfigPoll                    "20"
  StrCpy $ConfigAutoupgrade		"1"
  ; The commands that you have to give the Windows scheduler change depending
  ; upon your language. 'MINUTE' works for English.
  ; Allow it to be overridden on the command line. Maybe one day, there will
  ; be an advanced option to choose from the screens.
  StrCpy $ConfigMinuteText		"MINUTE"

  ; Allow things to be set on the command line.
  ClearErrors
  ${GetOptions} $R0 "/server=" $R1
  IfErrors +2
    StrCpy $ConfigServerAddress $R1
  ClearErrors
  ${GetOptions} $R0 "/port=" $R1
  IfErrors +2
    StrCpy $ConfigServerPort $R1
  ClearErrors
  ${GetOptions} $R0 "/cname=" $R1
  IfErrors +2
    StrCpy $ConfigClientName $R1
  ClearErrors
  ${GetOptions} $R0 "/password=" $R1
  IfErrors +2
    StrCpy $ConfigPassword $R1
  ClearErrors
  ${GetOptions} $R0 "/poll=" $R1
  IfErrors +2
    StrCpy $ConfigPoll $R1
  ClearErrors
  ${GetOptions} $R0 "/autoupgrade=" $R1
  IfErrors +2
    StrCpy $ConfigAutoupgrade $R1
  ClearErrors
  ${GetOptions} $R0 "/minutetext=" $R1
  IfErrors +2
    StrCpy $ConfigMinuteText $R1
  ClearErrors
  ${GetOptions} $R0 "/overwrite" $R1
  IfErrors +2
    StrCpy $Overwrite 1
  ClearErrors
  ${GetOptions} $R0 "/skippages" $R1
  IfErrors +2
    StrCpy $SkipPages 1

  !InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage1.ini"
  !InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage2.ini"

  Pop $R1
  Pop $R0
FunctionEnd

Function .onSelChange
  Call UpdateComponentUI
FunctionEnd

Function InstallCommonFiles
  ${If} $CommonFilesDone = 0

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
  Call GetSelectedComponents
  Pop $R2

  SetShellVarContext all

  ; Upgrade consideration. Things always used to get installed in
  ; C:\Program Files\Burp\ but changed to %PROGRAMFILES% in 1.3.11.
  IfFileExists "C:\Program Files\Burp\burp.conf" resetinstdir donotresetinstdir
resetinstdir:
  StrCpy $INSTDIR "C:\Program Files\Burp"
donotresetinstdir:

  CreateDirectory "$INSTDIR"
  CreateDirectory "$INSTDIR\bin"
  CreateDirectory "$INSTDIR\CA"

  SetOutPath "$INSTDIR"

; If /overwrite was given on the command line, allow overwrite of
; old configuration.
  StrCmp $Overwrite 1 overwrite
  IfFileExists $INSTDIR\Burp.conf end
overwrite:

  FileOpen $R1 $INSTDIR\burp.conf w

!If "$BITS" == "32"
  StrCpy $R2 "32"
!Else
  StrCpy $R2 "64"
!EndIf

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
  FileWrite $R1 "lockfile = $ConfDir/lockfile$\r$\n"
  FileWrite $R1 "ca_burp_ca = $ConfDir/bin/burp_ca.bat$\r$\n"
  FileWrite $R1 "ca_csr_dir = $ConfDir/CA$\r$\n"
  FileWrite $R1 "ssl_cert_ca = $ConfDir/ssl_cert_ca.pem$\r$\n"
  FileWrite $R1 "ssl_cert = $ConfDir/ssl_cert-client.pem$\r$\n"
  FileWrite $R1 "ssl_key = $ConfDir/ssl_cert-client.key$\r$\n"
  FileWrite $R1 "ssl_key_password = password$\r$\n"
  FileWrite $R1 "ssl_peer_cn = burpserver$\r$\n"
!if "${BITS}" == "32"
  FileWrite $R1 "autoupgrade_os = win32$\r$\n"
!endif
!if "${BITS}" == "64"
  FileWrite $R1 "autoupgrade_os = win64$\r$\n"
!endif
  ${If} $ConfigAutoupgrade == "0"
    FileWrite $R1 "# autoupgrade_dir = $ConfDir/autoupgrade$\r$\n"
  ${EndIf}
  ${If} $ConfigAutoupgrade != "0"
    FileWrite $R1 "autoupgrade_dir = $ConfDir/autoupgrade$\r$\n"
  ${EndIf}

  FileClose $R1

  ${If} $ConfigPoll != 0
    ; Delete the cron if it already exists.
    nsExec::Exec 'schtasks /DELETE /TN "burp cron" /F'
    nsExec::ExecToLog 'schtasks /CREATE /RU SYSTEM /TN "burp cron" /TR "\"$INSTDIR\bin\burp.exe\" -a t" /SC $ConfigMinuteText /MO $ConfigPoll'
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

  WriteUninstaller "$INSTDIR\Uninstall.exe"

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
  SetShellVarContext all

  ; remove the burp cron
  nsExec::Exec 'schtasks /DELETE /TN "burp cron" /F'

  ; remove files
  Delete "$INSTDIR\autoupgrade\*"
  Delete "$INSTDIR\bin\*"
  Delete "$INSTDIR\CA\*"
  Delete "$INSTDIR\*"

  ; remove directories
  RMDir "$INSTDIR\autoupgrade"
  RMDir "$INSTDIR\bin"
  RMDir "$INSTDIR\CA"
  RMDir "$INSTDIR"
SectionEnd

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

  StrCmp $SkipPages 1 end

  StrCmp $Overwrite 1 overwrite
  IfFileExists $INSTDIR\Burp.conf end
overwrite:

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

FunctionEnd

Function EnterConfigPage2
;  IntOp $R0 $NewComponents & ${ComponentsRequiringUserConfig}

;  ${If} $R0 = 0
;    Abort
;  ${EndIf}

  StrCmp $SkipPages 1 end

  StrCmp $Overwrite 1 overwrite
  IfFileExists $INSTDIR\Burp.conf end
overwrite:

  !insertmacro MUI_HEADER_TEXT "Install burp (page 2 of 2)" ""
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage2.ini" "Field 2" "State" "$ConfigPoll"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage2.ini" "Field 5" "State" "$ConfigAutoupgrade"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "ConfigPage2.ini"
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigPoll "ConfigPage2.ini" "Field 2" State
  !InsertMacro MUI_INSTALLOPTIONS_READ $ConfigAutoupgrade "ConfigPage2.ini" "Field 5" State

end:

FunctionEnd


!include "DumpLog.nsh"
