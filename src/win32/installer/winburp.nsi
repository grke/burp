;
; Include the Modern UI
;

!include "MUI.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "Sections.nsh"
!include "StrFunc.nsh"
!include "WinMessages.nsh"
!include "NsDialogs.nsh"
!include "ReplaceInFile.nsh"

;
; Basics
;
Name "${PACKAGE_NAME}"
OutFile "${OUT_DIR}\${PACKAGE_TARNAME}-win${BITS}-installer-${PACKAGE_VERSION}.exe"
SetCompressor lzma
!If "$BITS" == "32"
	InstallDir "$PROGRAMFILES\${PACKAGE_NAME}"
!Else
	InstallDir "$PROGRAMFILES64\${PACKAGE_NAME}"
!EndIf

InstType "${PACKAGE_NAME}"
InstType "Client"

!insertmacro GetParent

;
; Pull in pages
;

!define      MUI_COMPONENTSPAGE_SMALLDESC

!define      MUI_HEADERIMAGE
!define      MUI_BGCOLOR                FFFFFF

!define      MUI_WELCOMEPAGE_TITLE      "Welcome to the ${PACKAGE_NAME} setup wizard, version ${PACKAGE_VERSION}."
!InsertMacro MUI_PAGE_WELCOME
!define      MUI_PAGE_CUSTOMFUNCTION_SHOW PageComponentsShow
!define      MUI_PAGE_CUSTOMFUNCTION_PRE PageDirectoryPre
!InsertMacro MUI_PAGE_DIRECTORY
Page custom EnterConfigPage1
Page custom EnterConfigPage2
Page custom EnterConfigPage3
Page custom EnterConfigPage4 LeaveConfigPage4
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

DirText "Setup will install ${PACKAGE_NAME} ${PACKAGE_VERSION} to the directory specified below. To install in a different folder, click Browse and select another folder."

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
Var ConfigNoPowerMode
Var ConfigAutoupgrade
Var ConfigMinuteText
Var ConfigServerRestore
Var ConfigEncPass
Var ConfigInclude

Var AutomaticInstall

Var PreviousComponents
Var NewComponents

Var HWND
Var IncludesTmp

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

	; Use PLUGINSDIR as a temporary directory.
	InitPluginsDir
	StrCpy $IncludesTmp "$PLUGINSDIR\includes.txt"

	Push "$ConfDir" ; Haystack
	Push "\"        ; Needle
	Push "/"        ; Replacement
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
	StrCpy $ConfigClientName 	"clientname"
        Push $R0
        ; Try to get hostname via system call that supports lower/uppercase
        nsExec::ExecToStack '"$SYSDIR\cmd.exe" /c hostname'
        Pop $R0
        Pop $R1
        ${If} $R0 == 0
        ${AndIf} $R1 != ""
                StrCpy $ConfigClientName $R1
        ${Else}
                ReadEnvStr $R0 COMPUTERNAME
                ${If} "$R0" != ""
                        StrCpy $ConfigClientName "$R0"
                ${EndIf}
        ${EndIf}
        Pop $R0
	StrCpy $ConfigPassword                "abcdefgh"
	StrCpy $ConfigPoll                    "20"
	StrCpy $ConfigNoPowerMode		"0"
	StrCpy $ConfigAutoupgrade		"0"
	; The commands that you have to give the Windows scheduler change
	; depending upon your language. 'MINUTE' works for English.
	; Allow it to be overridden on the command line. Maybe one day, there
	; will be an advanced option to choose from the screens.
	StrCpy $ConfigMinuteText		"MINUTE"
	StrCpy $ConfigServerRestore		"0"
	StrCpy $ConfigEncPass			""

	${If} ${FileExists} "C:\Users"
		StrCpy $ConfigInclude "C:\Users"
	${Else}
		${If} ${FileExists} "C:\Documents and Settings"
			StrCpy $ConfigInclude "C:\Documents and Settings"
		${Else}
			StrCpy $ConfigInclude "C:\"
		${EndIf}
	${EndIf}

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
	${GetOptions} $R0 "/nopowermode" $R1
	IfErrors +2
	StrCpy $ConfigNoPowerMode 1
	ClearErrors
	${GetOptions} $R0 "/autoupgrade=" $R1
	IfErrors +2
	StrCpy $ConfigAutoupgrade $R1
	ClearErrors
	${GetOptions} $R0 "/server_can_restore=" $R1
	IfErrors +2
	StrCpy $ConfigServerRestore $R1
	ClearErrors
	${GetOptions} $R0 "/encryption_password=" $R1
	IfErrors +2
	StrCpy $ConfigEncPass $R1
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
	ClearErrors
	${GetOptions} $R0 "/include" $R1
	IfErrors +2
	StrCpy $ConfigInclude 1

	FileOpen $R2 "$IncludesTmp" w
	FileWrite $R2 "include = $ConfigInclude$\r$\n"
	FileClose $R2

	!InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage1.ini"
	!InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage2.ini"
	!InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage3.ini"
	!InsertMacro MUI_INSTALLOPTIONS_EXTRACT "ConfigPage4.ini"

	Pop $R1
	Pop $R0
FunctionEnd

Function .onSelChange
  Call UpdateComponentUI
FunctionEnd

Function InstallCommonFiles
	${If} $CommonFilesDone = 0
		SetOutPath "$INSTDIR"
		File "${SRC_DIR}\openssl.conf"
		SetOutPath "$INSTDIR\bin"
		File "${SRC_DIR}\bin\compat.dll"
		File "${SRC_DIR}\bin\${CRYPTO_DLL}"
		File "${SRC_DIR}\bin\libcheck-0.dll"
		File "${SRC_DIR}\bin\${LIBGCC_DLL}"
		File "${SRC_DIR}\bin\libpcre-1.dll"
		File "${SRC_DIR}\bin\libpcreposix-0.dll"
		File "${SRC_DIR}\bin\libyajl.dll"
		File "${SRC_DIR}\bin\openssl.exe"
		File "${SRC_DIR}\bin\${PACKAGE_TARNAME}_ca.bat"
		File "${SRC_DIR}\bin\${PACKAGE_TARNAME}.exe"
		File "${SRC_DIR}\bin\${SSL_DLL}"
		File "${SRC_DIR}\bin\utest.exe"
		File "${SRC_DIR}\bin\zlib1.dll"
		StrCpy $CommonFilesDone 1
	${EndIf}
FunctionEnd

Section "-Initialize"
	Call GetSelectedComponents
	Pop $R2

	SetShellVarContext all

	; Upgrade consideration. Things always used to get installed in
	; C:\Program Files\${PACKAGE_NAME}\ but changed to %PROGRAMFILES%
	; in 1.3.11.
	IfFileExists "C:\Program Files\${PACKAGE_NAME}\${PACKAGE_TARNAME}.conf" resetinstdir donotresetinstdir
resetinstdir:
	StrCpy $INSTDIR "C:\Program Files\${PACKAGE_NAME}"
donotresetinstdir:

	CreateDirectory "$INSTDIR"
	CreateDirectory "$INSTDIR\autoupgrade"
	CreateDirectory "$INSTDIR\bin"
	CreateDirectory "$INSTDIR\CA"

	SetOutPath "$INSTDIR"

; If /overwrite was given on the command line, allow overwrite of
; old configuration.
	StrCmp $Overwrite 1 overwrite
	IfFileExists "$INSTDIR\${PACKAGE_NAME}.conf" end
overwrite:

	FileOpen $R1 "$INSTDIR\${PACKAGE_TARNAME}.conf" w

!If "$BITS" == "32"
	StrCpy $R2 "32"
!Else
	StrCpy $R2 "64"
!EndIf

	FileWrite $R1 "mode = client$\r$\n"
	FileWrite $R1 "server = $ConfigServerAddress:$ConfigServerPort$\r$\n"
	FileWrite $R1 "status_port = 4972$\r$\n"
	FileWrite $R1 "cname = $ConfigClientName$\r$\n"
	FileWrite $R1 "password = $ConfigPassword$\r$\n"

	ClearErrors
	FileOpen $0 "$IncludesTmp" r
	${Do}
		FileRead $0 $1
		IfErrors done
		FileWrite $R1 "$1"
	${LoopUntil} 0 == 1
	done:
		FileClose $0

	FileWrite $R1 "exclude_regex = ^[A-Z]:/recycler$$$\r$\n"
	FileWrite $R1 "exclude_regex = ^[A-Z]:/\$$recycle\.bin$$$\r$\n"
	FileWrite $R1 "exclude_regex = ^[A-Z]:/pagefile\.sys$$$\r$\n"
	FileWrite $R1 "exclude_regex = ^[A-Z]:/swapfile\.sys$$$\r$\n"
	FileWrite $R1 "exclude_regex = ^[A-Z]:/hiberfil\.sys$$$\r$\n"
	FileWrite $R1 "stdout = 1$\r$\n"
	FileWrite $R1 "progress_counter = 1$\r$\n"
	FileWrite $R1 "nobackup = .nobackup$\r$\n"
	FileWrite $R1 "lockfile = $ConfDir/lockfile$\r$\n"
	FileWrite $R1 "ca_${PACKAGE_TARNAME}_ca = $ConfDir/bin/${PACKAGE_TARNAME}_ca.bat$\r$\n"
	FileWrite $R1 "ca_csr_dir = $ConfDir/CA$\r$\n"
	FileWrite $R1 "ssl_cert_ca = $ConfDir/ssl_cert_ca.pem$\r$\n"
	FileWrite $R1 "ssl_cert = $ConfDir/ssl_cert-client.pem$\r$\n"
	FileWrite $R1 "ssl_key = $ConfDir/ssl_cert-client.key$\r$\n"
	FileWrite $R1 "ssl_key_password = password$\r$\n"
	FileWrite $R1 "ssl_peer_cn = ${PACKAGE_TARNAME}server$\r$\n"
	FileWrite $R1 "server_can_restore = $ConfigServerRestore$\r$\n"
	FileWrite $R1 "split_vss = 0$\r$\n"
	FileWrite $R1 "strip_vss = 0$\r$\n"
	${If} $ConfigEncPass != ""
		FileWrite $R1 "encryption_password = $ConfigEncPass$\r$\n"
	${EndIf}
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
		nsExec::Exec 'schtasks /DELETE /TN "${PACKAGE_TARNAME} cron" /F'
		; Create a new task
		nsExec::ExecToLog 'schtasks /CREATE /RU SYSTEM /TN "${PACKAGE_TARNAME} cron" /TR "\"$INSTDIR\bin\${PACKAGE_TARNAME}.exe\" -a t" /SC $ConfigMinuteText /MO $ConfigPoll'
		${If} $ConfigNoPowerMode != 0
			; Export it as temporary XML file (ugly hack to make command be able to write to stdout)
			ExecWait '$SYSDIR\cmd.exe /C schtasks /QUERY /TN "${PACKAGE_TARNAME} cron" /XML > "$INSTDIR\${PACKAGE_TARNAME}_task.xml"'
			; Modify the XML file in order to remove battery limitations
			!insertmacro _ReplaceInFile "$INSTDIR\${PACKAGE_TARNAME}_task.xml" <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries> <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
			!insertmacro _ReplaceInFile "$INSTDIR\${PACKAGE_TARNAME}_task.xml" <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries> <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
			; Delete the former task
			nsExec::Exec 'schtasks /DELETE /TN "${PACKAGE_TARNAME} cron" /F'
			; Insert the modified XML
			nsExec::ExecToLog 'schtasks /CREATE /TN "${PACKAGE_TARNAME} cron" /XML "$INSTDIR\${PACKAGE_TARNAME}_task.xml" /RU SYSTEM /F'
			; Remove temporary XML file (and .old file created by ReplaceInFile)
			Delete "$INSTDIR\${PACKAGE_TARNAME}_task.xml"
			Delete "$INSTDIR\${PACKAGE_TARNAME}_task.xml.old"
		${EndIf}
	${EndIf}

end:
  DetailPrint "$INSTDIR\${PACKAGE_TARNAME}.conf already exists. Not overwriting."

SectionEnd

SectionGroup "Client" SecGroupClient

Section "File Service" SecFileDaemon
	SectionIn 1 2 3

	Call InstallCommonFiles
SectionEnd

SectionGroupEnd

Section "-Finish"
	Push $R0

	; Write the uninstall keys for Windows.
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "DisplayName" "${PACKAGE_NAME}"
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "InstallLocation" "$INSTDIR"
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "DisplayVersion" "${PACKAGE_VERSION}"
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "Publisher" "Graham Keeling"
	DeleteRegKey  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}\VersionMajor"
	DeleteRegKey  HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}\VersionMinor"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "NoRepair" 1
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "URLUpdateInfo" "${PACKAGE_URL}"
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "URLInfoAbout" "${PACKAGE_URL}"
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "HelpLink" "${PACKAGE_URL}"
	WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "UninstallString" '"$INSTDIR\uninstall.exe"'
	WriteUninstaller "$INSTDIR\Uninstall.exe"

	Pop $R0
SectionEnd

; Extra Page descriptions

LangString DESC_SecFileDaemon ${LANG_ENGLISH} "Install ${PACKAGE_NAME} on this system."

LangString TITLE_ConfigPage1 ${LANG_ENGLISH} "Configuration"
LangString SUBTITLE_ConfigPage1 ${LANG_ENGLISH} "Set installation configuration."

LangString TITLE_ConfigPage2 ${LANG_ENGLISH} "Configuration (continued)"
LangString SUBTITLE_ConfigPage2 ${LANG_ENGLISH} "Set installation configuration."

LangString TITLE_ConfigPage3 ${LANG_ENGLISH} "Configuration (continued)"
LangString SUBTITLE_ConfigPage3 ${LANG_ENGLISH} "Set installation configuration."

!InsertMacro MUI_FUNCTION_DESCRIPTION_BEGIN
!InsertMacro MUI_DESCRIPTION_TEXT ${SecFileDaemon} $(DESC_SecFileDaemon)
!InsertMacro MUI_FUNCTION_DESCRIPTION_END


; Uninstall section

UninstallText "This will uninstall ${PACKAGE_NAME}. Click Uninstall to continue."

Section "Uninstall"
	SetShellVarContext all

	; remove the cron
	nsExec::Exec 'schtasks /DELETE /TN "${PACKAGE_TARNAME} cron" /F'

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

	; remove registry keys
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}"
	DeleteRegKey HKLM "Software\${PACKAGE_NAME}"
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
	StrCmp $SkipPages 1 end

	StrCmp $Overwrite 1 overwrite
	IfFileExists "$INSTDIR\${PACKAGE_NAME}.conf" end
overwrite:

	!insertmacro MUI_HEADER_TEXT "Install ${PACKAGE_TARNAME} (page 1 of 4)" ""
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 2" "State" "$ConfigServerAddress"
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 5" "State" "$ConfigServerPort"
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 8" "State" "$ConfigClientName"
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage1.ini" "Field 11" "State" "$ConfigPassword"
	!insertmacro MUI_INSTALLOPTIONS_DISPLAY "ConfigPage1.ini"
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigServerAddress "ConfigPage1.ini" "Field 2" State
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigServerPort "ConfigPage1.ini" "Field 5" State
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigClientName "ConfigPage1.ini" "Field 8" State
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigPassword "ConfigPage1.ini" "Field 11" State

end:

FunctionEnd

Function EnterConfigPage2
	StrCmp $SkipPages 1 end

	StrCmp $Overwrite 1 overwrite
	IfFileExists "$INSTDIR\${PACKAGE_NAME}.conf" end
overwrite:

	!insertmacro MUI_HEADER_TEXT "Install ${PACKAGE_TARNAME} (page 2 of 4)" ""
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage2.ini" "Field 2" "State" "$ConfigPoll"
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage2.ini" "Field 5" "State" "$ConfigNoPowerMode"
	!insertmacro MUI_INSTALLOPTIONS_DISPLAY "ConfigPage2.ini"
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigPoll "ConfigPage2.ini" "Field 2" State
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigNoPowerMode "ConfigPage2.ini" "Field 5" State

end:

FunctionEnd

Function EnterConfigPage3
	StrCmp $SkipPages 1 end

	StrCmp $Overwrite 1 overwrite
	IfFileExists "$INSTDIR\${PACKAGE_NAME}.conf" end
overwrite:

	!insertmacro MUI_HEADER_TEXT "Install ${PACKAGE_TARNAME} (page 3 of 4)" ""
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage3.ini" "Field 2" "State" "$ConfigEncPass"
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage3.ini" "Field 5" "State" "$ConfigAutoupgrade"
	!insertmacro MUI_INSTALLOPTIONS_WRITE "ConfigPage3.ini" "Field 8" "State" "$ConfigServerRestore"
	!insertmacro MUI_INSTALLOPTIONS_DISPLAY "ConfigPage3.ini"
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigEncPass "ConfigPage3.ini" "Field 2" State
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigAutoupgrade "ConfigPage3.ini" "Field 5" State
	!InsertMacro MUI_INSTALLOPTIONS_READ $ConfigServerRestore "ConfigPage3.ini" "Field 8" State

end:

FunctionEnd

Function EnterConfigPage4
	StrCmp $SkipPages 1 end

	StrCmp $Overwrite 1 overwrite
	IfFileExists "$INSTDIR\${PACKAGE_NAME}.conf" end
overwrite:
	!insertmacro MUI_HEADER_TEXT "Install ${PACKAGE_TARNAME} (page 4 of 4)" ""
	!insertmacro MUI_INSTALLOPTIONS_INITDIALOG "ConfigPage4.ini"
	Pop $HWND

	GetDlgItem $1 $HWND 1204
	SendMessage $1 ${LB_ADDSTRING} 1 "STR:$ConfigInclude"
;	SendMessage $1 ${LB_SETHORIZONTALEXTENT} 200 0

	!insertmacro MUI_INSTALLOPTIONS_SHOW
	Pop $0
end:

FunctionEnd

Function LeaveConfigPage4
	!insertmacro MUI_INSTALLOPTIONS_READ $0 "ConfigPage4.ini" "Settings" "State"
	!insertmacro MUI_INSTALLOPTIONS_READ $R0 "ConfigPage4.ini" "Field 1" "State"
	!insertmacro MUI_INSTALLOPTIONS_READ $R1 "ConfigPage4.ini" "Field 4" "State"

	StrCmp $0 4 EnableDelete
	StrCmp $0 3 DeleteString
	StrCmp $0 2 AddString
	StrCmp $0 1 AddString
	StrCmp $0 0 Enter
	Abort

	EnableDelete:
		GetDlgItem $1 $HWND 1203
		EnableWindow $1 1
		Abort

	AddString:
		${GetFileAttributes} "$R0" "DIRECTORY" $1
		StrCmp $1 1 is_directory end
		is_directory:
			GetDlgItem $1 $HWND 1204
			SendMessage $1 ${LB_FINDSTRINGEXACT} 1 "STR:$R0" $0
			IntCmp $0 -1 notfound end end
		notfound:
			SendMessage $1 ${LB_ADDSTRING} 1 "STR:$R0"
;			SendMessage $1 ${LB_SETHORIZONTALEXTENT} 200 0
		end:
		Goto DisableEnableNext

	DeleteString:
		GetDlgItem $1 $HWND 1204
		SendMessage $1 ${LB_FINDSTRINGEXACT} 1 "STR:$R1" $0
		SendMessage $1 ${LB_DELETESTRING} $0 1
		Goto DisableDelete

	DisableDelete:
		GetDlgItem $1 $HWND 1203
		EnableWindow $1 0
		Goto DisableEnableNext

	DisableEnableNext:
		GetDlgItem $1 $HWND 1204
		SendMessage $1 ${LB_GETCOUNT} 0 0 $2
		IntCmp $2 0 DisableNext EnableNext EnableNext
		Abort

	DisableNext:
		GetDlgItem $1 $HWNDPARENT 1
		EnableWindow $1 0
		Abort

	EnableNext:
		GetDlgItem $1 $HWNDPARENT 1
		EnableWindow $1 1
		Abort

	Enter:
		GetDlgItem $2 $HWND 1204
		SendMessage $2 ${LB_GETCOUNT} 0 0 $3
		StrCpy $0 0
		FileOpen $R2 "$IncludesTmp" w
		${Do}
			System::Call user32::SendMessage(i$2,i${LB_GETTEXT},i$0,t.r1)
			Push "$1"   ; Haystack
			Push "\"    ; Needle
			Push "/"    ; Replacement
			Call StrRep
			Pop "$4"
			FileWrite $R2 "include = $4$\r$\n"
			IntOp $0 $0 + 1
		${LoopUntil} $0 == $3
		FileClose $R2
FunctionEnd

!include "DumpLog.nsh"
