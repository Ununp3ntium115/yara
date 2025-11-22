; NSIS Installer Script for YARA Cryptex (Windows)

!define PRODUCT_NAME "YARA Cryptex"
!define PRODUCT_VERSION "0.1.0"
!define PRODUCT_PUBLISHER "PYRO Platform"
!define PRODUCT_WEB_SITE "https://github.com/pyro-platform/yara-cryptex"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\cryptex.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI 1.67 compatible ------
!include "MUI2.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "LICENSE"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_RUN "$INSTDIR\bin\cryptex.exe"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "yara-cryptex-${PRODUCT_VERSION}-setup.exe"
InstallDir "$PROGRAMFILES\YARA Cryptex"
InstallDirRegKey HKCU "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
    SetOutPath "$INSTDIR\bin"
    File "build\bin\cryptex.exe"
    File "build\bin\cryptex-api.exe"
    File "build\bin\yara-feed-scanner.exe"
    File "build\bin\import_cryptex.exe"
    File "build\bin\export_cryptex.exe"
    
    SetOutPath "$INSTDIR\data"
    File "data\cryptex.json"
    
    SetOutPath "$INSTDIR\docs"
    File "*.md"
    
    ; Add to PATH
    EnVar::SetHKLM
    EnVar::AddValue "PATH" "$INSTDIR\bin"
    
    ; Create start menu shortcuts
    CreateDirectory "$SMPROGRAMS\YARA Cryptex"
    CreateShortCut "$SMPROGRAMS\YARA Cryptex\YARA Cryptex.lnk" "$INSTDIR\bin\cryptex.exe"
    CreateShortCut "$SMPROGRAMS\YARA Cryptex\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section -AdditionalIcons
    CreateShortCut "$SMPROGRAMS\YARA Cryptex\Website.lnk" "${PRODUCT_WEB_SITE}"
SectionEnd

Section -Post
    WriteUninstaller "$INSTDIR\uninstall.exe"
    WriteRegStr HKCU "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\bin\cryptex.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\bin\cryptex.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
SectionEnd

Function un.onUninstSuccess
    HideWindow
    MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
    MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
    Abort
FunctionEnd

Section Uninstall
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\bin\cryptex.exe"
    Delete "$INSTDIR\bin\cryptex-api.exe"
    Delete "$INSTDIR\bin\yara-feed-scanner.exe"
    Delete "$INSTDIR\bin\import_cryptex.exe"
    Delete "$INSTDIR\bin\export_cryptex.exe"
    Delete "$INSTDIR\data\cryptex.json"
    RMDir /r "$INSTDIR\docs"
    RMDir "$INSTDIR\bin"
    RMDir "$INSTDIR\data"
    RMDir "$INSTDIR"
    
    ; Remove from PATH
    EnVar::SetHKLM
    EnVar::DeleteValue "PATH" "$INSTDIR\bin"
    
    ; Remove shortcuts
    RMDir /r "$SMPROGRAMS\YARA Cryptex"
    
    ; Remove registry keys
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKCU "${PRODUCT_DIR_REGKEY}"
    
    SetAutoClose true
SectionEnd

