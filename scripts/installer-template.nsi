; ============================================================
; EXagent - Silent Windows Agent Installer
; Generated automatically by the EX SOFTWARE LLC portal backend.
;
; Template placeholders (all derived from the device group name by
; scripts/build_msi.py, so the .exe and the .msi always agree):
;   {{OUTFILE}}              - output path for exagent-setup.exe
;   {{AGENT_EXE}}            - path to the agent binary to embed
;   {{HELPER_PS1}}           - path to scripts/agent-service-install.ps1
;   {{PRODUCT_NAME}}         - device group name (Add/Remove Programs name)
;   {{PRODUCT_VERSION}}      - installer version
;   {{INSTALL_DIR_NAME}}     - folder name under Program Files
;   {{SERVICE_NAME}}         - SCM name for this group's service
;   {{SERVICE_DISPLAY_NAME}} - services.msc display name (the group name)
;   {{REG_KEY}}              - per-group metadata key
;   {{UNINST_KEY}}           - per-group Add/Remove Programs key
;   {{AGENT_FILENAME}}       - installed agent file name
;   {{MESH_ID}}              - MeshCentral device group id (mesh/domain/...)
;   {{SERVER_URL}}           - public MeshCentral URL
;
; Everything the installer names is derived from the device group, so two
; groups can be installed on one machine and neither one overwrites the
; other's folder, service, registry key or Add/Remove Programs entry.
; ============================================================

Unicode true

!define PRODUCT_NAME         "{{PRODUCT_NAME}}"
!define PRODUCT_PUBLISHER    "EX SOFTWARE LLC"
!define PRODUCT_VERSION      "{{PRODUCT_VERSION}}"
!define INSTALL_DIR_NAME     "{{INSTALL_DIR_NAME}}"
!define SERVICE_NAME         "{{SERVICE_NAME}}"
!define SERVICE_DISPLAY_NAME "{{SERVICE_DISPLAY_NAME}}"
!define REG_KEY              "{{REG_KEY}}"
!define UNINST_KEY           "{{UNINST_KEY}}"
!define AGENT_FILENAME       "{{AGENT_FILENAME}}"

Name            "${PRODUCT_NAME}"
OutFile         "{{OUTFILE}}"
InstallDir      "$PROGRAMFILES64\${INSTALL_DIR_NAME}\Agent"
SilentInstall   silent
RequestExecutionLevel admin
ShowInstDetails hide
SetCompressor   lzma

; The agent is started by its Windows service, never directly from this
; installer, so no console window ever appears even though the agent binary
; is a console-subsystem executable.
Section "Install"

  SetOutPath "$INSTDIR"
  File "/oname=${AGENT_FILENAME}" "{{AGENT_EXE}}"

  ; Service registration helper. It is installed next to the agent so the
  ; technician can re-run the same repair command by hand, and so the
  ; uninstaller can use it after the files are in place.
  File "/oname=agent-service.ps1" "{{HELPER_PS1}}"

  ; Per-group metadata, same values and same key shape the MSI writes.
  WriteRegStr HKLM "${REG_KEY}" "ClientName"  "${PRODUCT_NAME}"
  WriteRegStr HKLM "${REG_KEY}" "MeshId"      "{{MESH_ID}}"
  WriteRegStr HKLM "${REG_KEY}" "ServerUrl"   "{{SERVER_URL}}"
  WriteRegStr HKLM "${REG_KEY}" "ServiceName" "${SERVICE_NAME}"
  WriteRegStr HKLM "${REG_KEY}" "InstallDir"  "$INSTDIR"
  WriteRegStr HKLM "${REG_KEY}" "InstalledBy" "exagent-setup.exe"

  ; Register the service against THIS group's agent copy with THIS group's
  ; service name. The agent's own -fullinstall would use one shared folder and
  ; one shared service name for every group, which is why the helper exists.
  DetailPrint "Registering service ${SERVICE_NAME}..."
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "$INSTDIR\agent-service.ps1" -Mode install -AgentPath "$INSTDIR\${AGENT_FILENAME}" -ServiceName "${SERVICE_NAME}" -DisplayName "${SERVICE_DISPLAY_NAME}" -InstallDir "$INSTDIR"'
  Pop $R0
  Pop $R1
  DetailPrint "Service helper result: $R0"
  StrCmp $R0 "0" service_ok
    SetErrorLevel 1
  service_ok:

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName"     "${PRODUCT_NAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher"       "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion"  "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon"     "$INSTDIR\${AGENT_FILENAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "Comments"        "MeshId={{MESH_ID}} Server={{SERVER_URL}} Service=${SERVICE_NAME}"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1

SectionEnd

Section "Uninstall"

  ; Stop and delete this group's service and processes before the files go.
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "$INSTDIR\agent-service.ps1" -Mode uninstall -AgentPath "$INSTDIR\${AGENT_FILENAME}" -ServiceName "${SERVICE_NAME}" -DisplayName "${SERVICE_DISPLAY_NAME}" -InstallDir "$INSTDIR"'
  Pop $R0
  Pop $R1

  Delete "$INSTDIR\${AGENT_FILENAME}"
  Delete "$INSTDIR\agent-service.ps1"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  RMDir "$PROGRAMFILES64\${INSTALL_DIR_NAME}"

  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "${REG_KEY}"

SectionEnd
