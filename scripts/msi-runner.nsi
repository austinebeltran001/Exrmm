; ============================================================
; EXagent - MSI service-runner (console-less launcher)
; ============================================================
; Why this file exists
;   The MeshCentral Windows agent is a CONSOLE-subsystem binary
;   (PE32+ ... Subsystem = Windows CUI). The MSI registers the
;   service with a deferred Type-18 custom action that executes
;   the agent directly:
;
;       <CustomAction Id="InstallAgentService" FileKey="AgentExe"
;                     ExeCommand="-fullinstall" ... />
;
;   Windows Installer creates that process itself (msiexec.exe is a
;   GUI-subsystem process, and even the /qn service host has no
;   console), so Windows allocates a brand-new console window for
;   the CUI child. The result on a plain double-click was a black
;   console flashing up during an otherwise dialog-only install,
;   showing:
;       Checking for previous installation... [NONE]
;       Installing service... [DONE]
;       Writing firewall rules... [DONE]
;       Starting service...
;
;   There is no attribute on a Type-18 custom action to request
;   CREATE_NO_WINDOW, so the fix is to stop executing the agent
;   directly: this tiny NSIS executable is installed next to the
;   agent and launched instead. NSIS produces a GUI-subsystem
;   executable, and it runs its child processes through nsExec,
;   which creates them with redirected stdin/stdout/stderr and no
;   console window at all. This is the same technique already
;   proven by silent-wrapper-template.nsi for the .exe installer.
;
; What actually registers the service
;   scripts/agent-service-install.ps1, extracted from this binary to
;   $PLUGINSDIR and run through nsExec with the per-group identity:
;
;       -ServiceName   ExSoftwaresAgent_<group>   (SCM name)
;       -DisplayName   "<device group name>"      (shown in services.msc)
;       -InstallDir    $EXEDIR                    (this group's folder)
;       -LogPath       %ProgramData%\EXagent\<group>\agent-install.log
;
;   It stops/deletes only services and processes that belong to THIS
;   group (name, or image path inside this install directory), then
;   registers the service directly against this group's agent copy,
;   starts it and verifies it reached the Running state.
;
;   It deliberately does not depend on the agent's own -fullinstall
;   first: that path always copies the agent to the single shared
;   "%ProgramFiles%\Mesh Agent" folder and registers the single
;   shared service name baked into the binary (ExSoftwaresAgent), so
;   a second device group would overwrite the first group's payload
;   and hijack its service. -fullinstall is still used as a
;   last-resort fallback when direct registration fails.
;
;   If Windows PowerShell cannot be started at all, the runner
;   falls back to the old behaviour - `"<agent>" -fullinstall` via
;   nsExec - so the MSI still installs on a machine where the
;   helper is unavailable.
;
; Contract with the MSI (keep in sync with msi-template.wxs)
;   * installed into the same directory as the agent
;     ([ProgramFiles64Folder]\<group>\Agent\)
;   * the agent is looked up as $EXEDIR\${AGENT_FILENAME}
;     (the File Name= used by the AgentExe component - both values are
;     rendered from one constant in build_msi.py and checked at build time)
;   * the action is taken from the command line: a deferred
;     custom action runs us as
;         <svc>.exe -fullinstall
;         <svc>.exe -fulluninstall
;     anything that does not contain "fulluninstall" is treated as
;     an install, so the safe default is -fullinstall.
;   * no window is ever shown and no UAC prompt is raised when
;     Windows Installer launches us (it already runs elevated /
;     as SYSTEM). If a user double-clicks the file by hand,
;     RequestExecutionLevel admin still forces the single consent
;     prompt the agent itself would need.
;
; Template placeholders (rendered by build_msi.py):
;   {{OUTFILE}}               - path of the runner .exe to produce
;   {{PRODUCT_NAME}}          - device group name (version metadata)
;   {{AGENT_FILENAME}}        - installed agent file name
;   {{SVC_FILENAME}}          - installed name of this runner
;   {{SERVICE_NAME}}          - SCM service name for this group
;   {{SERVICE_DISPLAY_NAME}}  - service display name (= group name)
;   {{INSTALL_DIR}}           - install folder name (log sub-directory)
;   {{HELPER_PS1}}            - absolute path of agent-service-install.ps1
; ============================================================

Unicode true

!define PRODUCT_NAME          "{{PRODUCT_NAME}}"
!define PRODUCT_PUBLISHER     "EX SOFTWARE LLC"
!define PRODUCT_VERSION       "1.0.0.0"

; File name of the agent inside the install directory. MUST equal the
; Name= attribute of the AgentExe file in msi-template.wxs; both are
; rendered from AGENT_FILENAME in build_msi.py.
!define AGENT_FILENAME        "{{AGENT_FILENAME}}"

; Installed file name of this runner (for logging only).
!define SVC_FILENAME          "{{SVC_FILENAME}}"

; Per-group service identity. A shared name would make the second device
; group installed on a machine take over the first group's service.
!define SERVICE_NAME          "{{SERVICE_NAME}}"
!define SERVICE_DISPLAY_NAME  "{{SERVICE_DISPLAY_NAME}}"

; Install folder name, used for the per-group log directory.
!define INSTALL_DIR           "{{INSTALL_DIR}}"

; PowerShell helper embedded below and extracted next to the agent at run time.
!define HELPER_PS1            "{{HELPER_PS1}}"

Name            "${PRODUCT_NAME} Service Runner"
OutFile         "{{OUTFILE}}"

; No UI, no wizard, never keep a window on screen.
SilentInstall   silent
ShowInstDetails hide
AutoCloseWindow true

; Elevated when a human runs it; irrelevant (already SYSTEM) when
; Windows Installer runs it as a deferred custom action.
RequestExecutionLevel admin

SetCompressor   lzma

VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName"     "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName"     "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT_NAME} service runner (hidden launcher)"
VIAddVersionKey "FileVersion"     "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion"  "${PRODUCT_VERSION}"

Var AgentPath
Var Mode
Var ScanSrc
Var ScanIdx
Var Window
Var Code
Var Output
Var DataDir
Var LogFile

Section "Run"

  ; The helper is a real .ps1 file rather than a giant -Command string: no
  ; NSIS quoting rules inside PowerShell code, and the exact same script can be
  ; run by hand for a repair.
  InitPluginsDir
  File /oname=$PLUGINSDIR\agent-service.ps1 "${HELPER_PS1}"

  StrCpy $AgentPath "$EXEDIR\${AGENT_FILENAME}"

  ; Default to the install path; only an explicit "fulluninstall" in the
  ; command line switches us to service removal.
  StrCpy $Mode "install"
  StrCpy $ScanSrc $CMDLINE
  StrCpy $ScanIdx 0

  ; Plain substring scan for "fulluninstall" (13 chars) - no NSIS include file
  ; needed, and it works no matter how the argument is quoted or prefixed.
  scan_loop:
    StrCpy $Window $ScanSrc 13 $ScanIdx
    StrCmp $Window "fulluninstall" scan_found 0
    IntOp $ScanIdx $ScanIdx + 1
    StrCmp $ScanIdx 4096 scan_done
    Goto scan_loop

  scan_found:
    StrCpy $Mode "uninstall"

  scan_done:

  ; NSIS has no $PROGRAMDATA constant, so resolve it from the environment
  ; (always set, also for the SYSTEM account the deferred action runs as) and
  ; fall back to the literal default path. One log directory per group, so two
  ; groups on one machine never interleave their install logs.
  ReadEnvStr $DataDir "ProgramData"
  StrCmp $DataDir "" 0 data_dir_ok
    StrCpy $DataDir "C:\ProgramData"
  data_dir_ok:
  CreateDirectory "$DataDir\EXagent"
  CreateDirectory "$DataDir\EXagent\${INSTALL_DIR}"
  StrCpy $LogFile "$DataDir\EXagent\${INSTALL_DIR}\agent-install.log"

  ; If the agent is not where it should be, do nothing rather than popping a
  ; message box - a message box in a deferred, no-desktop action would hang the
  ; whole installation. The reason is still written to the log.
  IfFileExists "$AgentPath" 0 agent_missing

  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "$PLUGINSDIR\agent-service.ps1" -Mode $Mode -AgentPath "$AgentPath" -ServiceName "${SERVICE_NAME}" -DisplayName "${SERVICE_DISPLAY_NAME}" -InstallDir "$EXEDIR" -LogPath "$LogFile"'
  Pop $Code
  Pop $Output

  ; "error"/"timeout" (and an empty exit code) mean the helper never ran: fall
  ; back to the legacy path so the machine still gets an install attempt.
  StrCmp $Code "error" direct_run
  StrCmp $Code "timeout" direct_run
  StrCmp $Code "" direct_run
  Goto log_result

  ; Absolute labels, not relative jumps: a wrong offset here silently skips the
  ; removal (the package then uninstalls and leaves the service behind).
  direct_run:
    StrCmp $Mode "uninstall" 0 direct_run_install
      nsExec::ExecToStack '"$AgentPath" -fulluninstall'
      Goto direct_run_popped
    direct_run_install:
      nsExec::ExecToStack '"$AgentPath" -fullinstall'
    direct_run_popped:
      Pop $Code
      Pop $Output

  log_result:
    FileOpen $9 "$LogFile" a
    IfErrors log_done
    FileWrite $9 "----$\r$\n"
    FileWrite $9 "runner: $EXEDIR\${SVC_FILENAME}$\r$\n"
    FileWrite $9 "agent:  $AgentPath$\r$\n"
    FileWrite $9 "service: ${SERVICE_NAME} (${SERVICE_DISPLAY_NAME})$\r$\n"
    FileWrite $9 "mode:   $Mode$\r$\n"
    FileWrite $9 "script: exit $Code$\r$\n"
    FileClose $9
    Goto run_end

  agent_missing:
    FileOpen $9 "$LogFile" a
    IfErrors run_end
    FileWrite $9 "----$\r$\n"
    FileWrite $9 "runner: agent binary missing at $AgentPath$\r$\n"
    FileClose $9

  log_done:
  run_end:

SectionEnd
