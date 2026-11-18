; ============================================================
; EXagent - Single-click silent agent wrapper
; ============================================================
; Purpose
;   MeshCentral's own Windows agent binary is a combined
;   installer/agent. When it is launched with no arguments (a
;   double-click) the embedded JavaScript always runs
;   `global._OK = true; _start();` which opens the blue install
;   dialog, regardless of the InstallFlags value that was baked
;   in. InstallFlags only hides the Connect button inside that
;   dialog (see meshservice/ServiceMain.c: `_start`, and the
;   `(installFlagsInt & 3) == 2` "Background Only" branch).
;
;   There is therefore no way to make the raw MeshCentral agent
;   install silently by double-clicking it. This wrapper is the
;   supported replacement for the "Background only" download:
;   double-click -> single UAC prompt -> agent copied into
;   Program Files, service registered and started, no UI.
;
; How it works
;   1. RequestExecutionLevel admin  -> Windows shows ONE UAC
;      consent prompt when the file is opened.
;   2. SilentInstall silent        -> no wizard, no pages.
;   3. The real MeshCentral agent (same one the server would
;      have served, with MeshServer/MeshID/InstallFlags baked
;      in) is dropped into a temp directory and executed with
;      `-fullinstall`, which is the agent's own documented
;      silent install path (ServiceMain.c: "-fullinstall Copy
;      agent into program files, install and launch").
;   4. The temp copy is removed once the agent process exits.
;      agent-installer.js ends fullInstall with process.exit(),
;      so the file is unlocked at that point.
;
;   agent-installer.js installs the service as target
;   'MeshAgent' in %ProgramFiles%\Mesh Agent, so the temporary
;   file name used here does not affect the installed layout.
;
; Template placeholders:
;   {{OUTFILE}}      - output path for the wrapper .exe
;   {{AGENT_EXE}}    - path to the MeshCentral agent binary to embed
;   {{AGENT_NAME}}   - file name the agent is extracted as
;   {{PRODUCT_NAME}} - display name used for version metadata
; ============================================================

Unicode true

!define PRODUCT_NAME      "{{PRODUCT_NAME}}"
!define PRODUCT_PUBLISHER "EX SOFTWARE LLC"
!define PRODUCT_VERSION   "1.0.0.0"

Name            "${PRODUCT_NAME}"
OutFile         "{{OUTFILE}}"

; No UI at all: one elevation prompt, then nothing is displayed.
SilentInstall   silent
ShowInstDetails hide
AutoCloseWindow true

; Force the Windows UAC prompt on double-click.
RequestExecutionLevel admin

SetCompressor   lzma

VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName"     "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName"     "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "EX SOFTWARE LLC endpoint agent (silent installation)"
VIAddVersionKey "FileVersion"     "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion"  "${PRODUCT_VERSION}"

Section "Install"

  ; Work in a private temp directory that NSIS removes on exit.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "/oname={{AGENT_NAME}}" "{{AGENT_EXE}}"

  ; -fullinstall takes care of elevation-free work from here on: the
  ; process is already elevated, so the agent copies itself into
  ; %ProgramFiles%\Mesh Agent, registers the "Mesh Agent" service,
  ; adds its firewall rule and starts reporting. No window is shown.
  ;
  ; nsExec::ExecToStack runs the agent as a true child process with
  ; stdin/stdout/stderr redirected, so no console window is ever
  ; created. ExecWait was replaced because launching the agent
  ; (a console subsystem binary) directly caused a visible console
  ; window to appear during the otherwise-silent install.
  nsExec::ExecToStack '"$PLUGINSDIR\{{AGENT_NAME}}" -fullinstall'
  Pop $0
  Pop $1

  ; Best-effort cleanup of the extracted copy; the agent has already
  ; exited and installed itself elsewhere by this point.
  Delete "$PLUGINSDIR\{{AGENT_NAME}}"

SectionEnd
