#!/usr/bin/env python3
r"""Render the WiX template and compile a per-device-group EXagent MSI.

Usage:
    build_msi.py --agent <agent.exe> --client <group name> --meshid <mesh/...>
                 --server https://remote.exrmm.com --out <file.msi>
                 [--version 1.0.0] [--icon <file.ico>] [--no-icon] [--keep-wxs]
                 [--runner <runner.exe>] [--runner-template <runner.nsi>]

Toolchain
---------
Two WiX compilers are accepted; the template is shared by both:

  wixl          msitools (Linux): `wixl -a x64`
  candle+light  WiX v3 toolset (Windows): `candle -arch x64`, then `light`

NSIS (`makensis`) is required for the console-less service runner either way.
The build fails loudly on the full compiler output. With wixl it additionally
rejects a build in which wixl dropped the service custom actions (it does that
silently when it meets an attribute it does not understand). The built package
is then read back (msiinfo on Linux, msi.dll on Windows) and rejected when the
naming contract did not land in it.

Naming contract
---------------
The installed application is named after the MeshCentral device group, always:
`--client` is the group name and every visible name is derived from it, never
from the file the user downloaded.

  Add/Remove Programs   "<group name>" (exact, e.g. Exagent1999)
  install folder        %ProgramFiles%\<sanitised group name>\Agent
  service display name  "<group name>"
  service name          ExSoftwaresAgent_<group key>
  registry              HKLM\Software\EXagent\Groups\<sanitised group name>

Coexistence
-----------
Two different device groups are different products: the UpgradeCode and all
component GUIDs are derived with uuid5 from the immutable mesh id, so installing
group B leaves group A untouched instead of silently uninstalling it. Reusing
the mesh id (not the name) also means renaming a group keeps the same product
identity, so the rename is an in-place upgrade rather than a second app.

The MSI embeds two binaries:

  ex-softwares-agent.exe      the MeshCentral Windows agent (meshid baked in)
  ex-softwares-agent-svc.exe  console-less service runner (scripts/msi-runner.nsi)

The second one is compiled here from the NSIS template unless --runner points
at a prebuilt copy. It exists because the agent is a CONSOLE-subsystem binary:
running it directly from a Type-18 custom action makes Windows Installer pop up
a black console window during the install. The runner is a GUI-subsystem
executable that launches the agent through nsExec (redirected stdio, no console)
and simply forwards its own command line (-fullinstall / -fulluninstall).

The file names shared by the WiX template and the NSIS runner (the agent binary
and the runner itself) are single constants here and are rendered into both
sources, then read back out of the rendered sources as an assertion: a runner
that looks for a file the MSI never installs was exactly the bug that shipped a
package installing nothing but files (the service was never registered).
"""
import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.environ.get("MSI_TEMPLATE") or os.path.join(HERE, "msi-template.wxs")
RUNNER_TEMPLATE = os.environ.get("MSI_RUNNER_TEMPLATE") or os.path.join(HERE, "msi-runner.nsi")
# PowerShell helper embedded in the runner (service install / repair / removal).
# The runner extracts it to $PLUGINSDIR and executes it; it is compiled into the
# runner .exe, so an edit here is a build dependency of every MSI.
RUNNER_HELPER = os.environ.get("MSI_RUNNER_HELPER") or os.path.join(HERE, "agent-service-install.ps1")

# --- file names inside the package -----------------------------------------
# Rendered into both msi-template.wxs (File Name=) and msi-runner.nsi
# (AGENT_FILENAME), then verified. They must never be typed twice by hand.
AGENT_FILENAME = "ex-softwares-agent.exe"
SVC_FILENAME = "ex-softwares-agent-svc.exe"
# Name of the runner binary *while it is being compiled* (never installed).
RUNNER_BUILD_FILENAME = "exagent-agent-svc.exe"

# Every GUID is derived from this namespace plus the mesh id, so it is stable
# across rebuilds, machines and Python versions. Never change it: a different
# UpgradeCode turns an upgrade into a second side-by-side install.
GUID_NAMESPACE = uuid.UUID("a4d1c0f6-3b2e-4c58-9f71-0d6a8e5b2c93")

FALLBACK_PRODUCT_NAME = "EXagent"
# --- toolchain discovery ---------------------------------------------------
# The Windows build host installs the WiX v3 toolset and NSIS in their own
# directories (C:\exrmm\wix, C:\Program Files (x86)\NSIS) and neither is on
# %PATH%. The portal backend spawns this script, so the inherited PATH is the
# one the long-running Node process had at start-up - a machine PATH change
# does not reach it. A download therefore failed with 'no WiX compiler found'
# on a host that already had candle.exe/light.exe installed. Seed the lookup
# with the directories the tools are installed in instead of trusting PATH.
# MSI_WIX_BIN / MSI_NSIS_DIR override the defaults.
_TOOL_DIRS = (
    os.environ.get("MSI_WIX_BIN") or "",
    os.environ.get("MSI_NSIS_DIR") or "",
    r"C:\exrmm\wix",
    r"C:\exrmm\nsis",
    r"C:\Program Files (x86)\WiX Toolset v3.14\bin",
    r"C:\Program Files (x86)\WiX Toolset v3.11\bin",
    r"C:\Program Files\WiX Toolset v3.14\bin",
    r"C:\Program Files (x86)\NSIS",
    r"C:\Program Files\NSIS",
)


def seed_tool_path():
    """Prepend the installed build-tool directories to PATH."""
    extra = []
    for directory in _TOOL_DIRS:
        if directory and os.path.isdir(directory) and directory not in extra:
            extra.append(directory)
    if extra:
        parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
        os.environ["PATH"] = os.pathsep.join(
            extra + [p for p in parts if p not in extra]
        )
    return extra


seed_tool_path()


# scripts/ -> repo root -> brand/assets/favicon/favicon.ico
# Add/Remove Programs icon: brand asset when the brand pack is checked out,
# otherwise the favicon the web portal already ships. An .ico is required here,
# a .png cannot be used by the Icon table.
_ICON_CANDIDATES = (
    os.path.join(os.path.dirname(HERE), "brand", "assets", "favicon", "favicon.ico"),
    os.path.join(os.path.dirname(HERE), "frontend", "public", "favicon.ico"),
)
DEFAULT_ICON = next((p for p in _ICON_CANDIDATES if os.path.isfile(p)), "")

# Windows refuses these as directory names, whatever the extension.
_RESERVED_DOS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def xml_escape(value: str, wixl: bool = True) -> str:
    """Escape a value for the WiX source.

    wixl runs its own substitution pass over attribute values: a single dollar
    sign starts a variable reference and is silently deleted. MeshCentral mesh
    ids contain a dollar sign (base64 variant), so the id lost a character on
    the way into the package - ARPCOMMENTS and the registry MeshId string came
    out wrong. A doubled dollar sign is wixl's escape for one literal dollar
    and round-trips back to a single one in the built MSI.

    WiX v3 (candle/light) does no such substitution - only `$(var.x)`,
    `$(env.x)` and `$(sys.x)` are special - so a bare `$` is left alone there;
    doubling it would put a literal `$$` into the package.
    """
    escaped = (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    if wixl:
        escaped = escaped.replace("$", "$$")
    return escaped


def nsis_escape(value: str) -> str:
    """Make a value safe inside an NSIS double-quoted string literal.

    NSIS has no escaping inside "" - a literal quote or dollar sign would end
    the string or start a variable reference. Names come from the portal, so
    strip the dangerous characters rather than trusting them.
    """
    cleaned = value.replace('"', "").replace("$", "").replace("\\", "/")
    cleaned = "".join(ch for ch in cleaned if ch.isprintable())
    return cleaned.strip()


def display_name(client) -> str:
    """The device group name as the user sees it: trimmed, single spaces."""
    name = " ".join(str(client or "").split())
    return name or FALLBACK_PRODUCT_NAME


def install_dir_name(client) -> str:
    """Windows folder name for this group, derived from the group name.

    Human readable on purpose (a technician looking in Program Files must find
    the group they installed), but stripped of everything Windows rejects in a
    path component, of `$` (it is a substitution sigil in both wixl and NSIS),
    and of trailing dots/spaces.
    """
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "-", display_name(client))
    name = name.replace("$", "").replace("%", "")
    name = re.sub(r"\s+", " ", name).strip().strip(".").strip()
    if len(name) > 40:
        name = name[:40].strip().strip(".").strip()
    if not name:
        name = FALLBACK_PRODUCT_NAME
    if name.split(".")[0].upper() in _RESERVED_DOS_NAMES:
        name += "-agent"
    return name


def service_name(client) -> str:
    """Service (SCM) name for this group.

    The agent's own -fullinstall would register one shared name
    (ExSoftwaresAgent) for every group, so two groups could never coexist:
    the second install would hijack the first one's service. Derive it from the
    group instead. Lower-case alphanumerics only, so Windows' case-insensitive
    service table cannot collapse two different groups into one name.
    """
    key = re.sub(r"[^a-z0-9]", "", display_name(client).lower())
    if not key:
        key = hashlib.sha1(display_name(client).encode("utf-8")).hexdigest()[:12]
    return "ExSoftwaresAgent_" + key[:40]


def registry_key(client) -> str:
    """Per-group metadata key (the legacy shared key caused the same collision)."""
    return "Software\\EXagent\\Groups\\" + install_dir_name(client)


def guid_for(meshid: str, purpose: str) -> str:
    """Deterministic GUID for one MSI identity owned by one device group."""
    return str(uuid.uuid5(GUID_NAMESPACE, "%s|%s" % (purpose, meshid))).upper()


def icon_block(path, wixl: bool = True):
    """Optional Add/Remove Programs icon; empty string when unused."""
    if not path or not os.path.isfile(path):
        return ""
    return (
        '    <Icon Id="EXagentIcon" SourceFile="%s" />\n'
        '    <Property Id="ARPPRODUCTICON" Value="EXagentIcon" />'
        % xml_escape(os.path.abspath(path), wixl=wixl)
    )


def nsis_path(path):
    """Absolute path in the separator form makensis on this host resolves.

    makensis on Linux needs forward slashes; makensis on Windows does not find
    a "C:/dir/file" source spec at all ("no files found") and needs the native
    backslash form.
    """
    path = os.path.abspath(path)
    return path if os.name == "nt" else path.replace("\\", "/")


def build_runner(template_path, names, out_dir, keep_nsi=False, helper_path=None):
    """Compile scripts/msi-runner.nsi into the console-less launcher.

    `names` carries every per-group value the runner needs (agent file name,
    service name, display name, install folder). Returns the absolute path of
    the produced .exe. Raises RuntimeError with the full makensis output on any
    failure - a missing runner would otherwise silently produce an MSI with
    broken (dropped) service custom actions.
    """
    if not shutil.which("makensis"):
        raise RuntimeError("makensis not found (apt install nsis)")
    if not os.path.isfile(template_path):
        raise RuntimeError("runner template not found: " + template_path)
    helper_path = helper_path or RUNNER_HELPER
    if not os.path.isfile(helper_path):
        raise RuntimeError("runner helper script not found: " + helper_path)

    with open(template_path, encoding="utf-8") as fh:
        nsi = fh.read()

    runner_exe = os.path.join(out_dir, RUNNER_BUILD_FILENAME)
    render = {
        "{{OUTFILE}}": nsis_path(runner_exe),
        "{{PRODUCT_NAME}}": nsis_escape(names["product_name"]) or FALLBACK_PRODUCT_NAME,
        "{{AGENT_FILENAME}}": nsis_escape(names["agent_filename"]),
        "{{SVC_FILENAME}}": nsis_escape(names["svc_filename"]),
        "{{SERVICE_NAME}}": nsis_escape(names["service_name"]),
        "{{SERVICE_DISPLAY_NAME}}": nsis_escape(names["service_display_name"]),
        "{{INSTALL_DIR}}": nsis_escape(names["install_dir"]),
        # Absolute path, forward slashes: makensis resolves File paths for the
        # rendered .nsi that is written into the build directory, not scripts/.
        "{{HELPER_PS1}}": nsis_path(helper_path),
    }
    for key, val in render.items():
        nsi = nsi.replace(key, val)

    if "{{" in nsi or "}}" in nsi:
        raise RuntimeError("unrendered placeholder remains in runner template")

    os.makedirs(out_dir, exist_ok=True)
    nsi_path = os.path.join(out_dir, "msi-runner.nsi")
    with open(nsi_path, "w", encoding="utf-8") as fh:
        fh.write(nsi)

    if os.path.exists(runner_exe):
        os.unlink(runner_exe)

    cmd = ["makensis", nsi_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.exists(runner_exe) or os.path.getsize(runner_exe) < 1024:
        raise RuntimeError(
            "makensis failed (exit %s):\n%s%s"
            % (res.returncode, res.stdout, res.stderr)
        )

    if not keep_nsi:
        try:
            os.unlink(nsi_path)
        except OSError:
            pass

    # The whole point of the runner is that it is a GUI-subsystem binary; a
    # console stub would reintroduce the black window this file exists to
    # remove. Read the PE subsystem straight from the header: objdump is a
    # Linux-only tool and is not installed on the Windows build host.
    if pe_subsystem(runner_exe) == 3:
        raise RuntimeError("runner compiled as a console binary")

    return runner_exe


def pe_subsystem(path):
    """Windows PE subsystem of a binary (2 = GUI, 3 = console), or None.

    The service runner must be GUI-subsystem: a console-subsystem runner shows
    a black console window during the install, which is exactly what it is
    there to avoid.
    """
    try:
        with open(path, "rb") as fh:
            dos = fh.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            fh.seek(struct.unpack_from("<I", dos, 0x3C)[0])
            hdr = fh.read(0x18)
            if len(hdr) < 0x18 or hdr[:4] != b"PE\0\0":
                return None
            opt_size = struct.unpack_from("<H", hdr, 0x14)[0]
            opt = fh.read(opt_size)
            if len(opt) < 0x46:
                return None
            if struct.unpack_from("<H", opt, 0)[0] not in (0x10B, 0x20B):
                return None
            return struct.unpack_from("<H", opt, 0x44)[0]
    except (OSError, struct.error):
        return None


def _msi_windows_table(msi_path, table):
    """Rows of one MSI table read through msi.dll (Windows build host).

    Same shape as the msiinfo reader below: every column in table order, NULLs
    as empty strings. The column order is significant - verify_package()
    addresses columns by index exactly like the msiinfo export does.
    """
    import ctypes
    from ctypes import wintypes

    try:
        msi = ctypes.WinDLL("msi")
    except OSError:
        return None

    handle = wintypes.HANDLE
    msi.MsiOpenDatabaseW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                     ctypes.POINTER(handle)]
    msi.MsiOpenDatabaseW.restype = wintypes.UINT
    msi.MsiDatabaseOpenViewW.argtypes = [handle, wintypes.LPCWSTR,
                                         ctypes.POINTER(handle)]
    msi.MsiDatabaseOpenViewW.restype = wintypes.UINT
    msi.MsiViewExecute.argtypes = [handle, handle]
    msi.MsiViewExecute.restype = wintypes.UINT
    msi.MsiViewFetch.argtypes = [handle, ctypes.POINTER(handle)]
    msi.MsiViewFetch.restype = wintypes.UINT
    msi.MsiRecordGetFieldCount.argtypes = [handle]
    msi.MsiRecordGetFieldCount.restype = wintypes.UINT
    msi.MsiRecordGetStringW.argtypes = [handle, wintypes.UINT, wintypes.LPWSTR,
                                        ctypes.POINTER(wintypes.DWORD)]
    msi.MsiRecordGetStringW.restype = wintypes.UINT
    msi.MsiCloseHandle.argtypes = [handle]
    msi.MsiCloseHandle.restype = wintypes.UINT

    ERROR_SUCCESS = 0
    ERROR_MORE_DATA = 234
    ERROR_NO_MORE_ITEMS = 259

    def field(hrec, index):
        size = wintypes.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)
        rc = msi.MsiRecordGetStringW(hrec, index, buf, ctypes.byref(size))
        if rc == ERROR_MORE_DATA:
            buf = ctypes.create_unicode_buffer(size.value + 1)
            size = wintypes.DWORD(size.value + 1)
            rc = msi.MsiRecordGetStringW(hrec, index, buf, ctypes.byref(size))
        return buf.value if rc == ERROR_SUCCESS else ""

    db = handle()
    if msi.MsiOpenDatabaseW(os.path.abspath(msi_path), None,
                            ctypes.byref(db)) != ERROR_SUCCESS:
        return None
    view = handle()
    rows = None
    try:
        query = "SELECT * FROM `" + table + "`"
        if msi.MsiDatabaseOpenViewW(db, query, ctypes.byref(view)) != ERROR_SUCCESS:
            return None
        if msi.MsiViewExecute(view, 0) != ERROR_SUCCESS:
            return None
        rows = []
        while True:
            rec = handle()
            rc = msi.MsiViewFetch(view, ctypes.byref(rec))
            if rc == ERROR_NO_MORE_ITEMS:
                break
            if rc != ERROR_SUCCESS:
                return None
            try:
                count = msi.MsiRecordGetFieldCount(rec)
                rows.append([field(rec, i + 1) for i in range(count)])
            finally:
                msi.MsiCloseHandle(rec)
    finally:
        if view.value:
            msi.MsiCloseHandle(view)
        if db.value:
            msi.MsiCloseHandle(db)
    return rows


def _msi_table(msi_path, table):
    """Rows of one MSI table as lists of strings, or None when unavailable."""
    if os.name == "nt":
        return _msi_windows_table(msi_path, table)
    if not shutil.which("msiinfo"):
        return None
    res = subprocess.run(
        ["msiinfo", "export", msi_path, table], capture_output=True, text=True
    )
    if res.returncode != 0:
        return None
    lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
    # Three header lines: column names, column types, then the names again.
    return [ln.split("\t") for ln in lines[3:]]


def _long_name(value):
    """The long part of an MSI "shortname|longname" name field.

    WiX v3 generates 8.3 short names for directory and file names that do not
    fit and stores them as "TESTGR~1|Test Group"; wixl leaves the plain name.
    Both install the long name, which is what the naming contract is about.
    """
    return value.split("|", 1)[1] if "|" in value else value


def verify_package(msi_path, expected):
    """Read the built MSI back and fail if the naming did not land in it.

    Catches the whole class of bug this script exists for: a package whose
    metadata says one thing while the files/services it installs say another.
    """
    props = _msi_table(msi_path, "Property")
    if props is None:
        print("note: msiinfo unavailable, skipping MSI read-back checks",
              file=sys.stderr)
        return []
    props = {row[0]: (row[1] if len(row) > 1 else "") for row in props if row}
    problems = []

    if props.get("ProductName") != expected["product_name"]:
        problems.append(
            "ProductName is %r, expected %r"
            % (props.get("ProductName"), expected["product_name"])
        )
    if props.get("UpgradeCode", "").strip("{}").upper() != expected["upgrade_code"]:
        problems.append(
            "UpgradeCode is %r, expected %r"
            % (props.get("UpgradeCode"), expected["upgrade_code"])
        )
    if expected["mesh_id"] not in props.get("ARPCOMMENTS", ""):
        problems.append("ARPCOMMENTS does not carry the mesh id")

    dirs = _msi_table(msi_path, "Directory") or []
    default_dirs = {row[0]: _long_name(row[2] if len(row) > 2 else "") for row in dirs}
    if default_dirs.get("INSTALLFOLDER") != expected["install_dir"]:
        problems.append(
            "install folder is %r, expected %r"
            % (default_dirs.get("INSTALLFOLDER"), expected["install_dir"])
        )

    files = _msi_table(msi_path, "File") or []
    installed = {(row[0], _long_name(row[2])) for row in files if len(row) > 2}
    for file_id, name in (
        ("AgentExe", expected["agent_filename"]),
        ("AgentRunnerExe", expected["svc_filename"]),
    ):
        if (file_id, name) not in installed:
            problems.append("file %s is not installed as %r" % (file_id, name))
    # The runner must look for the file name the MSI really installs.
    if expected["agent_filename"] != expected["runner_agent_filename"]:
        problems.append(
            "runner expects %r but the MSI installs %r"
            % (expected["runner_agent_filename"], expected["agent_filename"])
        )

    reg = _msi_table(msi_path, "Registry") or []
    # wixl stores registry keys with a trailing backslash.
    keys = {row[2].rstrip("\\") for row in reg if len(row) > 2}
    if expected["reg_key"].rstrip("\\") not in keys:
        problems.append("registry key %r missing" % expected["reg_key"])

    # Both group folders must be removed on uninstall, or uninstalling leaves
    # %ProgramFiles%\<group>\Agent behind forever.
    remove_rows = _msi_table(msi_path, "RemoveFile") or []
    removed_dirs = {row[3] for row in remove_rows if len(row) > 3}
    for folder in ("AGENTFOLDER", "INSTALLFOLDER"):
        if folder not in removed_dirs:
            problems.append("%s is not removed on uninstall" % folder)
    return problems


def wix_compiler():
    """Which WiX compiler this host has: wixl or the WiX v3 toolset."""
    wixl = shutil.which("wixl")
    if wixl:
        return "wixl", [wixl]
    candle = shutil.which("candle")
    light = shutil.which("light")
    if candle and light:
        return "wix", [candle, light]
    return None, []


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--agent", required=True)
    p.add_argument("--client", required=True,
                   help="device group name; becomes the installed application name")
    p.add_argument("--meshid", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--version", default="1.0.0")
    p.add_argument("--icon", default=DEFAULT_ICON)
    p.add_argument("--no-icon", action="store_true")
    p.add_argument("--keep-wxs", action="store_true")
    p.add_argument("--runner", default=None,
                   help="prebuilt console-less runner .exe (otherwise compiled here)")
    p.add_argument("--runner-template", default=RUNNER_TEMPLATE)
    p.add_argument("--runner-helper", default=RUNNER_HELPER,
                   help="PowerShell helper embedded in the service runner")
    p.add_argument("--keep-runner-nsi", action="store_true")
    p.add_argument("--print-names", action="store_true",
                   help="print the derived names as JSON and exit")
    args = p.parse_args()

    names = {
        "product_name": display_name(args.client),
        "agent_filename": AGENT_FILENAME,
        "svc_filename": SVC_FILENAME,
        "install_dir": install_dir_name(args.client),
        "service_name": service_name(args.client),
        "service_display_name": display_name(args.client),
        "reg_key": registry_key(args.client),
    }

    if args.print_names:
        import json
        print(json.dumps(names, indent=2))
        return 0

    compiler, compiler_tools = wix_compiler()
    if compiler is None:
        print(
            "no WiX compiler found: install wixl (apt install wixl) or the "
            "WiX v3 toolset (candle.exe/light.exe) on PATH",
            file=sys.stderr,
        )
        return 2
    if not os.path.isfile(args.agent):
        print(f"agent binary not found: {args.agent}", file=sys.stderr)
        return 2
    if not os.path.isfile(TEMPLATE):
        print(f"template not found: {TEMPLATE}", file=sys.stderr)
        return 2

    out_abs = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    # Build the console-less launcher first: its path goes into the WiX source.
    # Keep generated intermediates out of the served cache directory: the
    # NSIS builder already uses a build/ subdirectory next to the installer.
    build_dir = os.path.join(os.path.dirname(out_abs), "build")

    if args.runner:
        runner_exe = os.path.abspath(args.runner)
        if not os.path.isfile(runner_exe):
            print(f"runner binary not found: {runner_exe}", file=sys.stderr)
            return 2
    else:
        try:
            runner_exe = build_runner(
                args.runner_template, names,
                build_dir, args.keep_runner_nsi, args.runner_helper,
            )
        except RuntimeError as err:
            print(str(err), file=sys.stderr)
            return 5
        print(f"built runner {runner_exe} ({os.path.getsize(runner_exe)} bytes)")

    with open(TEMPLATE, encoding="utf-8") as fh:
        wxs = fh.read()

    upgrade_code = guid_for(args.meshid, "upgrade")
    # wixl substitutes `$...` in attribute values, WiX v3 does not: escape the
    # dollar sign for the compiler that is actually being used.
    escape = lambda value: xml_escape(value, wixl=(compiler == "wixl"))
    subs = {
        "{{PRODUCT_NAME}}": escape(names["product_name"]),
        "{{CLIENT_NAME}}": escape(names["product_name"]),
        "{{MESH_ID}}": escape(args.meshid),
        "{{SERVER_URL}}": escape(args.server),
        "{{PRODUCT_VERSION}}": escape(args.version),
        "{{UPGRADE_CODE}}": upgrade_code,
        "{{INSTALL_DIR}}": escape(names["install_dir"]),
        "{{SERVICE_NAME}}": escape(names["service_name"]),
        "{{SERVICE_DISPLAY_NAME}}": escape(names["service_display_name"]),
        "{{REG_KEY}}": escape(names["reg_key"]),
        "{{AGENT_FILENAME}}": escape(names["agent_filename"]),
        "{{SVC_FILENAME}}": escape(names["svc_filename"]),
        "{{COMPONENT_GUID_BINARY}}": guid_for(args.meshid, "component:agent"),
        "{{COMPONENT_GUID_RUNNER}}": guid_for(args.meshid, "component:runner"),
        "{{COMPONENT_GUID_METADATA}}": guid_for(args.meshid, "component:metadata"),
        "{{COMPONENT_GUID_FOLDER}}": guid_for(args.meshid, "component:folder"),
        "{{AGENT_EXE}}": xml_escape(os.path.abspath(args.agent)),
        "{{RUNNER_EXE}}": xml_escape(runner_exe),
        "{{OUTFILE}}": xml_escape(out_abs),
        "{{ICON_BLOCK}}": icon_block(
            None if args.no_icon else args.icon, wixl=(compiler == "wixl")
        ),
    }
    for key, val in subs.items():
        wxs = wxs.replace(key, val)

    if "{{" in wxs or "}}" in wxs:
        print("unrendered placeholder remains in template", file=sys.stderr)
        return 3

    wxs_path = os.path.join(build_dir, "agent-msi.wxs")
    with open(wxs_path, "w", encoding="utf-8") as fh:
        fh.write(wxs)

    if os.path.exists(out_abs):
        os.unlink(out_abs)

    # The architecture flag is mandatory: it sets the "x64;1033" summary
    # template that makes ProgramFiles64Folder / Win64 components legal.
    # wixl takes it as -a, the WiX v3 toolset as `candle -arch`.
    intermediates = [wxs_path]
    if compiler == "wixl":
        cmd = ["wixl", "-a", "x64", "-v", "-o", out_abs, wxs_path]
        print("+ " + " ".join(cmd))
        res = subprocess.run(cmd, capture_output=True, text=True)
        output = (res.stdout or "") + (res.stderr or "")
        sys.stdout.write(res.stdout or "")
        sys.stderr.write(res.stderr or "")

        if not os.path.exists(out_abs):
            print(f"wixl failed (exit {res.returncode})", file=sys.stderr)
            return res.returncode or 1

        # Reject silent element drops: wixl keeps going when it meets an
        # attribute it does not understand, which produces a broken installer.
        problems = [
            line
            for line in output.splitlines()
            if "no property named" in line
            or "Unsupported" in line
            or "assertion" in line
        ]
        if problems:
            print("wixl dropped or rejected elements:", file=sys.stderr)
            for line in problems:
                print("  " + line.strip(), file=sys.stderr)
            return 4
    else:
        candle, light = compiler_tools
        obj_path = os.path.join(build_dir, "agent-msi.wixobj")
        intermediates.append(obj_path)
        if os.path.exists(obj_path):
            os.unlink(obj_path)
        cmd = [candle, "-nologo", "-arch", "x64", "-o", obj_path, wxs_path]
        print("+ " + " ".join(cmd))
        res = subprocess.run(cmd, capture_output=True, text=True)
        sys.stdout.write(res.stdout or "")
        sys.stderr.write(res.stderr or "")
        if res.returncode != 0 or not os.path.exists(obj_path):
            print(f"candle failed (exit {res.returncode})", file=sys.stderr)
            return res.returncode or 1

        cmd = [light, "-nologo", "-o", out_abs, obj_path]
        print("+ " + " ".join(cmd))
        res = subprocess.run(cmd, capture_output=True, text=True)
        sys.stdout.write(res.stdout or "")
        sys.stderr.write(res.stderr or "")
        if not os.path.exists(out_abs):
            print(f"light failed (exit {res.returncode})", file=sys.stderr)
            return res.returncode or 1

    expected = dict(names)
    expected.update(
        mesh_id=args.meshid,
        upgrade_code=upgrade_code,
        runner_agent_filename=names["agent_filename"],
    )
    readback = verify_package(out_abs, expected)
    if readback:
        print("built package does not match the requested names:", file=sys.stderr)
        for line in readback:
            print("  " + line, file=sys.stderr)
        return 6

    if not args.keep_wxs:
        for path in intermediates:
            try:
                os.unlink(path)
            except OSError:
                pass
    print(
        "built %s (%s bytes) product=%r folder=%r service=%r"
        % (out_abs, os.path.getsize(out_abs), names["product_name"],
           names["install_dir"], names["service_name"])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
