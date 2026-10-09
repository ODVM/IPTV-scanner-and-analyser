"""IPTV_scanner.pyw
======
Assembly in .exe:
Manually:
pyinstaller --noconfirm --clean --onefile --windowed --name IPTV_Scanner --hidden-import vpn --add-data "vpn.py;." IPTV_scanner.pyw
IPTV_Scanner.exe is assembled second, after vpn.exe is assembled, the hash is calculated and entered.
Automatic: use python build.py
======"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import functools
import queue
import threading
import time
import requests
import re
import json
import sys
import os
import subprocess
import platform
import ctypes
from ctypes import wintypes
import atexit
import logging
import logging.handlers
import math
import colorsys
import ipaddress
import faulthandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Union, cast, Set, Callable
from enum import Enum
from types import ModuleType
import socket
from urllib.parse import urlsplit, urlunsplit

# Warning until logger is fully configured (RotatingFileHandler is not yet available).
# Otherwise, except OSError in optional WinAPI blocks catches NameError on logger
# and masks the real reason the DLL is unavailable.
_EARLY_LOG_WARNINGS: List[str] = []

# Sound only on Windows
winsound: Optional[Any]
if platform.system() == "Windows":
    import winsound
else:
    winsound = None

# === Path to config ===
base_path = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent

# === VPN subsystem (all functionality is in one vpn.py file next to
# script; see its docstring) ===
# Here, in the main GUI process, from vpn.py only
# unprivileged client functions. Server (elevated) role
# the same file is launched ONLY by a separate process via vpn.launch_helper()
# (see ScannerGUI._sett_finish_vpn_and_close) - the main process itself
# the scanner never executes it.
#
# sys.path.insert(0, base_path) - ONLY in dev mode. In dev mode
# base_path = script directory, and vpn.py is also there; explicit insert
# provides insurance in case IPTV_scanner.pyw is imported
# in a non-standard way (not through `python IPTV_scanner.pyw`, but,
# for example via exec/open/importlib) when sys.path[0] does not match
# with the script directory.
#
# In frozen mode (PyInstaller) base_path = IPTV_Scanner.exe directory.
# You CANNOT insert it into sys.path there: vpn is already accessible via
# PyInstaller's meta_path-finder (--hidden-import vpn), optional
# sys.path.insert is not needed here, but provides a potential replacement point -
# if in sys.path search (for one reason or another, including changes
# in future versions of PyInstaller) will be ahead of the meta_path loader,
# then the vpn.py lying next to the EXE will override the built-in module. vpn
# participates in launching an elevated helper (launch_helper → ShellExecuteExW
# with verb="runas"), so replacing this particular module is an attempt
# bypassing the UAC boundary, and not just replacing “some code”. Examination
# SHA-256 (verify_helper_integrity) does not help here: it protects
# vpn.exe, but this is another artifact.
_vpn_import_error: Optional[BaseException] = None
vpn: Optional[ModuleType]
try:
    if not getattr(sys, "frozen", False):
        sys.path.insert(0, str(base_path))
    import vpn
except Exception as _e:  # noqa: N816 - logged below when logger has already been created
    vpn = None
    _vpn_import_error = _e

# ---------------------------------------------------------------------------
# Local probe helpers and client Wi-Fi soft reset (no elevation; see
# _wifi_soft_reset_local). _local_probe_hosts is scanner-only.
# ---------------------------------------------------------------------------

_LOCAL_PROBE_TCP_TIMEOUT = 2.5
_LOCAL_PROBE_HTTP_TIMEOUT = 3.0
_LOCAL_PROBE_MAX_WORKERS = 8


def _local_tcp_probe(host: str, port: int,
                     timeout: float = _LOCAL_PROBE_TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _local_http_probe(host: str, port: int, scheme: str = "http",
                      timeout: float = _LOCAL_PROBE_HTTP_TIMEOUT) -> bool:
    try:
        # IPv6 literals are filtered in _extract_proxy_hosts (see its docstring).
        # If that filter is ever removed, host must be bracketed here and
        # vpn.connect_and_route needs an IPv6 branch (currently AF_INET only).
        url = f"{scheme}://{host}:{port}/"
        # verify=True explicitly rather than the default requests: probe for
        # The https scheme should behave exactly the same as a real download
        # playlist (fetch_playlist_channels) and stream
        # (StreamFetcher.open_stream). Otherwise, the probe could "approve" the host,
        # which the real download will then reject on TLS-handshake, and
        # precheck would run the scan blindly.
        r = requests.get(
            url, timeout=timeout, stream=True, allow_redirects=False,
            verify=True,
        )
        r.close()
        return True
    except Exception:
        return False


def _local_probe_hosts(hosts) -> Dict[Tuple[Any, ...], bool]:
    hosts_list = list(dict.fromkeys(hosts))
    if not hosts_list:
        return {}
    results: Dict[Tuple[Any, ...], bool] = {}

    def _probe(item: Tuple[Any, ...]) -> bool:
        host, port = item[0], item[1]
        scheme = str(item[2]).lower() if len(item) >= 3 else "http"
        if not _local_tcp_probe(host, port):
            return False
        return _local_http_probe(host, port, scheme)

    with ThreadPoolExecutor(
        max_workers=min(_LOCAL_PROBE_MAX_WORKERS, len(hosts_list))
    ) as pool:
        futures = {pool.submit(_probe, item): item for item in hosts_list}
        for fut in as_completed(futures):
            item = futures[fut]
            try:
                results[item] = fut.result()
            except Exception:
                results[item] = False
    return results


# === WLAN API (client-side; used by _wifi_soft_reset_local, no elevation) ===
_WLAN_MAX_NAME_LENGTH = 256
_wlan_interface_state_connected    = 1
_wlan_interface_state_disconnected = 4

_WLAN_API_AVAILABLE = False
if platform.system() == "Windows":
    try:
        _wlanapi_local = ctypes.WinDLL("wlanapi", use_last_error=True)

        class _WLAN_GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_uint32),
                ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class _WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", _WLAN_GUID),
                ("strInterfaceDescription",
                 ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
                ("isState", ctypes.c_uint32),
            ]

        class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", ctypes.c_uint32),
                ("dwIndex", ctypes.c_uint32),
                ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),
            ]

        _WlanOpenHandle = _wlanapi_local.WlanOpenHandle
        _WlanOpenHandle.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
        ]
        _WlanOpenHandle.restype = ctypes.c_uint32

        _WlanCloseHandle = _wlanapi_local.WlanCloseHandle
        _WlanCloseHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        _WlanCloseHandle.restype = ctypes.c_uint32

        _WlanEnumInterfaces = _wlanapi_local.WlanEnumInterfaces
        _WlanEnumInterfaces.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)),
        ]
        _WlanEnumInterfaces.restype = ctypes.c_uint32

        _WlanFreeMemoryLocal = _wlanapi_local.WlanFreeMemory
        _WlanFreeMemoryLocal.argtypes = [ctypes.c_void_p]
        _WlanFreeMemoryLocal.restype = None
        
        # Opcode constant (wlanapi.h): Query the current connection.
        _WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7

        class _WLAN_CONNECTION_ATTRIBUTES_HEAD(ctypes.Structure):
            """The first three fields of WLAN_CONNECTION_ATTRIBUTES(isState,
            wlanConnectionMode, strProfileName[256]). We don't need the rest -
            strProfileName lies on this prefix."""
            _fields_ = [
                ("isState", ctypes.c_uint32),
                ("wlanConnectionMode", ctypes.c_uint32),
                ("strProfileName", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
            ]

        _WlanQueryInterface = _wlanapi_local.WlanQueryInterface
        _WlanQueryInterface.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WLAN_GUID),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        _WlanQueryInterface.restype = ctypes.c_uint32

        _WLAN_API_AVAILABLE = True
    except OSError:
        _EARLY_LOG_WARNINGS.append(
            "wlanapi.dll is unavailable — local Wi-Fi soft reset "
            "will be degraded (falls back to netsh-only)"
        )


# === Win32 IP Helper: GetAdaptersAddresses ============================
# Modular bindings so as not to recreate WinDLL and struct class on
# every call to _is_internet_connected() (the health monitor calls it
# once per second). Explicit argtypes/restypes protect against “playing for luck”:
# without them, ctypes relies on argument conversion heuristics,
# which may diverge during refactoring or non-standard
# Windows builds.
#
# The constants are the same as those used in vpn.py; Here
# duplicated intentionally - the scanner should not depend on imports
# vpn.py (it's optional, see try/except around `import vpn` above),
# and the bindings are the same pattern that has already been used for wlanapi.
_GAA_FLAG_INCLUDE_PREFIX   = 0x0010
_GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
_AF_UNSPEC                 = 0
_IF_TYPE_PPP               = 23
_IF_TYPE_TUNNEL            = 131
_IF_TYPE_SOFTWARE_LOOPBACK = 24
_IF_OPER_STATUS_UP         = 1
_ERROR_BUFFER_OVERFLOW     = 111
_ERROR_SUCCESS             = 0

_IPHLPAPI_AVAILABLE = False
if platform.system() == "Windows":
    try:
        _iphlpapi_local = ctypes.WinDLL("iphlpapi", use_last_error=True)

        class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
            pass
        # Forward-reference: Next refers to itself via POINTER,
        # therefore _fields_ is set after the class declaration (as in vpn.py).
        _IP_ADAPTER_ADDRESSES._fields_ = [
            ("Length", wintypes.ULONG),
            ("IfIndex", wintypes.DWORD),
            ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
            ("AdapterName", ctypes.c_char_p),
            ("FirstUnicastAddress", ctypes.c_void_p),
            ("FirstAnycastAddress", ctypes.c_void_p),
            ("FirstMulticastAddress", ctypes.c_void_p),
            ("FirstDnsServerAddress", ctypes.c_void_p),
            ("DnsSuffix", wintypes.LPWSTR),
            ("Description", wintypes.LPWSTR),
            ("FriendlyName", wintypes.LPWSTR),
            ("PhysicalAddress", wintypes.BYTE * 8),
            ("PhysicalAddressLength", wintypes.DWORD),
            ("Flags", wintypes.DWORD),
            ("Mtu", wintypes.DWORD),
            ("IfType", wintypes.DWORD),
            ("OperStatus", wintypes.DWORD),
            ("Ipv6IfIndex", wintypes.DWORD),
            ("ZoneIndices", wintypes.DWORD * 16),
            ("FirstPrefix", ctypes.c_void_p),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
            ("FirstWinsServerAddress", ctypes.c_void_p),
            ("FirstGatewayAddress", ctypes.c_void_p),
        ]

        # argtypes/restype: exactly what is declared in iphlpapi.h:
        #   ULONG GetAdaptersAddresses(
        #       ULONG Family, ULONG Flags, PVOID Reserved,
        #       PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);
        # Previously, the call went without them - ctypes “guessed” correctly
        # conversions (byref(None) etc.), but this worked for
        # heuristics, not contract. An explicit signature captures
        # contract and catches inconsistencies in future edits.
        _GetAdaptersAddresses = _iphlpapi_local.GetAdaptersAddresses
        _GetAdaptersAddresses.argtypes = [
            wintypes.ULONG,                                # Family
            wintypes.ULONG,                                # Flags
            ctypes.c_void_p,                               # Reserved
            ctypes.POINTER(_IP_ADAPTER_ADDRESSES),         # AdapterAddresses
            ctypes.POINTER(wintypes.ULONG),                # SizePointer
        ]
        _GetAdaptersAddresses.restype = wintypes.ULONG

        _IPHLPAPI_AVAILABLE = True
    except OSError:
        _EARLY_LOG_WARNINGS.append(
            "iphlpapi.dll is unavailable — network health check will be "
            "degraded (_is_internet_connected will always return None)"
        )


# The same allowlist as _VPN_NAME_RE in vpn.py. Wi-Fi profile - name from
# netsh, potentially contains Cyrillic/spaces/NBSP; quotes, $, `, |, ;
# and newlines are stripped off (this is a future argv for netsh).
_WIFI_PROFILE_NAME_RE = re.compile(
    r"^[A-Za-z0-9\u0400-\u04FF .+\-()#\xa0]{1,256}$"
)


def _validate_wifi_profile_name(name: str) -> str:
    text = (name or "").strip()
    if not text or not _WIFI_PROFILE_NAME_RE.match(text):
        raise ValueError(f"Invalid Wi-Fi profile name: {name!r}")
    return text


def _wifi_enum_interfaces_local() -> List[Dict[str, Any]]:
    """List of WLAN interfaces: [{"state": int}, ...]."""
    if not _WLAN_API_AVAILABLE:
        return []
    wlan_handle = ctypes.c_void_p()
    negotiated = ctypes.c_uint32()
    rc = _WlanOpenHandle(
        2, None, ctypes.byref(negotiated), ctypes.byref(wlan_handle),
    )
    if rc != 0:
        return []
    try:
        p_list = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
        rc = _WlanEnumInterfaces(wlan_handle, None, ctypes.byref(p_list))
        if rc != 0:
            return []
        try:
            lst = p_list.contents
            count = int(lst.dwNumberOfItems)
            if count == 0:
                return []
            base_addr = ctypes.addressof(lst.InterfaceInfo)
            elem_size = ctypes.sizeof(_WLAN_INTERFACE_INFO)
            out: List[Dict[str, Any]] = []
            for i in range(count):
                info = _WLAN_INTERFACE_INFO.from_address(base_addr + i * elem_size)
                out.append({
                    "guid": info.InterfaceGuid,
                    "description": info.strInterfaceDescription or "",
                    "state": int(info.isState),
                })
            return out
        finally:
            _WlanFreeMemoryLocal(p_list)
    finally:
        _WlanCloseHandle(wlan_handle, None)


def _wifi_run_local(args: List[str], timeout: float):
    kwargs: Dict[str, Any] = {"capture_output": True, "timeout": timeout}
    if platform.system() == "Windows":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs["creationflags"] = getattr(
            subprocess, "CREATE_NO_WINDOW", 0,
        )
        kwargs["startupinfo"] = si
    return subprocess.run(args, **kwargs)


def _wifi_soft_reset_local(
    profile: str,
    wait_connected_sec: float = 15.0,
    reconcile_sec: float = 8.0,
    reconnect_retry_after_sec: float = 3.0,
) -> Dict[str, Any]:
    """Client Wi-Fi soft reset (no elevation; current-user profiles only).

    Flow: netsh wlan disconnect → brief pause → connect name=X → wait for
    Connected up to wait_connected_sec; on failed connect, a reconcile_sec
    window with one connect retry (no second disconnect).

    Same result contract as the server-side version so
    _run_intentional_l2_reset can treat both uniformly:
      {"ok": bool, "profile": str, "error": str|None, "reconciled": bool}
    """
    if platform.system() != "Windows":
        return {"ok": False, "profile": profile,
                "error": "not Windows", "reconciled": False}
    try:
        profile = _validate_wifi_profile_name(profile)
    except ValueError as e:
        return {"ok": False, "profile": profile, "error": str(e),
                "reconciled": False}

    connect_cmd = ["netsh", "wlan", "connect", f"name={profile}"]

    try:
        _wifi_run_local(["netsh", "wlan", "disconnect"], timeout=5.0)
    except Exception:
        logger.debug("netsh wlan disconnect failed", exc_info=True)

    time.sleep(2.0)

    connect_error: Optional[str] = None
    try:
        proc = _wifi_run_local(connect_cmd, timeout=8.0)
        if proc.returncode != 0:
            connect_error = f"netsh wlan connect returned {proc.returncode}"
    except subprocess.TimeoutExpired:
        connect_error = "netsh connect timeout"

    window = wait_connected_sec if connect_error is None else reconcile_sec
    started = time.monotonic()
    deadline = started + max(0.0, window)
    retried = False

    while time.monotonic() < deadline:
        time.sleep(0.5)
        ifaces = _wifi_enum_interfaces_local()
        connected = any(
            i["state"] == _wlan_interface_state_connected for i in ifaces
        )
        disconnected = bool(ifaces) and all(
            i["state"] == _wlan_interface_state_disconnected for i in ifaces
        )
        if connected:
            if connect_error is not None:
                logger.info(
                    "wifi_soft_reset(local): %s, but the adapter "
                    "returned to Connected (reconciled, profile=%r)",
                    connect_error, profile,
                )
            return {
                "ok": True, "profile": profile, "error": None,
                "reconciled": connect_error is not None,
            }
        if (
            connect_error is not None
            and not retried
            and disconnected
            and (time.monotonic() - started) >= reconnect_retry_after_sec
        ):
            retried = True
            logger.info(
                "wifi_soft_reset(local): adapter is still Disconnected "
                "after a failed connect (%s) — single connect retry "
                "(profile=%r)", connect_error, profile,
            )
            try:
                _wifi_run_local(connect_cmd, timeout=5.0)
            except Exception:
                logger.debug(
                    "wifi_soft_reset(local): retry connect failed",
                    exc_info=True,
                )

    if connect_error is not None:
        return {
            "ok": False, "profile": profile,
            "error": (
                f"{connect_error}; adapter did not become Connected "
                f"within {reconcile_sec:.0f}s reconcile window"
            ),
            "reconciled": False,
        }
    return {
        "ok": False, "profile": profile,
        "error": (
            f"adapter did not become Connected within "
            f"{wait_connected_sec:.0f}s"
        ),
        "reconciled": False,
    }


def _wlan_get_profile_name_local(iface_guid) -> Optional[str]:
    """The name of the active profile on this interface, or None."""
    if not _WLAN_API_AVAILABLE:
        return None
    handle = ctypes.c_void_p()
    negotiated = ctypes.c_uint32()
    rc = _WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle))
    if rc != 0:
        return None
    try:
        data_size = ctypes.c_uint32()
        data_ptr = ctypes.c_void_p()
        opcode_type = ctypes.c_uint32()
        rc = _WlanQueryInterface(
            handle, iface_guid,
            _WLAN_INTF_OPCODE_CURRENT_CONNECTION, None,
            ctypes.byref(data_size),
            ctypes.byref(data_ptr),
            ctypes.byref(opcode_type),
        )
        if rc != 0 or not data_ptr or data_ptr.value is None:
            return None
        try:
            attrs = _WLAN_CONNECTION_ATTRIBUTES_HEAD.from_address(data_ptr.value)
            if attrs.isState != _wlan_interface_state_connected:
                return None
            name = (attrs.strProfileName or "").strip()
            return name or None
        finally:
            _WlanFreeMemoryLocal(data_ptr)
    finally:
        _WlanCloseHandle(handle, None)


def get_active_wifi_profile_local() -> Optional[str]:
    """The profile (not SSID) of an active Wi-Fi connection is exactly that
    accepts `netsh wlan connect name=<profile>`. None if Wi-Fi is not available
    connected or WLAN API is not available. Without administrator rights.

    Does not depend on Windows language: interface state reads as
    numeric constant WLAN_INTERFACE_STATE, profile name - as a WCHAR string
    from WLAN_CONNECTION_ATTRIBUTES (see _wlan_enum_interfaces_local/
    _wlan_get_profile_name_local)."""
    if not _WLAN_API_AVAILABLE:
        return None
    for iface in _wifi_enum_interfaces_local():
        if iface["state"] != _wlan_interface_state_connected:
            continue
        # _wifi_enum_interfaces_local returns GUID as _WLAN_GUID
        # (struct value, not pointer). Take the address of the local copy
        # for the duration of the call - this is correct, because _WlanQueryInterface
        # synchronous.
        guid = iface["guid"]
        name = _wlan_get_profile_name_local(ctypes.byref(guid))
        if name:
            return name
    return None


def _data_dir(base: Path) -> Path:
    """Directory for scanner_config.json (hybrid, portability is more important for
    config that the user may want to carry with the program).

    Let's try to write next to the program (base_path - installation directory).
    If the ACL prohibits this (for example, the program is in Program Files, and
    the process is not elevated) - move to %LOCALAPPDATA%\\IPTV_Scanner\\.
    Called once at start. Logs and vpn_client_state.json are not here
    refer - see _logs_dir()/APPDATA_DIR below and vpn._appdata_dir():
    they are always, of course, written to %LOCALAPPDATA%\\IPTV_Scanner\\, without
    attempts to write next to the program."""
    try:
        probe = base / ".write_probe"
        probe.touch()
        probe.unlink()
        return base
    except OSError:
        fallback = Path(
            os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home()
        ) / "IPTV_Scanner"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _appdata_dir() -> Path:
    """%LOCALAPPDATA%\\IPTV_Scanner\\ - the same unconditional logic as in
    vpn.py (see vpn._appdata_dir()), duplicated here so as not
    depend on whether the vpn module was successfully imported (see try/except
    around `import vpn` above)."""
    base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home())
    d = base / "IPTV_Scanner"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _logs_dir() -> Path:
    """%LOCALAPPDATA%\\IPTV_Scanner\\logs\\ - always written here
    scanner.log, regardless of where the program is installed and whether there is
    write access there."""
    d = _appdata_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


# CONFIG_FILE - hybrid: next to the program, or (if not available for
# entries, such as Program Files) in %LOCALAPPDATA%\IPTV_Scanner\ (see
# _data_dir above). base_path (installation directory) to find resources
# (vpn.exe/logo.ico) does not change.
# LOG_FILE - definitely in %LOCALAPPDATA%\IPTV_Scanner\logs\ (see _logs_dir).
DATA_DIR = _data_dir(base_path)
CONFIG_FILE = DATA_DIR / "scanner_config.json"
LOG_FILE = _logs_dir() / "scanner.log"
LOG_MAX_BYTES = 1_000_000


# === Logging ===
# Standard RotatingFileHandler: when maxBytes is exceeded the current scanner.log
# renamed to scanner.log.1 (rather than cleared), so that when parsing
# incident that happened right before the rotation is something to look at.
logger = logging.getLogger("iptv_scanner")
logger.setLevel(logging.INFO)
logger.propagate = False
try:
    _log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=1, encoding="utf-8"
    )
    _log_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(_log_handler)
except OSError:
    logger.addHandler(logging.NullHandler())

for _msg in _EARLY_LOG_WARNINGS:
    logger.warning("%s", _msg)
_EARLY_LOG_WARNINGS.clear()

if _vpn_import_error is not None:
    logger.warning(
        "VPN module (vpn.py) not found or failed to load (%s) — "
        "the VPN fallback will be unavailable", _vpn_import_error
    )


# === TLS trust store ==================================================
# requests by default verifies TLS using the certifi bundle (comes with
# with requests), and not through the system Windows Certificate Store. By cars,
# where corporate root CA is installed via Group Policy/MDM/manually,
# this gives SSLError on HTTPS playlists that the browser and curl open
# no problem: the certificate is signed by a CA, which is not in certifi.
#
# truststore.inject_into_ssl() replaces ssl.SSLContext with the implementation,
# reading the system store. There is no need to keep any certificates in the code,
# verify=True remains in effect everywhere (see fetch_playlist_channels,
# _local_http_probe, StreamFetcher.open_stream) - only changes
# SOURCE trusted CAs.
#
# The absence of a package is not a reason not to start: the scanner works on certifi
# exactly the same way it worked before. Silent degradation: user
# without a corporate CA, the difference is not visible; the user with it needs
# either install truststore (pip install truststore) or add
# corporate CA in the certifi bundle manually.
try:
    import truststore
    truststore.inject_into_ssl()
    logger.info("TLS trust store: using the system store (truststore)")
except ImportError:
    # The package is not installed, or Python < 3.10 (truststore requires 3.10+).
    # We remain on the default requests (certifi) - the behavior is indistinguishable from
    # state before this edit.
    logger.debug("truststore not installed — using the certifi TLS bundle")
except Exception:
    # inject_into_ssl() may throw on unexpected SSL configuration
    # (for example, if ssl has already been patched by another library in this
    # process). We roll back to certifi and log: during parsing
    # The TLS incident should show that the system tried to use
    # system store, but could not.
    logger.warning(
        "truststore.inject_into_ssl() failed — falling back to certifi",
        exc_info=True,
    )


# ---------------------------------------------------------------------------
# Protocol constants (not tuned)
# ---------------------------------------------------------------------------
TS_PACKET_SIZE = 188
# Size of one read from a socket: 21 TS packets = 3948 B (multiples of 7 packets - typical
# UDP datagram 1316 B). The size was not chosen for performance reasons:
# iter_content() on a regular (non-chunked) HTTP response blocks until it accumulates
# ENTIRE chunk_size, so interval between reads = buffer filling time +
# real pause. With the previous 22 KB, the filling time itself was
# 0.5–1.2 s on channels 150–400 kbit/s and “ate up” the max_allowed_gap_sec threshold (1.1 s);
# at 3.9 KB it does not exceed ~0.1 s already from 300 kbps, and max_chunk_gap
# reflects precisely the pause in delivery. (For chunked responses, the reading size is set
# server and does not depend on this constant.)
READ_PACKET_COUNT = 21
MAX_TS_BUFFER = TS_PACKET_SIZE * 480   # ≈ 90 KB

MPEG2_STREAM_TYPES = {0x01, 0x02}
H264_STREAM_TYPES = {0x1B}
HEVC_STREAM_TYPES = {0x24}
MODERN_VIDEO_STREAM_TYPES = H264_STREAM_TYPES | HEVC_STREAM_TYPES
VIDEO_STREAM_TYPES = MPEG2_STREAM_TYPES | MODERN_VIDEO_STREAM_TYPES
AUDIO_STREAM_TYPES = {0x03, 0x04, 0x0F, 0x11, 0x81, 0x87}
# Video codecs that the scanner recognizes as video, but cannot parse
# (MPEG-4 Visual, MVC, JPEG 2000, JPEG XS, VVC, AVS, Dirac, VC-1). It's not a mistake
# channel: see Status.OK_UNSUPPORTED (“OK**”) and _classify_transport_only().
UNSUPPORTED_VIDEO_STREAM_TYPES = {0x10, 0x20, 0x21, 0x32, 0x33, 0x42, 0xD1, 0xEA}

# DVB (EN 300 468 §6.2) signals AC-3/Enhanced AC-3/DTS not separately
# stream_type (as ATSC, see 0x81/0x87 above), and via generic stream_type=0x06
# ("PES private data") plus one of these descriptors in the ES info loop inside
# PMT. Without taking them into account, such sound does not get into audio_pids, and on working channels
# A false "No sound" occurs.
# stream_type=0x06 in DVB is used for teletext (tag 0x56) and subtitles
# (tag 0x59) - they are deliberately not included in the set so as not to be mistaken for sound.
DVB_PRIVATE_STREAM_TYPE = 0x06
DVB_AUDIO_DESCRIPTOR_TAGS = {0x6A, 0x7A, 0x7B}  # AC-3, Enhanced AC-3, DTS

# Safety-net for Status.NO_AUDIO (see _is_no_audio). List of known codes
# audio (AUDIO_STREAM_TYPES + DVB_AUDIO_DESCRIPTOR_TAGS above) cannot be
# comprehensive: MPEG-H 3D Audio, DRA, Opus-in-TS and non-standard muxers for it
# not included. Therefore, additionally, it is definitely NOT the sound that is recognized; ES-stream,
# not suitable either for video, or for sound, or for these cases, is considered
# "unidentified" (ScanMetrics.unclassified_pids), and "no sound" is not
# states: when you are unsure, it is better to remain silent than to falsely report
# problem on a working channel.
KNOWN_NON_AUDIO_STREAM_TYPES = {0x05, 0x0B, 0x0C, 0x0D, 0x0E, 0x86, 0x95}
DVB_NON_AUDIO_DESCRIPTOR_TAGS = {0x56, 0x59}  # teletext, subtitling

SCRAMBLED_VALUES = {1, 2, 3}
MPEG2_SLICE_CODES = set(range(0x01, 0xB0))
H264_VCL_NAL_TYPES = {1, 2, 3, 4, 5, 19, 20}
H264_PARAM_NAL_TYPES = {7, 8}
HEVC_VCL_NAL_TYPES = set(range(0, 10)) | set(range(16, 22))
HEVC_PARAM_NAL_TYPES = {32, 33, 34}

# Filler data: the encoder finishes the CBR stream with a “dummy” INSIDE the video PID, and not
# NULL packets 0x1FFF. Such bytes do not carry pictures, but they also end up in
# video_payload_bytes, and in bitrate_kbps - a stream with a black screen looks like
# full 6 Mbit/s. Therefore, they must be counted separately.
H264_FILLER_NAL_TYPE = 12   # filler data NAL (H.264)
HEVC_FILLER_NAL_TYPE = 38   # FD_NUT (HEVC)

# MPEG-2 video: padding - zero bytes inside ES (stuffing between pictures /
# before the next start code). MPEG-2 compressed data has more than 22 zero bits
# cannot be in a row (otherwise the start code is emulated), so a series of 8+
# zero bytes - guaranteed stuffing, not a picture.
_MPEG2_STUFFING_RE = re.compile(rb"\x00{8,}")

# AAC sound. According to ISO 14496-3, the FIL element achieves fill_byte = 0xA5 (10100101).
# Since FIL starts at an arbitrary bit offset, the byte is visible in the stream
# in any of 8 cyclic shifts: A5, 4B, 96, 2D, 5A, B4, 69, D2.
AAC_STREAM_TYPES = {0x0F, 0x11}
_AAC_FILL_BYTES = [((0xA5 << i) | (0xA5 >> (8 - i))) & 0xFF for i in range(8)]
_AAC_FILL_RE = re.compile(
    b"|".join(re.escape(bytes([b])) + b"{8,}" for b in sorted(set(_AAC_FILL_BYTES)))
)

MAX_PLAYLISTS = 5
# Hard ceilings for one playlist (fetch_playlist_channels). Needed
# so that the server that gave a huge response (by accident, due to a misconfiguration
# or intentionally - DNS substitution, captive-portal, redirect to "garbage"
# endpoint), has not exhausted the memory of the scanner process. Values ​​are not tuned
# via scanner_config.json: this is failsafe, not custom
# parameters - 10 MB / 10000 channels / 2 KB per line with a huge margin
# cover any real M3U (typical playlist - 100 KB - 2 MB,
# several thousand channels, URL length up to ~1 KB).
MAX_PLAYLIST_BYTES = 10_000_000
MAX_PLAYLIST_CHANNELS = 10_000
MAX_PLAYLIST_LINE_LENGTH = 2048
MAX_PSI_BUFFER_BYTES = 65_536

_SINGLE_INSTANCE_MUTEX_NAME = "Local\\IPTV_Channel_Scanner_SingleInstance"
_single_instance_mutex_handle: Any = None

def _try_acquire_single_instance() -> bool:
    """True - this process is the first; False—the scanner is already running."""
    global _single_instance_mutex_handle

    if platform.system() == "Windows":
        ERROR_ALREADY_EXISTS = 183
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [
            ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR
        ]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateMutexW(None, False, _SINGLE_INSTANCE_MUTEX_NAME)
        if not handle:
            logger.warning(
                "CreateMutexW failed (WinError %s) — single-instance check skipped",
                ctypes.get_last_error(),
            )
            return True
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return False
        _single_instance_mutex_handle = int(handle)
        return True

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 47831))
        _single_instance_mutex_handle = sock
        return True
    except OSError:
        return False


def _enable_faulthandler() -> None:
    """Enables faulthandler with an entry in %LOCALAPPDATA%\\IPTV_Scanner\\logs\\scanner_fatal.log.

    faulthandler intercepts native crashes (SIGSEGV/SIGABRT/SIGFPE/
    SIGBUS/SIGILL) and Python alarms and writes traceback ALL
    streams to the specified file. This is the only way to see the trail if
    process dies from access violation in WinAPI ctypes call - normal
    logging/sys.excepthook does not catch such a crash, but pythonw.exe without it
    leaves silently.

    The file contains exactly one crash - the last one:

      * each launch starts with truncating scanner_fatal.log and writing
        marker line "===== run started <timestamp> pid=<pid> =====",
        therefore, the launch history is not saved in the file;
      * if the last launch failed, faulthandler added after the marker
        traceback (there is more than one meaningful line in the file) - this
        information is saved in scanner_fatal_last.log (file
        is overwritten: only the last fall is stored), after which
        scanner_fatal.log starts over with a new marker;
      * if the last launch completed normally, the file contains only
        marker line - there is nothing to save, the file is simply truncated under
        new marker.

    The file is opened ONCE for the entire process and is not closed: faulthandler
    writes to an already open fd directly from the signal handler, so
    You cannot close it (let alone reopen it) during operation."""
    fatal_log = _logs_dir() / "scanner_fatal.log"
    fatal_log_last = _logs_dir() / "scanner_fatal_last.log"

    # We read the contents of the previous run BEFORE truncation.
    existing = ""
    if fatal_log.exists():
        try:
            existing = fatal_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.debug(
                "Failed to read scanner_fatal.log before rotation",
                exc_info=True,
            )

    # “Marker only” = last launch completed normally. Any other
    # non-empty string = there was a traceback (or the file remained from the version without
    # marker - we save it and this: the content must survive rotation,
    # even if we don't understand its format).
    crash_detected = False
    for line in existing.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if (stripped.startswith("===== run started ")
                and stripped.endswith(" =====")):
            continue
        crash_detected = True
        break

    if crash_detected:
        try:
            fatal_log_last.write_text(existing, encoding="utf-8")
            logger.info(
                "Previous crash traceback preserved → %s", fatal_log_last
            )
        except OSError:
            logger.warning(
                "Failed to preserve previous crash traceback → %s",
                fatal_log_last, exc_info=True,
            )

    try:
        # "w" - truncation (see docstring): the only one allowed in the file
        # history is the last crash, and it has already been postponed if necessary
        # in scanner_fatal_last.log above. Buffering line by line - when
        # better faulthandler calls write() from the signal context, and
        # without line-buffering, the traceback tail may remain in the buffer.
        # encoding is explicit - so that even non-ASCII traceback is recorded correctly.
        fh = open(fatal_log, "w", encoding="utf-8", buffering=1)
    except OSError:
        logger.warning("Failed to open scanner_fatal.log — faulthandler disabled")
        return

    try:
        fh.write(
            f"===== run started {time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"pid={os.getpid()} =====\n"
        )
        fh.flush()
    except OSError:
        logger.warning(
            "Failed to write run marker to scanner_fatal.log", exc_info=True
        )

    try:
        faulthandler.enable(file=fh, all_threads=True)
    except (RuntimeError, OSError):
        logger.warning("faulthandler.enable() failed", exc_info=True)
        return
    logger.info("faulthandler enabled → %s", fh.name)


def _install_exception_hooks() -> None:
    """Sets sys.excepthook and threading.excepthook for logging
    unhandled exceptions.

    Why: pythonw.exe has no visible stderr, and any exception not
    caught Tk (main thread between callbacks, background threads, code
    initialization/completion), goes nowhere. With hooks such exceptions
    will end up in scanner.log with a full traceback.

    The original sys.excepthook is saved and called after logging:
    the semantics of “unhandled exception → process crashes” does not change,
    It’s just that now there’s a record of it."""
    _default_excepthook = sys.excepthook

    def _excepthook(exc_type, exc_value, exc_tb):
        logger.critical(
            "Unhandled exception in the main thread",
            exc_info=(exc_type, exc_value, exc_tb),
        )
        try:
            _default_excepthook(exc_type, exc_value, exc_tb)
        except Exception:
            # A hook should not replace the original exception with its own crash.
            logger.debug("Default excepthook raised", exc_info=True)

    sys.excepthook = _excepthook

    def _thread_excepthook(args: "threading.ExceptHookArgs") -> None:
        thread_name = args.thread.name if args.thread is not None else "<unknown>"
        logger.critical(
            "Unhandled exception in thread %r",
            thread_name,
            exc_info=(
                (args.exc_type, args.exc_value, args.exc_traceback)
                if args.exc_value is not None else None
            ),
        )

    threading.excepthook = _thread_excepthook

    
def _name_has_prefix(name: str, prefixes: tuple[str, ...]) -> bool:
    text = (name or "").strip().lower()
    return any(text.startswith(p) for p in prefixes)
    

# Secret query parameters: values ​​are replaced with *** before logging.
# Keys are compared in lowercase. The list is a compromise between
# “cover typical names” (OAuth/OpenID in different notations, jdbc-style,
# AWS-style api_key) and “do not overwhelm diagnostics with triggers
# harmless names."
_REDACT_QUERY_KEYS = frozenset({
    "password", "passwd", "pass", "pwd",
    "token", "access_token", "refresh_token", "id_token", "auth_token",
    "api_key", "apikey", "key", "auth_key",
    "secret", "client_secret",
    "auth", "authorization",
    "credentials", "credential",
    "username", "user", "login",
    "session", "sessionid", "session_id",
    "sig", "signature",
    "jwt", "bearer",
})


def _redact_url(url: str) -> str:
    """Removes credentials and secret query parameter values from the URL -
    to securely record the URL in a persistent log (scanner.log).

    The following are saved: scheme, host, port, path, fragment and “safe”
    query parameters. This is needed for diagnostics - the URL in the log should
    be clear to which host/path the request was going.

    Removed:
      * userinfo (user:password@host) - replaced with "***@host":
        the very fact of having userinfo for diagnostics is useful,
        credits - no;
      * values of query parameters with “secret” names (see.
        _REDACT_QUERY_KEYS): token=abc → token=***.

    Never throws exceptions: if the URL is not parsed, it returns
    placeholder so that a raw URL is guaranteed not to be included in the log."""
    if not isinstance(url, str):
        return "<unredactable url>"
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return "<unredactable url>"
    if not parts.scheme:
        # Not a URL in the full sense (relative path, garbage). Doesn't matter
        # We don’t risk writing it as it is - anything can happen there.
        return "<unredactable url>"

    # netloc without userinfo: host[:port]. hostname is always lowercase
    # and without framing brackets for IPv6; with an empty host (for example,
    # "http://user:pass@/path" - unlikely, but possible) remains
    # is an empty string, and "***@host" is not collected.
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    if parts.username is not None or parts.password is not None:
        netloc = f"***@{netloc}"

    # query: we keep order and “safe” pairs as they are.
    redacted_query = parts.query
    if parts.query:
        redacted_pairs: List[str] = []
        for raw in parts.query.split("&"):
            if not raw:
                continue
            key, sep, _value = raw.partition("=")
            if sep and key.lower() in _REDACT_QUERY_KEYS:
                redacted_pairs.append(f"{key}=***")
            else:
                redacted_pairs.append(raw)
        redacted_query = "&".join(redacted_pairs)

    return urlunsplit((parts.scheme, netloc, parts.path,
                       redacted_query, parts.fragment))


# The tvg-name="..." (or '...') attribute on the #EXTINF line is a fallback name source
# channel when there is no name after the comma.
_EXTINF_TVG_NAME_RE = re.compile(
    r"""tvg-name\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# RuntimeLimits - all tuning runtime constants in one place
# (limits of UI settings, join timeouts, hanging-recovery, heartbeat).
# TS detection thresholds - in Thresholds (config section "thresholds").
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RuntimeLimits:
    scan_timeout_min_sec: int = 3
    scan_timeout_max_sec: int = 15
    default_scan_timeout: int = 4
    parallel_min: int = 1
    parallel_max: int = 8
    default_parallel: int = 4
    # min_bitrate_setting_kbps — lower UI limit; default_min_bitrate_kbps - for new configs.
    min_bitrate_setting_kbps: int = 100
    default_min_bitrate_kbps: int = 200
    heartbeat_interval_ms: int = 2000
    hibernation_gap_threshold_sec: float = 10.0
    post_wake_guard_sec: float = 8.0
    fail_cooldown_cleanup_interval_sec: float = 300.0
    hanging_cleanup_interval_sec: float = 600.0
    scan_thread_join_margin_sec: int = 10
    scan_thread_join_min_timeout: int = 20
    hanging_slot_wait_timeout_sec: float = 5.0
    # Soft recovery: how many times in a row to reset the hanging counter
    # without stopping the scan completely before escalating to fatal.
    hanging_soft_reset_max: int = 3
    hanging_soft_reset_cooldown_sec: float = 30.0
    # --- Network Health Monitor ---
    # Physical connectivity polling period (GetAdaptersAddresses). Examination
    # relatively expensive (complete bypass of adapters), so the period is 1 s. Works
    # continuously - both during scanning and idle time.
    network_poll_interval_sec: float = 1.0
    # VPN session polling period (_VpnSessionWatch/_poll_vpn_health_tick), when
    # _vpn_relied_upon. Checking one ifIndex(GetIfEntry2/GetAdaptersAddresses)
    # takes microseconds, so _network_health_loop always spins with that
    # pace, and performs expensive physical checks no more often
    # network_poll_interval_sec.
    # 250 ms, not 1 s: RAS-handshake (L2TP/SSTP) lasts a second or more, and
    # a short step guarantees at least one tick caught instead of a chance to slip through
    # him entirely.
    vpn_watch_poll_interval_sec: float = 0.25
    # Fixed pause before retrying connect_and_route after
    # failures (don’t pester the VPN server with repeated failed authorizations
    # once per second). Terminates early if it disappears during this time
    # Internet or a new connectivity event will occur - see _net_epoch.
    vpn_reconnect_retry_sec: float = 18.0
    # "N failures in M ​​minutes" - threshold for a one-time warning
    # user that the VPN cannot be reconnected (the attempts themselves
    # reconnections do not stop).
    vpn_reconnect_fail_window_sec: float = 300.0
    vpn_reconnect_fail_threshold: int = 3
    # A short settle window after the VPN breaks in front of your own dial. Long pause
    # not needed: connect_and_route itself first checks get_vpn_connected and when
    # An already up VPN only repairs routes without calling rasdial. 2.5 s is enough,
    # to filter instant flap Disconnect→Connect and do not run
    # an extra dial on top of the user's manual reconnect.
    vpn_reconnect_grace_sec: float = 4.0
    # How many seconds is a successful precheck considered relevant for a restart?
    # without a new get_vpn_connected + _local_probe_hosts pass.
    # The cache is additionally bound to _net_epoch: any connectivity event
    # (waking up, network loss, invalidate VPN, changing playlist or VPN profile)
    # invalidates it regardless of TTL. TTL - only insurance in case
    # the episode deteriorated "quietly", without an obvious event.
    precheck_cache_ttl_sec: float = 300.0
    
    # --- Path-quality soft recovery (degradation to udpxy without “no network”) ---
    # Window of the last successful readings of the stream; share with cc_err >= threshold
    # launches soft recovery (flush DNS/ARP + force VPN routes + resume).
    path_quality_window: int = 24
    path_quality_cc_threshold: int = 1          # cc_err "elevated"
    path_quality_elevated_ratio: float = 0.4   # share of bad ones in the window
    path_quality_min_samples: int = 12          # not before it accumulates
    path_quality_min_ts_packets: int = 100      # ignore empty/open
    # Minimum pause between launches of soft path recovery (from the beginning
    # previous). Inside - _network_recovery_aggressive: Wi-Fi soft reset or
    # restarting the adapter, that is, breaking ALL connections of the machine. Repeat it
    # more than once every 10 minutes is not possible: in case of persistent degradation that reset does not treat,
    # The network would "blink" constantly.
    path_quality_recovery_cooldown_sec: float = 600.0
    path_quality_hygiene_pause_sec: float = 2.5
    # ---Controlled L2-reset (Wi-Fi soft reset / adapter restart) ---
    # How long to wait for physical connectivity to return AFTER reset before
    # admit that reset did not help and give the situation the usual way
    # “network lost” (_on_internet_lost).
    l2_reset_link_wait_sec: float = 20.0
    # How many seconds must connectivity be continuously “up” to count?
    # its restored (symmetrically 2.5-s debounce monitor).
    l2_reset_link_stable_sec: float = 2.5
    # Reserve on top (command timeout + waiting for link) for watchdog deadline
    # intentional_network_reset flag: if the worker for some reason did not reach
    # Finally, the flag will go out on its own and will not block the monitor forever.
    l2_reset_flag_margin_sec: float = 10.0

    # --- Soft recovery via CONNECT_FAILED (dead path to udpxy, VPN still "up") ---
    # Consecutive all-CONNECT_FAILED batches → same soft-recovery pipeline as
    # path_quality_* above. Threshold >2 so a brief Wi-Fi blip (~2 batches) does
    # not fire it; 5 ≈ five groups at typical parallel >= 2.
    connect_fail_batch_trigger: int = 5
    
    debounce_sec: float = 2.5
    max_alerts: int = 200
    connect_fail_cooldown_sec: float = 45.0
    
    batch_retry_settle_min_sec: float = 0.5
    batch_fast_fail_max_ratio: float = 0.75
    
    # Pause after retrying emergency batch (the whole group in parallel
    # scanned channels fell on CONNECT_FAILED and was rerun,
    # see _select_batch_retry_candidates). Gives Wi-Fi queues and
    # NAT/conntrack to rest before the next wave of connections.
    # The case is rare, so 300 ms has virtually no effect on the overall
    # scan time.
    retry_pause_sec: float = 0.3


RUNTIME = RuntimeLimits()

# SetThreadExecutionState Flags (Windows) - See ScannerGUI.toggle_prevent_sleep.
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


@dataclass(frozen=True)
class _BeepBatch:
    """One sound signal: a sequence of (freq, dur_ms) pairs plus a gap between them.

    A dedicated type instead of a bare tuple — queue.Queue[_BeepBatch] reads as
    "a queue of signals", not "a queue of two-element tuples with a nested
    tuple of tuples".
    """
    beeps: Tuple[Tuple[int, int], ...]
    gap: float


class _SoundPlayer:
    """Single background thread for all audio signals.

    winsound.Beep() blocks the thread for the duration of the tone, so a separate thread on
    Each signal in case of massive errors (dozens of new alerts in a row) would accumulate
    waiting threads. Signals go to a queue of limited length (_MAX_PENDING):
    while the current one is playing, one or two can wait, the rest collapse - series
    identical “alarms” are heard as one."""

    _MAX_PENDING = 2

    def __init__(self) -> None:
        self._q: "queue.Queue[Optional[_BeepBatch]]" = queue.Queue(maxsize=self._MAX_PENDING)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stopped = False

    def play(self, beeps: List[Tuple[int, int]], gap: float = 0.0) -> None:
        if self._stopped:
            return
        self._ensure_thread()
        try:
            self._q.put_nowait(_BeepBatch(tuple(beeps), gap))
        except queue.Full:
            logger.debug("Sound queue is full — beep dropped")

    def shutdown(self) -> None:
        """Stops playback: the queue is cleared, the stream ends."""
        self._stopped = True
        try:
            while True:
                self._q.get_nowait()
        except queue.Empty:
            pass
        try:
            self._q.put_nowait(None)  # sentinel: wake up thread
        except queue.Full:
            pass

    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="sound-player"
            )
            self._thread.start()

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None or self._stopped:
                return
            try:
                for freq, dur in item.beeps:
                    if self._stopped:
                        return
                    if winsound is not None:
                        winsound.Beep(freq, dur)
                    else:
                        time.sleep(dur / 1000.0)
                    if item.gap:
                        time.sleep(item.gap)
            except Exception:
                logger.debug("Failed to play a sound signal", exc_info=True)


_SOUND_PLAYER = _SoundPlayer()


@dataclass(frozen=True)
class GenerationToken:
    """Opaque UI/scan generation token instead of raw int.

    Comparison by value; bump() returns a new token. Used for
    scan_generation / load_generation to cut out stale callbacks."""
    value: int = 0

    def bump(self) -> "GenerationToken":
        return GenerationToken(self.value + 1)


# ---------------------------------------------------------------------------
# Detection thresholds (tuned via scanner_config.json → "thresholds" section)
# ---------------------------------------------------------------------------
@dataclass
class Thresholds:
    min_video_packets_for_scramble_check: int = 1200
    min_pes_scrambled_count: int = 30
    min_video_packets_for_pes_scramble_check: int = 300
    min_scrambled_ratio_for_no_card: float = 0.95
    min_scrambled_ratio_for_partial: float = 0.15

    min_video_packets_for_empty_payload_check: int = 40
    min_video_payload_bytes: int = 800
    min_video_packets_for_picture_check: int = 80
    min_picture_codes: int = 5
    min_slice_codes: int = 15
    min_modern_vcl_nals: int = 2

    max_video_packets_for_stuffing_check: int = 30
    min_bitrate_for_stuffing_check_kbps: int = 1500
    max_payload_bytes_for_stuffing_check: int = 300

    min_scan_duration_sec: float = 0.8
    min_total_bytes: int = 10_000
    scrambled_all_packets_threshold: int = 2500
    min_ts_packets_for_full_scramble_check: int = 3500
    error_bitrate_kbps: int = 700
    max_allowed_gap_sec: float = 1.1
    # The share of TEI packets (transport_error_indicator=1) among all non-NULL TS packets,
    # above which the channel is considered erroneous. A healthy source has TEI = 0.
    max_tei_ratio: float = 0.01

    # --- tolerance of a single self-healing gap ---
    # A single TCP retransmit with minimal RTO sometimes gives a pause between
    # HTTP chunks are slightly larger than max_allowed_gap_sec, while TCP delivers everything without
    # loss of TS packets (cc_err near zero). This is a one-time network blip, not
    # degradation of the channel, and by itself it should not transfer the channel to ERRORS.
    # Several pauses in excess of max_allowed_gap_sec in one scan are already a sign of real
    # problems (usually along with an increase in cc_err).
    gap_violations_error_threshold: int = 2  # From how many times the gap is exceeded in one scan, we consider this a real error (not a one-time one).
    gap_single_violation_max_cc_err: int = 2  # If exactly one gap is exceeded, the cc_err is acceptable, and this is still not an error.
    
    max_continuity_errors: int = 4  # the floor of “noise”, not the ceiling of disaster, see _is_cc_bad
    max_continuity_errors_per_sec: float = 1.0  # add. tolerance above the floor, proportional to scan duration
    max_continuity_error_ratio: float = 0.01  # insurance for short/poor flow
    min_video_packets_for_cc_ratio_check: int = 200
    min_ts_packets_for_radio_check: int = 300

    # New thresholds for NOT_TS detection based on the proportion of “garbage”
    min_total_bytes_for_garbage_check: int = 10_000
    max_garbage_ratio: float = 0.40

    watchdog_multiplier: float = 1.5
    
    # --- classification NO_CARD / MODULE_HUNG ---
    min_audio_packets_for_clear_check: int = 40
    max_scrambled_audio_ratio_for_clear: float = 0.15

    # --- payload remained encrypted at TSC=0 (frozen CI reset flags) ---
    # If payload_unit_start is enough for video PID, and PES headers
    # (00 00 01 Ex) almost none, payload is indistinguishable from the cipher, although
    # transport_scrambling_control is already 0. For a broken encoder, the muxer still writes
    # PES, so this case is not confused with "the picture breaks".
    min_video_pus_for_pes_check: int = 8
    max_pes_header_ratio_for_encrypted_payload: float = 0.05
    min_pes_headers_for_garbled: int = 2

    # --- stream clogged with filler (there is a bitrate, but no picture or sound) ---
    # Video: filler-NAL share in ES and “useful” (without filler) video bitrate.
    # Both conditions together: an honest CBR channel has filler, but it is useful
    # hundreds of kbit/s and more data.
    min_video_filler_ratio: float = 0.80
    min_useful_video_kbps: float = 150.0
    # MPEG-2: an “empty” picture is expensive and increases with resolution (no
    # intra-frame prediction, as in H.264: black SD ≈ 120–170 kbit/s,
    # black HD ≈ 700 kbps), so an absolute threshold is not suitable. We normalize
    # useful bitrate per frame area (bit/pixel/s): black ≈ 0.3–0.4,
    # simple live picture ≈ 2 and higher. If resolution fails
    # read from sequence header, min_useful_video_kbps is used.
    min_useful_mpeg2_bits_per_pixel_sec: float = 0.8
    # Audio (AAC): the share of fill bytes in the ES of the track and the “useful” bitrate of the track.
    # Digital silence in AAC-LC gives ~5–8 kbit/s (ADTS header + empty CPE).
    min_audio_fill_ratio: float = 0.80
    min_useful_audio_kbps: float = 16.0
    min_audio_es_bytes_for_fill_check: int = 4000


def _validate_thresholds(data: Any) -> Thresholds:
    """Load threshold values safely, falling back per-field to defaults."""
    defaults = Thresholds()
    if not isinstance(data, dict):
        return defaults

    int_fields = {
        name for name, value in vars(defaults).items()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    ratio_fields = {
        "max_continuity_error_ratio",
        "max_garbage_ratio",
        "max_scrambled_audio_ratio_for_clear",
        "max_pes_header_ratio_for_encrypted_payload",
        "min_scrambled_ratio_for_no_card",
        "min_scrambled_ratio_for_partial",
        "min_video_filler_ratio",
        "min_audio_fill_ratio",
        "max_tei_ratio",
    }
    positive_float_fields = {"min_scan_duration_sec"}
    at_least_one_float_fields = {"watchdog_multiplier"}
    result: Dict[str, Union[int, float]] = {}

    for name, default in vars(defaults).items():
        raw = data.get(name, default)
        value: Union[int, float]
        try:
            if name in int_fields:
                if isinstance(raw, bool):
                    raise ValueError
                value = int(raw)
            else:
                value = float(raw)
                if not math.isfinite(value):
                    raise ValueError
        except (TypeError, ValueError, OverflowError):
            logger.warning(
                "Invalid threshold %s=%r; falling back to default %r",
                name, raw, default
            )
            value = default

        valid = value >= 0
        if name in positive_float_fields:
            valid = value > 0
        if name in at_least_one_float_fields:
            # watchdog_multiplier - multiplier on top of scan_timeout (see.
            # comments in thread_join_timeout and _scan_channel_stream).
            # A value < 1.0 would shift deadline/hard_timeout/read_timeout
            # before scan_timeout, and the channel would be terminated by watchdog earlier
            # the scan budget itself. The semantics of the field requires exactly >= 1.0.
            valid = value >= 1.0
        if name in ratio_fields:
            valid = 0 <= value <= 1

        if not valid:
            logger.warning(
                "Threshold %s=%r out of valid range; falling back to default %r",
                name, value, default
            )
            value = default
        result[name] = value

    # --- Semantic (cross-field) validation -----------------------------
    # Individual fields have already passed type and range checks. Here they are cut off
    # combinations that are valid individually, but together they obviously give
    # senseless behavior. All checks below follow what is already accepted in
    # this function style: reset both values ​​to defaults + warning, not
    # tacit acceptance or exclusion.

    # _is_partial_scramble() defines the range [partial, no_card).
    # If left border >= right, the range is empty, and the partial branch
    # MODULE_HUNG detection is silently turned off (channel with partially
    # scrambled video will receive OK or another status instead
    # MODULE_HUNG, without a single message in the log that the diagnostics
    # disabled by config).
    if result["min_scrambled_ratio_for_partial"] > result["min_scrambled_ratio_for_no_card"]:
        logger.warning(
            "min_scrambled_ratio_for_partial (%r) is greater than "
            "min_scrambled_ratio_for_no_card (%r) — the partial-scramble band "
            "would be empty; both values were reset to their defaults",
            result["min_scrambled_ratio_for_partial"],
            result["min_scrambled_ratio_for_no_card"],
        )
        result["min_scrambled_ratio_for_partial"] = defaults.min_scrambled_ratio_for_partial
        result["min_scrambled_ratio_for_no_card"] = defaults.min_scrambled_ratio_for_no_card

    if result["min_pes_scrambled_count"] > result["min_video_packets_for_pes_scramble_check"]:
        logger.warning(
            "min_pes_scrambled_count is greater than min_video_packets_for_pes_scramble_check; "
            "both values were reset to their defaults"
        )
        result["min_pes_scrambled_count"] = defaults.min_pes_scrambled_count
        result["min_video_packets_for_pes_scramble_check"] = defaults.min_video_packets_for_pes_scramble_check

    if result["error_bitrate_kbps"] < RUNTIME.min_bitrate_setting_kbps:
        logger.warning(
            "error_bitrate_kbps=%r is below the minimum user-settable bitrate %r; "
            "falling back to default %r",
            result["error_bitrate_kbps"], RUNTIME.min_bitrate_setting_kbps, defaults.error_bitrate_kbps
        )
        result["error_bitrate_kbps"] = defaults.error_bitrate_kbps

    return Thresholds(**cast(Dict[str, Any], result))


# ---------------------------------------------------------------------------
# Custom strings (configured via scanner_config.json → section
# "ui_strings").
# This is not a switchable localization (there is no language choice), but text customization
# interface and statuses; The section is named explicitly so as not to create i18n expectations.
# Service messages (logs, VPN technical errors) are not included here and are always
# are displayed in English.
# ---------------------------------------------------------------------------
DEFAULT_UI_STRINGS: Dict[str, str] = {
    "status_ok": "OK",
    "status_ok_scrambled": "OK*",
    "status_ok_unsupported": "OK**",
    "status_radio": "Radio",
    "status_no_card": "No access card",
    "status_module_hung": "CI module hung",
    "status_no_picture": "No picture",
    "status_no_audio": "No audio",
    "status_dead": "Dead",
    "status_errors": "Errors",
    "status_connect_failed": "Connection failed",
    "detail_too_many_hanging": "Too many hung connections; please try again later",
    "msg_vpn_route_failed_title": "VPN: failed to restore access",
    "msg_vpn_route_failed": (
    "Failed to access proxy hosts after VPN setup: {hosts}\n\n"
    "Possible causes: no internet connection, VPN server unavailable, "
    "routing failure, or the hosts themselves are temporarily unavailable.\n\n"
    "Details: {details}"
    ),
    "msg_hosts_unreachable_no_vpn_title": "Hosts unreachable",
    "msg_hosts_unreachable_no_vpn": (
    "Failed to connect to proxy hosts: {hosts}\n\n"
    "Possible causes: no internet connection, hosts unavailable, "
    "or these addresses are accessible only via VPN (VPN fallback is not "
    "currently enabled). Check your network and, if necessary, enable VPN "
    "fallback in the settings, then restart the scan."
    ),
    "msg_hanging_limit_title": "Scan stopped",
    "msg_hanging_limit": "Scan stopped: too many hanging network connections accumulated. Check the network/DNS and restart the scan.",
    "detail_hanging_abandoned": "Hanging network streams: {count}.",
    "detail_hanging_soft_resets": "Repeated resets of hanging streams ({resets}) did not help (hanging: {count}).",
    "detail_cooldown": "Cooldown {remaining:.0f}s after previous failure",
    "status_not_ts": "Not TS / unsupported",
    "status_internal_error": "Internal error",
    "status_waiting": "Waiting...",

    "app_title": "IPTV Channel Scanner",
    "settings_title": "Settings",
    "frame_channels": "Channels",
    "frame_alerts": "Active alerts",
    "frame_vlc": "VLC",
    "hint_vlc_double_click": "Double-click a channel row to open the channel in the video player",
    "frame_config_location": "scanner_config.json",
    "label_config_location": "Location:",
    "btn_open_config_location": "Open",
    "msg_open_config_location_error": "Failed to open folder:\n{path}\n\n{error}",
    "frame_color_saturation": "Row color saturation",
    "btn_saturation_reset": "Reset (100%)",
    "frame_scan_params": "Scan parameters",
    "frame_playlists": "Playlists (name and URL both filled or both empty). Auto — preload on startup",
    "frame_vpn": "VPN when proxy is unavailable",
    "chk_vpn_enabled": "Use VPN if necessary",
    "label_vpn_connection": "Connection:", "vpn_status_loading": "Loading list...",
    "vpn_status_none_found": "No VPN connections found",
    "vpn_status_applying": "Applying...",
    "vpn_status_uac_declined": "Administrator privileges denied — VPN function disabled. To re-enable, check 'Use VPN' in the settings and confirm the privilege request.",
    "vpn_status_helper_timeout": "Failed to start the VPN helper process (administrator privilege request was accepted, but the process failed to connect). This is often caused by a hung process from a previous run: check Task Manager for python.exe/pythonw.exe processes and terminate any extra ones, or restart Windows. See vpn_helper.log next to the program for details. Will retry on the next program launch or when opening settings.",
    "vpn_status_helper_not_found": "VPN helper file (vpn.py/vpn.exe) not found next to the program — VPN function unavailable until the file is placed in the same folder.",
    "vpn_status_helper_integrity": "VPN helper file (vpn.exe/vpn.py) failed integrity check — it may have been tampered with. VPN function disabled. Please reinstall the program from a trusted source.",
    "vpn_status_ready": "Ready",
    "msg_vpn_no_connection_selected": "Select a VPN connection from the list or uncheck 'Use VPN when necessary'.",
    "btn_reset_advanced": "Reset advanced settings",
    "msg_reset_advanced_title": "Reset advanced settings",
    "msg_reset_advanced_confirm": (
    "Reset advanced parameters to default values ​​"
    "(detection thresholds, interface text, row colors, column widths, "
    "channel prefixes)?\n\n"
    "Parameters from this settings window (VLC, playlists, timeout, "
    "concurrency, bitrate, saturation, VPN) will NOT be changed."
    ),
    "msg_reset_advanced_done": "Advanced settings have been reset to default values.",

    "btn_settings": "Settings",
    "btn_start": "▶ Start",
    "btn_stop": "⏹ Stop",
    "btn_stopping": "⏳ Stopping…",
    "btn_close": "Close",
    "btn_precheck": "⏳ Network check…",
    "btn_browse": "Browse...",
    "chk_sound": "Alert sound",
    "chk_prevent_sleep": "Prevent hibernation",
    "label_playlist_none": "No playlist loaded",
    "label_waiting_uac": "Waiting for administrator privilege confirmation (VPN)...",
    "label_loading": "Loading '{name}'...",
    "label_vpn_status": "VPN: {state}",
    "vpn_state_connecting": "Connecting",
    "vpn_state_connected": "Connected",
    "vpn_state_system": "System",
    "vpn_state_disconnecting": "Disconnecting",
    "vpn_state_disconnected": "Disconnected",
    "label_no_internet": "Network: No internet",
    "msg_vpn_reconnect_failed_title": "VPN: Unable to reconnect",
    "msg_vpn_reconnect_failed": "After the VPN connection dropped, it could not be restored after several consecutive attempts ({attempts}). The scanner will continue trying automatically in the background; I will not bother you with this message again.",
    "label_current": "Current: {name} ({count} channels)",

    "col_status": "Status",
    "col_name": "Channel Name",
    "col_result": "Last Result",

    "label_timeout": "Analysis time (sec):",
    "label_parallel": "Parallel:",
    "label_min_bitrate": "Min. bitrate (kbps):",
    "label_pl_auto": "Auto",
    "label_pl_name": "Playlist name",
    "label_pl_url": "Playlist URL",

    "msg_vlc_not_found": "VLC not found:\n{path}",
    "msg_vlc_error": "VLC error", "msg_playlist_incomplete": "Playlist {n}: both name and URL must be filled in or both left blank.",
    "msg_stop_timeout": "The previous scan stream did not finish in time. The channel list has not been updated.",
    "msg_stop_title": "Stopping scan",
    "msg_load_playlist_first": "Load the playlist first",
    "msg_attention": "Attention",
    "msg_scrambled_channel": (
    "The channel is broadcast in scrambled format; "
    "video display is not possible"
    ),
    "msg_playlist_not_configured": "Playlist not configured (missing name or URL)",
    "msg_playlist_load_error": "Failed to load playlist",
    "msg_error": "Error",
    "msg_error_title": "Error",

    "menu_copy_url": "Copy URL",
    "menu_copy_name": "Copy name",
    "menu_copy_result": "Copy result",
    "menu_copy_all": "Copy all",
    "alert_line": "[{status}] {name} — {details} (since {since})",

    "detail_no_data": "No data",
    "detail_garbage": "garbage {garbage}/{total} ({ratio:.0%})",
    "detail_video_no_data": "video PID with no data ({bytes} bytes / {pkts} pkts)",
    "detail_mpeg2_codes": "pic:{pic} slice:{slice} seq:{seq} gop:{gop}, PES:{pes}/{pus} PUS",
    "detail_modern_nals": "vcl:{vcl} param:{param}, PES:{pes}/{pus} PUS",
    "detail_few_video": "very few video packets ({pkts} pkts, {bytes} bytes)",
    "detail_no_card_video": "{codec}Video: {scr}/{total} PES:{pes}",
    "detail_no_card_all": "No card (all packets: {scr}/{total})",
    "detail_pmt_missing": (
    "PMT not received for {dur:.1f} s (TS packets: {pkts}, PAT: {pat}, "
    "PMT PID found: {pmt}, PMT packets: {pmt_pkts}, "
    "sections: {pmt_valid}/{pmt_sections})"
    ),
    "detail_bitrate": "{br:.1f} kbit/s",
    "detail_scrambled_no_pmt_or_video": (
    "Known scrambled channel: no PMT/video PID "
    "(PMT: {pmt}, video PID: {video})"
    ),
    "detail_errors": "{codec}{br:.1f} kbit/s (gap:{gap:.2f}, cc_err:{cc})",
    "detail_ok_cc": " cc_err:{cc}",
    # TEI (transport_error_indicator) - packets marked by source/demodulator
    # as damaged; appended to details in the same way as cc_err.
    "detail_tei": " TEI:{tei}",
    # OK**: the video codec is not understood by the scanner (see UNSUPPORTED_VIDEO_STREAM_TYPES).
    "detail_unsupported_video": " video not analyzed (stream_type {types})",
    # NO_AUDIO: All audio tracks are scrambled in pure video. 
    "detail_no_audio_scrambled": "audio: PID {pids} scrambled ({scr:.0f}%)", 
    # Distinguishes between two different causes of NO_AUDIO (see _is_no_audio): 
    # * detail_no_audio_not_declared - PMT does not declare any 
    # audio tracks (single video stream channel or multiplexer 
    # deleted audio from PMT); 
    # * detail_no_audio_no_packets - there is audio track(s) in PMT, 
    # but not a single packet was received for them during the entire scan 
    # (the audio part of the encoder is broken / the track does not flood). 
    "detail_no_audio_not_declared": "audio: not declared in PMT", 
    "detail_no_audio_no_packets": "audio: PID {pids} declared, but no packets", 
    "detail_garbled": "Image is broken: {details}", 
    # There is a bitrate, but almost the entire video PID is filler-NAL (the encoder “threshes” 
    # dummy"): there is no real picture (black/empty frame). 
    "detail_video_filler": ( 
    "Filler filled: {ratio:.0f}% ES, data: {useful:.0f}/{total:.0f} kbit/s" 
    ), 
    # The track is declared and the packets are coming, but AAC consists of fill/silence. 
    "detail_no_audio_fill": "audio: PID {pids} - fill/silence only ({fill:.0f}%)",
    "detail_module_hung_encrypted": (
    "CI not decrypting (TSC=0; {picture})"
    ),

    "msg_already_running_title": "Action cancelled",
    "msg_already_running": "The program is already running",

    # Short texts of network errors (requests/urllib3) for the UI. Default
    # in English - if necessary, edited/translated by the same
    # in the same way as the rest of ui_strings.
    "err_connect_timeout": "Connect timed out",
    "err_read_timeout": "Read timed out",
    "err_timeout": "Timeout error",
    "err_max_retries_exceeded": "Max retries exceeded",
    "err_connection_refused": "Connection refused",
    "err_host_not_found": "Host not found",
    "err_connection_error": "Connection error",
    "err_connection_reset": "Connection terminated",
    # TLS layer error: most often - the certificate does not pass verification
    # (self-signed / corporate CA, which is not in the bundle certifi /
    # expired / CN mismatch). Less commonly, incompatible protocol or SSL failure
    # handshake. The right first step for the user in both cases
    # is the same: check the server certificate and, if it is a corporate CA,
    # install truststore (see TLS trust store initialization block at the beginning
    # module) - rather than disabling verify=False.
    "err_ssl_error": "TLS certificate error",
}

def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    """Safely casts value to int and clamps it to [lo, hi]. In case of error - default."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


class Status(str, Enum):
    """Status keys are also ui_strings keys."""
    OK = "status_ok"
    OK_SCRAMBLED = "status_ok_scrambled"
    OK_UNSUPPORTED = "status_ok_unsupported"
    RADIO = "status_radio"
    NO_CARD = "status_no_card"
    MODULE_HUNG = "status_module_hung"
    NO_PICTURE = "status_no_picture"
    NO_AUDIO = "status_no_audio"
    DEAD = "status_dead"
    ERRORS = "status_errors"
    CONNECT_FAILED = "status_connect_failed"
    NOT_TS = "status_not_ts"
    INTERNAL_ERROR = "status_internal_error"


class ConnectFailReason(str, Enum):
    NETWORK = "network"
    HANGING_LIMIT = "hanging_limit"
    TIMEOUT = "timeout"
    NO_DATA = "no_data"
    COOLDOWN = "cooldown"
    CANCELLED = "cancelled"


class PrecheckMode(str, Enum):
    """Precheck mode before starting the scan (see _precheck_worker)."""
    VPN = "vpn"            # VPN enabled: probe → connect_and_route for unavailable
    DIRECT = "direct"      # VPN is disabled: probe → popup if something is unavailable
    WARMUP = "warmup"      # warming up the cache: probe → fill the cache if everything is available


STATUS_TAGS: Dict[str, str] = {
    Status.NO_CARD: "scrambled",
    Status.MODULE_HUNG: "module_hung",
    Status.NO_PICTURE: "no_picture",
    Status.NO_AUDIO: "no_picture",  # the same color as “No picture”: separate colors for each status are not created
    Status.RADIO: "radio",
    Status.OK: "ok",
    Status.OK_SCRAMBLED: "ok_scrambled",
    Status.OK_UNSUPPORTED: "ok_scrambled",  # same color as "OK*"
    Status.DEAD: "error",
    Status.CONNECT_FAILED: "error",
    Status.NOT_TS: "error",
}
DEFAULT_STATUS_TAG = "warning"
# “Channel is OK” statuses: cooldown/alert is removed, not written to the problem log.
OK_STATUSES = (Status.OK, Status.RADIO, Status.OK_SCRAMBLED, Status.OK_UNSUPPORTED)
# INTERNAL_ERROR, ERRORS → DEFAULT_STATUS_TAG = "warning"

# Treeview tag color scheme and column widths are default values.
# Both are configured via scanner_config.json (sections "tree_colors" and
# "column_widths"), as well as ui_strings/thresholds - see load_config().
DEFAULT_TREE_COLORS: Dict[str, Dict[str, str]] = {
    "ok":          {"background": "#d4edda", "foreground": "#155724"},
    "ok_scrambled":{"background": "#cffafe", "foreground": "#155e75"},
    "warning":     {"background": "#fff3cd", "foreground": "#856404"},
    "error":       {"background": "#f8d7da", "foreground": "#721c24"},
    "scrambled":   {"background": "#f3e8ff", "foreground": "#6b21a8"},
    "radio":       {"background": "#fef9c3", "foreground": "#854d0e"},
    "no_picture":  {"background": "#fce7f3", "foreground": "#9d174d"},
    "module_hung": {"background": "#ffedd5", "foreground": "#9a3412"},
    "scanning":    {"background": "#bae6fd", "foreground": "#1e40af"},
}

# Line saturation slider limits (see IPTVScanner.color_saturation).
# 1.0 - no changes; the range is taken with a margin in both directions: up to almost
# gray (0.0) and noticeably higher than the original saturation (to compensate
# HDR decolorization in Windows 11).
COLOR_SATURATION_MIN = 0.0
COLOR_SATURATION_MAX = 3.0
COLOR_SATURATION_DEFAULT = 1.0


def _scale_hex_color_saturation(hex_color: str, factor: float, pull_toward_mid: bool = False) -> str:
    """Changes the saturation (S in HLS) of a hex color to factor.

    For very light pastel colors, multiplying S alone is not enough: they already have S
    about 1.0, and the color appears whitish due to the high lightness L. Therefore, when
    pull_toward_mid=True and factor > 1.0 L additionally smoothly extends to 0.5
    (proportional to the excess of factor over 1.0). Applies only to background:
    Text lightness is usually medium/low.
    An invalid hex is returned as is, so that one broken color in the config is not
    interfered with the use of the others."""
    text = (hex_color or "").strip()
    if not text.startswith("#") or len(text) != 7:
        return hex_color
    try:
        r = int(text[1:3], 16) / 255.0
        g = int(text[3:5], 16) / 255.0
        b = int(text[5:7], 16) / 255.0
    except ValueError:
        return hex_color
    h, l, s = colorsys.rgb_to_hls(r, g, b)
    s = max(0.0, min(1.0, s * factor))
    if pull_toward_mid and factor > 1.0:
        span = max(COLOR_SATURATION_MAX - 1.0, 1e-9)
        blend = min(1.0, (factor - 1.0) / span)
        l = l - (l - 0.5) * blend * 0.9
    r, g, b = colorsys.hls_to_rgb(h, l, s)
    return "#{:02x}{:02x}{:02x}".format(
        max(0, min(255, round(r * 255))),
        max(0, min(255, round(g * 255))),
        max(0, min(255, round(b * 255))),
    )

# width/minwidth in pixels, stretch — whether to stretch the column when resizing
# windows (see ScannerGUI._on_tree_configure).
DEFAULT_COLUMN_WIDTHS: Dict[str, Dict[str, Any]] = {
    "status":  {"width": 200, "minwidth": 160, "stretch": False},
    "name":    {"width": 220, "minwidth": 120, "stretch": True},
    "bitrate": {"width": 280, "minwidth": 100, "stretch": True},
}


def _validate_tree_colors(data: Any) -> Dict[str, Dict[str, str]]:
    """Safely reads the "tree_colors" section of the config.

    Takes DEFAULT_TREE_COLORS as a basis and for each known tag
    rolls over background/foreground from data if it is non-empty
    lines. Unknown tags (not matching any default tags)
    ignored - only tags from STATUS_TAGS / are actually used in the GUI
    DEFAULT_STATUS_TAG, extra entries are not applied in any way.

    This does NOT check that the string is a valid Tk color (for this you need
    running Tk, and load_config() should work without GUI, see
    conftest.py). Protection against invalid color - on the call side
    tag_configure() in ScannerGUI, where the error is caught point-wise on the tag.
    """
    result: Dict[str, Dict[str, str]] = {tag: dict(colors) for tag, colors in DEFAULT_TREE_COLORS.items()}
    if not isinstance(data, dict):
        return result
    for tag, colors in data.items():
        if tag not in result or not isinstance(colors, dict):
            continue
        for color_attr in ("background", "foreground"):
            value = colors.get(color_attr)
            if isinstance(value, str) and value.strip():
                result[tag][color_attr] = value.strip()
    return result


def _validate_column_widths(data: Any) -> Dict[str, Dict[str, Any]]:
    """Safely reads the "column_widths" section of the config.

    Like _validate_tree_colors, known columns (matching
    DEFAULT_COLUMN_WIDTHS) are validated and clamped separately,
    unknown ones are ignored.
    """
    result: Dict[str, Dict[str, Any]] = {col: dict(vals) for col, vals in DEFAULT_COLUMN_WIDTHS.items()}
    if not isinstance(data, dict):
        return result
    for col, vals in data.items():
        if col not in result or not isinstance(vals, dict):
            continue
        result[col]["width"] = _clamp_int(vals.get("width"), 20, 2000, result[col]["width"])
        result[col]["minwidth"] = _clamp_int(vals.get("minwidth"), 10, 2000, result[col]["minwidth"])
        stretch = vals.get("stretch")
        if isinstance(stretch, bool):
            result[col]["stretch"] = stretch
    return result


def get_default_vlc_path() -> str:
    system = platform.system()
    if system == "Windows":
        return r"C:\Program Files\VideoLAN\VLC\vlc.exe"
    elif system == "Darwin":
        return "/Applications/VLC.app/Contents/MacOS/VLC"
    else:
        return "/usr/bin/vlc"


def get_pid(packet: bytes) -> int:
    return ((packet[1] & 0x1F) << 8) | packet[2]


def get_scrambling(packet: bytes) -> int:
    return (packet[3] & 0xC0) >> 6


def get_continuity_counter(packet: bytes) -> int:
    return packet[3] & 0x0F


def find_ts_sync(buf: bytearray, start: int = 0) -> int:
    """Searches for the position from which three consecutive TS packets begin
    (0x47 with step TS_PACKET_SIZE) - used for primary synchronization
    after connecting to the stream.

    Instead of checking each position in a row (slow in pure Python on
    large buffers with frequent loss of synchronization from broken sources)
    jump directly to the next candidate for byte 0x47 via
    bytearray.find - in fact, we are looking for an extremely rare byte, so
    This is an order of magnitude faster than linear search.

    `start` — from what position in the buffer to start the search (used
    _scan_channel_stream() for searching without physically shifting the buffer, see
    comment there).
    """
    if len(buf) - start < TS_PACKET_SIZE * 3:
        return -1
    limit = len(buf) - TS_PACKET_SIZE * 2
    pos = buf.find(0x47, start, limit)
    while pos != -1:
        if buf[pos + TS_PACKET_SIZE] == 0x47 and buf[pos + TS_PACKET_SIZE * 2] == 0x47:
            return pos
        pos = buf.find(0x47, pos + 1, limit)
    return -1


def find_resync_pos(buf: bytearray, start: int = 1) -> int:
    """Looks for a position to resynchronize within the buffer after
    how sync byte 0x47 was not found where expected (e.g.
    due to lost bytes in the stream). Same optimization as find_ts_sync.

    `start` - see find_ts_sync()."""
    n = len(buf)
    pos = buf.find(0x47, start)
    while pos != -1:
        next_pos = pos + TS_PACKET_SIZE
        third_pos = next_pos + TS_PACKET_SIZE
        if third_pos >= n:
            break
        if buf[next_pos] == 0x47 and buf[third_pos] == 0x47:
            return pos
        pos = buf.find(0x47, pos + 1)
    return -1


def extract_payload(packet: bytes) -> Optional[bytes]:
    if len(packet) != TS_PACKET_SIZE or packet[0] != 0x47:
        return None
    adaptation_control = (packet[3] & 0x30) >> 4
    if adaptation_control == 0:
        return None
    if adaptation_control == 2:
        return None
    if adaptation_control == 1:
        return packet[4:]
    af_len = packet[4]
    header_size = 5 + af_len
    if header_size > TS_PACKET_SIZE:
        return None
    return packet[header_size:]


def _extract_complete_psi_sections(
    buffer: bytearray,
    payload: bytes,
    payload_unit_start: bool
) -> List[bytes]:
    sections: List[bytes] = []
    if payload_unit_start:
        if not payload:
            return sections
        pointer = payload[0]
        if pointer > len(payload) - 1:
            return sections
        if pointer == 0:
            buffer.clear()
        elif buffer:
            buffer.extend(payload[1:1 + pointer])
        payload = payload[1 + pointer:]
    if payload:
        buffer.extend(payload)
    if len(buffer) > MAX_PSI_BUFFER_BYTES:
        del buffer[:-(MAX_PSI_BUFFER_BYTES // 2)]
    while True:
        if len(buffer) < 3:
            break
        section_length = ((buffer[1] & 0x0F) << 8) | buffer[2]
        total_length = 3 + section_length
        if total_length < 4 or total_length > 4096:
            # Obviously broken section (garbage instead of PAT/PMT). del buffer[:1] here
            # would cost O(len(buffer)) for EACH garbage byte - on a stream,
            # which sends garbage instead of sections, it is O(len(buffer)^2) when
            # buffer growing to MAX_PSI_BUFFER_BYTES. One broken section is not
            # must be restored byte-by-byte: simpler and
            # It's orders of magnitude cheaper to throw away the entire buffer and wait for the next one
            # payload_unit_start, which reinitializes it again.
            buffer.clear()
            break
        if len(buffer) < total_length:
            break
        sections.append(bytes(buffer[:total_length]))
        del buffer[:total_length]
    return sections


def _build_mpeg2_crc_table() -> List[int]:
    """Table for CRC-32/MPEG-2 (poly 0x04C11DB7, non-reflected)."""
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
        table.append(crc)
    return table


_MPEG2_CRC_TABLE = _build_mpeg2_crc_table()


def _mpeg2_crc32(data: bytes) -> int:
    """CRC-32/MPEG-2 (table-driven). init=0xFFFFFFFF, xorout=0."""
    crc = 0xFFFFFFFF
    for byte in data:
        idx = ((crc >> 24) ^ byte) & 0xFF
        crc = ((crc << 8) ^ _MPEG2_CRC_TABLE[idx]) & 0xFFFFFFFF
    return crc


def _psi_crc_valid(section: bytes) -> bool:
    if len(section) < 4:
        return False
    return _mpeg2_crc32(section) == 0


def parse_pat_section(section: bytes, pmt_pid_to_program: Dict[int, int]) -> bool:
    if len(section) < 12 or section[0] != 0x00:
        return False
    section_length = ((section[1] & 0x0F) << 8) | section[2]
    if len(section) < 3 + section_length:
        return False
    if not _psi_crc_valid(section[:3 + section_length]):
        return False
    pos = 8
    end_pos = 3 + section_length - 4
    while pos + 4 <= end_pos:
        program_num = (section[pos] << 8) | section[pos + 1]
        pmt_pid = ((section[pos + 2] & 0x1F) << 8) | section[pos + 3]
        if program_num != 0:
            pmt_pid_to_program[pmt_pid] = program_num
        pos += 4
    return True


def _has_descriptor_tag(es_info: bytes, tags: Set[int]) -> bool:
    """Is there an elementary stream among the descriptors (ES_info loop in PMT) though
    there would be one with a tag from `tags`. TLV format: tag(1) + length(1) + value(length).
    Protected from incorrect length - does not read beyond es_info and does not
    loops at length=0 (pos increases by at least 2 per iteration)."""
    pos = 0
    n = len(es_info)
    while pos + 2 <= n:
        tag = es_info[pos]
        length = es_info[pos + 1]
        if pos + 2 + length > n:
            break
        if tag in tags:
            return True
        pos += 2 + length
    return False


def parse_pmt_section(
    section: bytes,
    video_pids: Dict[int, int],
    audio_pids: Dict[int, int],
    unclassified_pids: Dict[int, int],
    unsupported_video_pids: Optional[Dict[int, int]] = None,
) -> bool:
    if len(section) < 16 or section[0] != 0x02:
        return False
    section_length = ((section[1] & 0x0F) << 8) | section[2]
    total_length = 3 + section_length
    if len(section) < total_length:
        return False
    if not _psi_crc_valid(section[:total_length]):
        return False
    program_info_len = ((section[10] & 0x0F) << 8) | section[11]
    pos = 12 + program_info_len
    end_pos = total_length - 4
    while pos + 5 <= end_pos:
        stream_type = section[pos]
        elem_pid = ((section[pos + 1] & 0x1F) << 8) | section[pos + 2]
        es_info_len = ((section[pos + 3] & 0x0F) << 8) | section[pos + 4]
        if pos + 5 + es_info_len > end_pos:
            return False
        es_info = section[pos + 5: pos + 5 + es_info_len]
        if stream_type in VIDEO_STREAM_TYPES:
            video_pids[elem_pid] = stream_type
        elif unsupported_video_pids is not None and stream_type in UNSUPPORTED_VIDEO_STREAM_TYPES:
            unsupported_video_pids[elem_pid] = stream_type
        elif stream_type in AUDIO_STREAM_TYPES:
            audio_pids[elem_pid] = stream_type
        elif stream_type == DVB_PRIVATE_STREAM_TYPE and _has_descriptor_tag(es_info, DVB_AUDIO_DESCRIPTOR_TAGS):
            audio_pids[elem_pid] = stream_type
        elif stream_type in KNOWN_NON_AUDIO_STREAM_TYPES:
            pass  # obviously not sound (data/DSM-CC/SCTE-35, etc.)
        elif stream_type == DVB_PRIVATE_STREAM_TYPE and _has_descriptor_tag(es_info, DVB_NON_AUDIO_DESCRIPTOR_TAGS):
            pass  # teletext/subtitles under the same generic stream_type=0x06 - also no sound
        else:
            # No video, no recognized sound, no known-not-sound: unfamiliar
            # stream_type (eg MPEG-H 3D Audio=0x2C, DRA or something
            # proprietary) - we can neither exclude nor confirm that
            # it's sound. See ScanMetrics.unclassified_pids/_is_no_audio.
            unclassified_pids[elem_pid] = stream_type
        pos += 5 + es_info_len
    return True


@dataclass
class ScanMetrics:
    video_pids: Dict[int, int] = field(default_factory=dict)
    audio_pids: Dict[int, int] = field(default_factory=dict)
    unclassified_pids: Dict[int, int] = field(default_factory=dict)
    # Video PIDs in codecs that the scanner does not understand (UNSUPPORTED_VIDEO_STREAM_TYPES).
    unsupported_video_pids: Dict[int, int] = field(default_factory=dict)
    # Packets with transport_error_indicator=1 (except NULL): are not analyzed.
    tei_packets: int = 0
    pmt_pid_to_program: Dict[int, int] = field(default_factory=dict)
    scrambled_video: int = 0
    scrambled_any_pid: int = 0
    total_video_packets: int = 0
    total_audio_packets: int = 0
    scrambled_audio: int = 0
    total_ts_packets: int = 0
    mpeg2_picture_count: int = 0
    mpeg2_slice_count: int = 0
    mpeg2_sequence_count: int = 0
    mpeg2_gop_count: int = 0
    modern_vcl_count: int = 0
    modern_param_count: int = 0
    pes_header_count: int = 0
    video_pus_count: int = 0
    pes_scrambled_count: int = 0
    continuity_errors_by_pid: Counter = field(default_factory=Counter)
    video_payload_bytes: int = 0
    duration: float = 0.0
    bitrate_kbps: float = 0.0
    details_short: str = ""
    max_chunk_gap: float = 0.0
    pat_parsed: bool = False
    pmt_parsed: bool = False
    pmt_pid_packets: int = 0
    pmt_sections_seen: int = 0
    pmt_sections_valid: int = 0
    null_packets: int = 0
    garbage_bytes: int = 0
    # Total video ES bytes (without PES headers) and how many of them are padding.
    # H.264/HEVC: filler-NAL; MPEG-2: series of zero bytes (stuffing) in ES.
    video_es_bytes: int = 0
    video_filler_bytes: int = 0
    # MPEG-2: frame size from sequence header (0 = not yet read).
    mpeg2_width: int = 0
    mpeg2_height: int = 0
    # AAC: ES bytes and fill bytes per audio track (PID -> bytes).
    audio_es_bytes_by_pid: Counter = field(default_factory=Counter)
    audio_fill_bytes_by_pid: Counter = field(default_factory=Counter)
    gap_violations: int = 0  # How many times per scan the pause between HTTP chunks exceeded th.max_allowed_gap_sec (not to be confused with max_chunk_gap - this is a counter, not the worst value).
    

class TSStreamAnalyzer:
    """Parses a stream of TS packets of one channel and accumulates ScanMetrics.

    All parsing state (PAT/PMT buffers, last continuity-counter by PID,
    "tails" of incomplete start-code sequences, etc.) are stored
    explicitly in instance attributes, and not in closure variables - this does
    class under test without real network flow (see test_iptv_scanner.py).

    The public method is process_packet(). After the packet flow
    ended, metrics are read from the .metrics attribute (metrics pmt_parsed
    and null_packets are set during parsing).
    """

    def __init__(self):
        self.metrics = ScanMetrics()
        self._psi_buffers: Dict[int, bytearray] = {}
        self._pmt_seen_pids: set = set()
        self._last_cc: Dict[int, int] = {}
        self._video_tails: Dict[int, bytes] = {}
        # Type of current NAL by PID (True = filler): bytes between start codes
        # are attributed to the NAL that they continue, incl. at the junction
        # TS packages.
        self._in_filler_nal: Dict[int, bool] = {}   # no key = NAL type not yet known

    def process_packet(self, packet: bytes) -> None:
        metrics = self.metrics
        if len(packet) != TS_PACKET_SIZE or packet[0] != 0x47:
            return          # protection in case of direct call from tests
        metrics.total_ts_packets += 1

        pid = get_pid(packet)
        # transport_error_indicator: source/demodulator marked packet as
        # irreparably damaged. Its header and payload are invalid, so
        # the packet is only counted and not further analyzed (we don’t touch NULL packets:
        # their accounting is needed for bitrate).
        if packet[1] & 0x80 and pid != 0x1FFF:
            metrics.tei_packets += 1
            # We do not check the package itself in continuity, but we “accept” it CC as
            # last seen: otherwise the normal packet following it would give
            # an extra cc error (each TEI would be counted twice - as TEI and as CC).
            if packet[3] & 0x10:        # CC increases only for packages with payload
                self._last_cc[pid] = packet[3] & 0x0F
            return
        payload_unit_start = bool(packet[1] & 0x40)
        payload = extract_payload(packet)

        if payload is not None:
            self._parse_psi(pid, payload, payload_unit_start)

        scrambling = get_scrambling(packet)
        adaptation_control = (packet[3] & 0x30) >> 4
        self._update_continuity(packet, pid, adaptation_control, payload)  # ← transfer payload
        self._update_scrambling(pid, scrambling)

        if payload and pid in metrics.audio_pids:
            self._analyze_audio_fill(pid, payload, payload_unit_start)

        if pid not in metrics.video_pids or pid == 0:
            return
        if payload_unit_start and payload:
            metrics.video_pus_count += 1
        if payload:
            metrics.video_payload_bytes += len(payload)
            self._analyze_start_codes(pid, payload, metrics.video_pids[pid], payload_unit_start)

    def finalize(self) -> ScanMetrics:
        """Replenishes metrics that are calculated only upon completion
        parsing (pmt_parsed depends on the full set of PMT sections seen)."""
        self.metrics.pmt_parsed = bool(self._pmt_seen_pids)
        return self.metrics

    def _parse_psi(self, pid: int, payload: bytes, payload_unit_start: bool) -> None:
        metrics = self.metrics
        if pid == 0x0000:
            buffer = self._psi_buffers.setdefault(pid, bytearray())
            for section in _extract_complete_psi_sections(buffer, payload, payload_unit_start):
                if parse_pat_section(section, metrics.pmt_pid_to_program):
                    metrics.pat_parsed = True
            return
        if pid in metrics.pmt_pid_to_program:
            metrics.pmt_pid_packets += 1
            buffer = self._psi_buffers.setdefault(pid, bytearray())
            sections = _extract_complete_psi_sections(buffer, payload, payload_unit_start)
            metrics.pmt_sections_seen += len(sections)
            for section in sections:
                if parse_pmt_section(
                        section, metrics.video_pids, metrics.audio_pids,
                        metrics.unclassified_pids, metrics.unsupported_video_pids,
                ):
                    self._pmt_seen_pids.add(pid)
                    metrics.pmt_sections_valid += 1
                    # We set it here too, and not just in finalize(): it is necessary
                    # know the live status "PMT has already been caught" right as you go
                    # stream reading - see IPTVScanner._read_deadline_reached().
                    metrics.pmt_parsed = True

    def _update_continuity(self, packet: bytes, pid: int, adaptation_control: int, payload: Optional[bytes]) -> None:
        # Continuity counter is taken into account only for packets with a real (non-zero) payload.
        # Packets with adaptation_field_control == 3, but AF occupying the entire rest of the packet
        # (payload == b''), in fact they do not carry payloads - we skip them so as not
        # receive false cc_err on real IPTV streams.
        if pid == 0 or pid == 0x1FFF or adaptation_control == 0:
            return

        cc = get_continuity_counter(packet)

        # discontinuity_indicator is in the adaptation field, so it can come
        # both in the adaptation-only package (afc=2) and in the package with payload (afc=3).
        # Flag semantics: after it CC can be arbitrary (replaced
        # source/encoder, timebase updated) - current CC becomes new
        # base point, a discrepancy with the previous one is NOT an error.
        #
        # Retrieved BEFORE early return due to lack of payload: otherwise
        # an adaptation-only packet with discontinuity_indicator=1 would be lost, and
        # the next CC divergence would produce a false cc_err.
        discontinuity = False
        if adaptation_control in (2, 3):
            af_len = packet[4]
            if af_len >= 1 and 5 + af_len <= TS_PACKET_SIZE:
                discontinuity = bool(packet[5] & 0x80)

        if discontinuity:
            # Reset baseline to current CC: next packet with payload will be
            # checked against (cc + 1), not against the value from the old one
            # continuum.
            self._last_cc[pid] = cc
            return

        # CC is taken into account only for packets with a real (non-zero) payload:
        # adaptation-only (afc=2) and afc=3 with AF taking up the entire rest of the packet
        # (payload == b''), CC is not incremented and baseline is not moved.
        # We skip them until we check the discrepancy.
        if adaptation_control not in (1, 3) or not payload:
            return

        if pid in self._last_cc:
            previous_cc = self._last_cc[pid]
            if cc != previous_cc:
                expected = (previous_cc + 1) & 0x0F
                if cc != expected:
                    self.metrics.continuity_errors_by_pid[pid] += 1
        self._last_cc[pid] = cc

    def _update_scrambling(self, pid: int, scrambling: int) -> None:
        metrics = self.metrics
        if pid == 0x1FFF:
            metrics.null_packets += 1
        if pid != 0 and scrambling in SCRAMBLED_VALUES:
            metrics.scrambled_any_pid += 1
        if pid in metrics.video_pids:
            metrics.total_video_packets += 1
            if scrambling in SCRAMBLED_VALUES:
                metrics.scrambled_video += 1
        elif pid in metrics.audio_pids:
            metrics.total_audio_packets += 1
            if scrambling in SCRAMBLED_VALUES:
                metrics.scrambled_audio += 1

    def _analyze_audio_fill(
        self, pid: int, payload: bytes, payload_unit_start: bool
    ) -> None:
        """For AAC, counts the share of fill bytes (FIL, fill_byte=0xA5) in the ES track.

        An encoder without audio input produces "empty" frames (silence = tiny
        CPE) and finishes them off with CBR FIL elements. Packets are coming, bitrate is 128
        kbps, but nothing can be heard. Real audio of long series of the same
        does not contain fill bytes.
        """
        metrics = self.metrics
        if metrics.audio_pids.get(pid) not in AAC_STREAM_TYPES:
            return
        es = payload
        if (payload_unit_start and len(payload) >= 9
                and payload[0] == 0x00 and payload[1] == 0x00 and payload[2] == 0x01
                and 0xC0 <= payload[3] <= 0xDF):
            es = payload[9 + payload[8]:]   # cut off the PES header
        if not es:
            return
        metrics.audio_es_bytes_by_pid[pid] += len(es)
        metrics.audio_fill_bytes_by_pid[pid] += sum(
            len(m) for m in _AAC_FILL_RE.findall(es)
        )

    def _analyze_start_codes(
        self,
        pid: int,
        payload: bytes,
        stream_type: int,
        payload_unit_start: bool
    ) -> None:
        metrics = self.metrics
        is_mpeg2 = stream_type in MPEG2_STREAM_TYPES
        is_modern = stream_type in MODERN_VIDEO_STREAM_TYPES
        if not (is_mpeg2 or is_modern):
            return

        # In addition to the pes_header_count/pes_scrambled_count counters, the PES header
        # needed to separate service bytes from elementary stream: search
        # 00 00 01 in EVERYTHING payload gives false start codes.
        #
        # (a) The prefix of the PES header itself is also 00 00 01. The byte going
        #     immediately after it is stream_id (0xE0..0xEF), and it is erroneously
        #     interpreted as H.264 NAL header: with stream_id 0xE1..0xE5
        #     (nal_type = stream_id & 0x1F = 1..5) gives a false VCL, when
        #     0xE7/0xE8 (nal_type 7/8) - false PARAM. Threshold
        #     min_modern_vcl_nals=2 is low, and there are plenty of such false hits,
        #     to mask the real Status.NO_PICTURE.
        # (b) _video_tails[pid] stores the tail of the ES data, not
        #     arbitrary payload: otherwise the last bytes of the PES header
        #     are merged with the ES data of the next TS packet and again give
        #     false start code at the junction.
        pes_hdr: Optional[bytes] = None
        es_payload = payload
        if payload_unit_start and payload:
            pes_hdr_offset = -1
            if (len(payload) >= 9 and payload[0] == 0x00 and payload[1] == 0x00
                    and payload[2] == 0x01 and 0xE0 <= payload[3] <= 0xEF):
                pes_hdr_offset = 0
            elif (len(payload) >= 10 and payload[0] == 0x00 and payload[1] == 0x00
                    and payload[2] == 0x00 and payload[3] == 0x01
                    and 0xE0 <= payload[4] <= 0xEF):
                pes_hdr_offset = 1
            if pes_hdr_offset >= 0:
                # The pes_hdr_offset+8 byte is PES_header_data_length:
                #   +0..+2  start code prefix
                #   +3      stream_id
                #   +4..+5  PES_packet_length
                #   +6..+7  flags1/flags2
                #   +8      PES_header_data_length
                #   +9 .. +9+len-1  PTS/DTS/stuffing
                #   +9+len — beginning of elementary stream
                # Checking len(payload) in recognition conditions ensures that
                # that byte +8 is present.
                header_data_length = payload[pes_hdr_offset + 8]
                es_start = pes_hdr_offset + 9 + header_data_length
                pes_hdr = payload[pes_hdr_offset:]
                # If the header “does not fit” into the payload (a broken stream with
                # unrealistic header_data_length) - we assume that ES data
                # not in this package. Nothing to lose: analyze the remaining
                # bytes as ES would still mean looking for start codes in
                # middle of the PES title.
                es_payload = payload[es_start:] if es_start <= len(payload) else b""

        if pes_hdr is not None:
            metrics.pes_header_count += 1
            # pes_hdr is always aligned to the beginning of the 3-byte start code prefix,
            # so pes_hdr[6] = flags1 with scrambling_control field in
            # bits 4..5 - as before this edit.
            pes_scrambling = (pes_hdr[6] & 0x30) >> 4
            if pes_scrambling in (2, 3):
                metrics.pes_scrambled_count += 1

        # Only ES data + tail from the previous TS packet (also only ES).
        if is_mpeg2 and es_payload:
            metrics.video_es_bytes += len(es_payload)
            metrics.video_filler_bytes += sum(
                len(m) for m in _MPEG2_STUFFING_RE.findall(es_payload)
            )

        tail = self._video_tails.get(pid, b"")
        data = tail + es_payload
        start = 0
        data_len = len(data)
        # Accounting of ES bytes for H.264/HEVC: acc - the first byte not yet taken into account
        # (the first len(tail) bytes are already taken into account in the previous call).
        # in_filler = None - the type of the current NAL is not yet known (analysis is included in
        # flow in the middle of PES, for example, immediately after receiving PMT): such
        # bytes are not taken into account until the first start code, otherwise the “tail” of someone else’s
        # filler-NAL would be written to the payload.
        in_filler = self._in_filler_nal.get(pid)
        acc = len(tail)
        while start + 3 < data_len:
            pos = data.find(b'\x00\x00\x01', start)
            if pos < 0 or pos + 3 >= data_len:
                break
            code = data[pos + 3]
            if is_modern:
                if pos > acc:
                    if in_filler is not None:
                        metrics.video_es_bytes += pos - acc
                        if in_filler:
                            metrics.video_filler_bytes += pos - acc
                    acc = pos
                filler_type = (H264_FILLER_NAL_TYPE if stream_type in H264_STREAM_TYPES
                               else HEVC_FILLER_NAL_TYPE)
                nal = (code & 0x1F) if stream_type in H264_STREAM_TYPES else ((code >> 1) & 0x3F)
                in_filler = (nal == filler_type)
            if is_mpeg2:
                if code == 0x00:
                    metrics.mpeg2_picture_count += 1
                elif code == 0xB3:
                    metrics.mpeg2_sequence_count += 1
                    # sequence_header: start code is followed by horizontal_size (12 bits)
                    # and vertical_size (12 bits). We read it once only if everything
                    # 3 bytes are in the current buffer (otherwise at the next GOP).
                    if not metrics.mpeg2_width and pos + 7 <= data_len:
                        w = (data[pos + 4] << 4) | (data[pos + 5] >> 4)
                        h = ((data[pos + 5] & 0x0F) << 8) | data[pos + 6]
                        if 16 <= w <= 4096 and 16 <= h <= 4096:
                            metrics.mpeg2_width, metrics.mpeg2_height = w, h
                elif code == 0xB8:
                    metrics.mpeg2_gop_count += 1
                elif code in MPEG2_SLICE_CODES:
                    metrics.mpeg2_slice_count += 1
            else:
                if stream_type in H264_STREAM_TYPES:
                    nal_type = code & 0x1F
                    if nal_type in H264_VCL_NAL_TYPES:
                        metrics.modern_vcl_count += 1
                    elif nal_type in H264_PARAM_NAL_TYPES:
                        metrics.modern_param_count += 1
                else:
                    nal_type = (code >> 1) & 0x3F
                    if nal_type in HEVC_VCL_NAL_TYPES:
                        metrics.modern_vcl_count += 1
                    elif nal_type in HEVC_PARAM_NAL_TYPES:
                        metrics.modern_param_count += 1
            start = pos + 4
        if is_modern:
            if in_filler is not None and data_len > acc:
                metrics.video_es_bytes += data_len - acc
                if in_filler:
                    metrics.video_filler_bytes += data_len - acc
            if in_filler is not None:
                self._in_filler_nal[pid] = in_filler
        # The tail is also from ES data (not from the full payload). This is exactly what
        # closes the second channel of false hits - at the junction of TS packets.
        self._video_tails[pid] = data[-3:] if data_len >= 3 else data


class Channel:
    def __init__(self, name: str, url: str) -> None:
        self.name: str = name.strip()
        self.url: str = url.strip()
        # Display name (may contain suffix [2], [3] ... for duplicates).
        # Channel.name always remains original.
        self.display_name: str = self.name

    @property
    def alert_key(self) -> Tuple[str, str]:
        return self.name.lower(), self.url


@dataclass(frozen=True)
class ScanResult:
    channel: Channel
    status: Status
    details: str
    metrics: Optional[ScanMetrics] = None
    connect_reason: Optional[ConnectFailReason] = None


class StreamFetcher:
    """A thin wrapper over an HTTP stream request.

    Moved so that the implementation can be replaced in the future
    on asyncio/httpx without rewriting TSStreamAnalyzer and classification.
    """
    def __init__(self, session: requests.Session, headers: dict):
        self._session = session
        self._headers = headers

    def open_stream(self, url: str, connect_timeout: float, read_timeout: float):
        """Returns requests.Response (stream=True). Caller must close."""
        return self._session.get(
            url,
            stream=True,
            timeout=(connect_timeout, read_timeout),
            headers=self._headers,
            # verify=True explicitly - insurance against accidental TLS disconnection when
            # future edits; the CA policy and source are described in the block
            # "TLS trust store" at the beginning of the module.
            verify=True,
        )


class IPTVScanner:
    def __init__(self) -> None:
        self.vlc_path: str = get_default_vlc_path()
        self.scan_timeout: int = RUNTIME.default_scan_timeout
        self.parallel: int = RUNTIME.default_parallel
        self.min_bitrate_kbps: int = RUNTIME.default_min_bitrate_kbps
        self.playlist_names: List[str] = [""] * MAX_PLAYLISTS
        self.playlist_urls: List[str] = [""] * MAX_PLAYLISTS
        self.current_playlist_idx: int = -1
        self.preload_playlist: str = ""  # default; load_config() may overwrite
        self.channels: List[Channel] = []
        self.alerts: Dict[Tuple[str, str], dict] = {}
        self._alerts_lock = threading.Lock()
        self.last_index: int = 0
        self._thread_local = threading.local()
        self._sessions_lock = threading.Lock()
        self._active_sessions: list[requests.Session] = []
        self._active_responses_lock = threading.Lock()
        self._active_responses: List[requests.Response] = []
        # The only source of truth for the "scanning progress/failure" status.
        # is_scanning below is a read-only wrapper around this Event, not a separate one
        # bool flag so that you don’t have to keep two independent ones synchronous
        # sign of the condition. Event semantics: "set" = scanning stopped
        # or has not started yet, "clear" = scanning is active. Initially
        # exposed (idle state).
        self._stop_event = threading.Event()
        self._stop_event.set()
        self.thresholds: Thresholds = Thresholds()
        # Channel name prefixes for which sound/alert windows are suppressed
        # (see update_channel_row) and error log entries (see
        # IPTVScanner.check_channel). Set via scanner_config.json
        # ("no_alert_prefixes"); the default is empty - nothing is suppressed.
        self.no_alert_prefixes: tuple[str, ...] = ()
        # Channels that are known to be scrambled: for them it is used
        # simplified transport classification (Status.OK*). Set via
        # scanner_config.json("known_scrambled_prefixes"); default is empty.
        self.known_scrambled_prefixes: tuple[str, ...] = ()
        self.ui_strings: Dict[str, str] = dict(DEFAULT_UI_STRINGS)
        self._unsupported_logged: set = set()   # channels for which OK is already registered**
        self.tree_colors: Dict[str, Dict[str, str]] = {
            tag: dict(colors) for tag, colors in DEFAULT_TREE_COLORS.items()
        }
        # Saturation multiplier (HSL) on top of tree_colors. 1.0 = as specified in
        # tree_colors/DEFAULT_TREE_COLORS no changes. Exists due to
        # known Windows 11 bug: when HDR is enabled, the system becomes discolored
        # SDR applications on the way to the screen (see settings → saturation slider
        # lines), values above 1.0 compensate for this by setting the colors "with a margin".
        self.color_saturation: float = 1.0
        self.column_widths: Dict[str, Dict[str, Any]] = {
            col: dict(vals) for col, vals in DEFAULT_COLUMN_WIDTHS.items()
        }
        self.session_headers = {
            'User-Agent': 'Mozilla/5.0',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Connection': 'close',
        }

        # VPN fallback (see vpn.py). vpn_enabled - user intent
        # from settings; it does NOT guarantee that the elevated helper is currently alive
        # (the helper could have crashed, UAC could have been rejected at the start of the program
        # with already saved vpn_enabled=True, etc.). Opting out of UAC
        # It is when you enable the checkbox in the settings that it rolls back
        # vpn_enabled to False - see _sett_apply_vpn_result.
        self.vpn_enabled: bool = False
        self.vpn_connection_name: str = ""
        # None = legacy/auto; True = All User; False = current user.
        self.vpn_connection_all_user: Optional[bool] = None

        # The locks/structures below must exist before load_config():
        # on a clean machine (no scanner_config.json) load_config() itself
        # calls save_config(), which already needs _config_lock.
        self._hanging_lock = threading.Lock()
        self._hanging_count = 0
        self.MAX_HANGING_THREADS = self._compute_max_hanging_threads(self.parallel)
        self._hanging_semaphore = threading.Semaphore(self.MAX_HANGING_THREADS)
        self._channels_lock = threading.Lock()
        # RLock (not Lock): save_config() builds a snapshot of the configuration
        # data UNDER the same location (see save_config), and the snapshot itself
        # relies on get_active_playlists(), which also takes
        # _config_lock - a regular Lock here would lead to self-jamming
        # flow on re-acquire.
        self._config_lock = threading.RLock()
        self._fail_cooldowns: Dict[Tuple[str, str], float] = {}  # alert_key → monotonic time
        self._cooldowns_lock = threading.Lock()
        # Rate-limiting logs: full traceback ("Internal analyzer error") is not written
        # every time the same channel drops (alert_key), and once per scan -
        # otherwise a massive network failure (for example, the entire playlist fell off) would print
        # the same traceback hundreds of times. Resets to clear_stop(): every new one
        # The scan again receives a full traceback for the first drop of each channel.
        self._internal_error_seen: Set[Tuple[str, str]] = set()
        self._internal_error_lock = threading.Lock()
        self._last_cooldown_cleanup = time.monotonic()
        self._last_hanging_cleanup = time.monotonic()
        self._abandoned_total = 0
        # Soft backoff for hanging-recovery (see _maybe_cleanup_hanging_locked).
        # Initialized here, and not just in clear_stop(), because cleanup
        # may also work before the first clear_stop() (for example, at the start
        # program if scan_timeout has already expired by the time of the first check_channel).
        self._hanging_soft_resets: int = 0
        self._last_hanging_soft_reset: float = 0.0
        self._fatal_scan_lock = threading.Lock()
        self._fatal_scan_message: Optional[str] = None
        # The last logged problem status for the channel (alert_key → Status).
        # This is necessary so as not to write the same fault in the log on each
        # scan iterations - only at the moment the type of problem appears or changes.
        self._last_issue_status: Dict[Tuple[str, str], Status] = {}
        self._issue_log_lock = threading.Lock()

        # We declare the flag before load_config(): it is overridden there, but
        # check below should work and if load_config() fails
        # before he is put out.
        self._ui_strings_migrated: bool = False
        self.load_config()
        # Migrating ui_strings: if load_config() is found in the config
        # keys that are not in the current DEFAULT_UI_STRINGS - immediately
        # rewrite the config so that the JSON contains only the current one
        # set of strings. Without this, new keys (for example, those that appeared after
        # detail_no_audio splits) would not appear in the file until
        # next change in settings, and the obsolete ones would not go away.
        if self._ui_strings_migrated:
            # Reset BEFORE save_config: save_config does not read by itself
            # this flag, but the “remove the flag before working” rule protects against
            # random recursive entry in the future.
            self._ui_strings_migrated = False
            self.save_config()


    @staticmethod
    def _compute_max_hanging_threads(parallel: int) -> int:
        """Limit of simultaneously “stuck” worker threads (see check_channel).

        2× parallel provides a reserve for short-term freezes of individual
        inspections, without allowing their number to grow to many dozens
        zombie streams; the lower bound 12 is needed so that when parallel is small
        (for example, 1-2) the scanner did not begin to refuse checks almost immediately.
        """
        return max(12, parallel * 2)

    def _max_abandoned_threads(self) -> int:
        return max(24, self.MAX_HANGING_THREADS * 2)

    def _report_fatal_scan_error(self, message: str) -> None:
        with self._fatal_scan_lock:
            if self._fatal_scan_message is None:
                self._fatal_scan_message = message
        self._stop_event.set()

    def consume_fatal_scan_error(self) -> Optional[str]:
        with self._fatal_scan_lock:
            msg = self._fatal_scan_message
            self._fatal_scan_message = None
            return msg

    def _cleanup_fail_cooldowns_locked(self, now: float) -> None:
        """Removes from _fail_cooldowns entries with already expired cooldown.

        Usually the entry itself is deleted in check_channel() on the next successful
        scan of the same channel (see OK/RADIO branch). But if a channel with an active
        cooldown disappears from the playlist forever (deleted, renamed URL and
        etc.), this “next scan” will no longer exist - the record would remain in
        dictionary forever. Therefore once in RUNTIME.fail_cooldown_cleanup_interval_sec
        we clean up everything that has already expired on its own.

        IMPORTANT: call only under self._cooldowns_lock (the lock itself is not here
        takes it so as not to try to capture it again from check_channel).
        """
        if now - self._last_cooldown_cleanup < RUNTIME.fail_cooldown_cleanup_interval_sec:
            return
        self._last_cooldown_cleanup = now
        expired_keys = [k for k, until in self._fail_cooldowns.items() if until <= now]
        for k in expired_keys:
            del self._fail_cooldowns[k]
        if expired_keys:
            logger.debug("Cleaned up %d expired fail-cooldown entries", len(expired_keys))
            
    def _maybe_cleanup_hanging_locked(self, now: float) -> None:
        """Periodically resets the counter of frozen threads and recreates the semaphore.

        Needed as a recovery mechanism: if the worker is forever stuck inside
        getaddrinfo/system socket, its finally will never be executed,
        _hanging_count and semaphore slots will leak. Once per RUNTIME.hanging_cleanup_interval_sec
        we forcefully reset the counter and issue a fresh semaphore.
        The old daemon threads continue to live, but no longer block
        new checks.

        Soft backoff: several soft-resets in a row (with cooldown) do not stop
        scan; fatal - only after the soft limit has been exhausted or exceeded
        _max_abandoned_threads(). Call only under self._hanging_lock."""
        if now - self._last_hanging_cleanup < RUNTIME.hanging_cleanup_interval_sec:
            return
        self._last_hanging_cleanup = now
        if self._hanging_count > 0:
            if self._abandoned_total >= self._max_abandoned_threads():
                logger.error(
                    "Too many hung network threads (%d) — further scanning stopped",
                    self._abandoned_total,
                )
                self._report_fatal_scan_error(
                    self.s("detail_hanging_abandoned", count=self._abandoned_total)
                )
                return
            # Soft-reset: we reset the counter, but accumulate soft resets.
            soft_count = self._hanging_soft_resets + 1
            if now - self._last_hanging_soft_reset > RUNTIME.hanging_soft_reset_cooldown_sec:
                soft_count = 1
            self._hanging_soft_resets = soft_count
            self._last_hanging_soft_reset = now
            if soft_count > RUNTIME.hanging_soft_reset_max:
                logger.error(
                    "Repeated soft resets of hung threads (%d) did not help "
                    "(abandoned=%d) — scanning stopped",
                    soft_count, self._abandoned_total,
                )
                self._report_fatal_scan_error(
                    self.s(
                        "detail_hanging_soft_resets",
                        resets=soft_count, count=self._abandoned_total,
                    )
                )
                return
            logger.warning(
                "Soft hanging-threads cleanup #%d: was %d/%d — resetting "
                "counter and semaphore; total abandoned=%d/%d",
                soft_count, self._hanging_count, self.MAX_HANGING_THREADS,
                self._abandoned_total, self._max_abandoned_threads(),
            )
            self._hanging_count = 0
            self._hanging_semaphore = threading.Semaphore(self.MAX_HANGING_THREADS)

    @staticmethod
    def _find_in_exception_chain(
        e: Optional[BaseException],
        predicate: Callable[[BaseException], bool],
        _seen: Optional[set] = None,
    ) -> Optional[BaseException]:
        """The first object in the exception chain (e, args, __cause__,
        __context__) for which predicate() is true, or None.

        Single workaround for _is_connection_reset() and _find_os_error(): exceptions
        from requests/urllib3 layered, the real reason (eg
        ConnectionRefusedError or ConnectionResetError) usually lies at 2–4
        nesting levels, and both functions look for a specific type in this chain.
        The general implementation guarantees the same traversal order (object itself →
        args → __cause__ → __context__) and the same loop protection - earlier
        these were two independent copies that could diverge during editing
        one of them.

        Traversal order is important for _find_os_error(): it returns FIRST
        is a match, and __cause__ (the more direct cause) should be checked first
        __context__ (implicit context). The order has been preserved.

        predicate is called with a BaseException node; only objects are bypassed
        isinstance BaseException - the same limitation that both original ones had
        functions.
        """
        if e is None:
            return None
        if _seen is None:
            _seen = set()
        if id(e) in _seen:
            return None
        _seen.add(id(e))
        if predicate(e):
            return e
        for arg in getattr(e, "args", ()):
            if isinstance(arg, BaseException):
                found = IPTVScanner._find_in_exception_chain(arg, predicate, _seen)
                if found is not None:
                    return found
        for attr in ("__cause__", "__context__"):
            nested = getattr(e, attr, None)
            if isinstance(nested, BaseException):
                found = IPTVScanner._find_in_exception_chain(nested, predicate, _seen)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _is_connection_reset(e: BaseException) -> bool:
        """True if in the exception chain (object itself, args, __cause__/__context__)
        there is a ConnectionResetError, that is, the remote side forcibly disconnected
        established connection (WinError 10054 / ECONNRESET).

        Needed separately from the isinstance checks below: urllib3/requests wrap
        such a reset is not in ConnectionError, but, for example, in ChunkedEncodingError (break
        in the middle of reading a stream - typically right after the computer wakes up, when
        the old TCP socket is still alive on the client, but has already been reset by the OS or remote
        side). There is no separate check for ChunkedEncodingError, and its str() is
        unreadable repr of nested ConnectionResetError.
        """
        return IPTVScanner._find_in_exception_chain(
            e, lambda x: isinstance(x, ConnectionResetError),
        ) is not None

    @staticmethod
    def _find_os_error(e: BaseException) -> Optional[BaseException]:
        """The first OSError/socket.gaierror in the __cause__/__context__/args chain.

        The structure is the same idiom as _is_connection_reset(): exceptions
        from requests/urllib3 layered, the real reason (eg
        ConnectionRefusedError) lies at a depth of 2–4 levels. Returns None
        if nothing is found.
        """
        # requests.exceptions.RequestException inherits from IOError (=OSError) so
        # without an explicit exception the predicate would fire on the requests.ConnectionError ITSELF
        # (errno=None) and the bypass would never get to the real reason
        # (ConnectionRefusedError/socket.gaierror) in __cause__/__context__.
        return IPTVScanner._find_in_exception_chain(
            e,
            lambda x: (
                isinstance(x, (socket.gaierror, OSError))
                and not isinstance(x, requests.exceptions.RequestException)
            ),
        )

    def _shorten_request_error(self, e: Exception) -> str:
        """Short meaningful UI text from requests/urllib3 exceptions.

        Branching by TYPES and error codes, not by text str(e): messages
        system socket errors are localized by Windows, so in non-English
        locale, text substrings like 'connection refused' will not match.
        The only text match is 'max retries exceeded' -
        safe: this line is hardcoded in the urllib3 sources and is not
        depends on the OS.
        """
        if self._is_connection_reset(e):
            return self.s("err_connection_reset")
        # SSLError comes BEFORE ConnectTimeout/ReadTimeout/ConnectionError:
        # requests.exceptions.SSLError is a subclass of ConnectionError, and without
        # earlier, it would have ended up in the generic ConnectionError branch.
        # and would return a useless "Connection error" to the user instead
        # "TLS certificate error." Order is key here.
        #
        # Position AFTER _is_connection_reset: if raw TCP reset arrived
        # in the middle of a TLS handshake, urllib3 can wrap it in an SSLError.
        # Then it would be more correct to report “Connection terminated” rather than
        # “TLS certificate error” - otherwise the user will leave to figure it out
        # with certificates, although the problem was network.
        if isinstance(e, requests.exceptions.SSLError):
            return self.s("err_ssl_error")
        if isinstance(e, requests.exceptions.ConnectTimeout):
            return self.s("err_connect_timeout")
        if isinstance(e, requests.exceptions.ReadTimeout):
            return self.s("err_read_timeout")
        if isinstance(e, requests.exceptions.Timeout):
            return self.s("err_timeout")
        if isinstance(e, requests.exceptions.ConnectionError):
            # We go down the chain __cause__/__context__ to the first
            # OSError/socket.gaierror: the text of the requests.ConnectionError itself
            # contains only English urllib3 messages, but here is the reason
            # ('connection refused' / 'host not found') determined by code
            # from nested exception.
            err = self._find_os_error(e)
            if isinstance(err, socket.gaierror):
                return self.s("err_host_not_found")
            if isinstance(err, ConnectionRefusedError):
                return self.s("err_connection_refused")
            # WinError 10061 = WSAECONNREFUSED, 11001/11002 = WSAHOST_NOT_FOUND / WSATRY_AGAIN.
            # ctypes is not needed: errno for socket errors is the same as WinError.
            if isinstance(err, OSError) and err.errno in (10061,):
                return self.s("err_connection_refused")
            if isinstance(err, OSError) and err.errno in (11001, 11002, 11004):
                return self.s("err_host_not_found")
            msg = str(e).lower()
            if "max retries exceeded" in msg:
                return self.s("err_max_retries_exceeded")
            return self.s("err_connection_error")
        msg = str(e)
        if ": " in msg:
            return msg.rsplit(": ", 1)[-1].strip()[:60]
        return msg[:80]

    def s(self, key: str, **kwargs) -> str:
        template = self.ui_strings.get(key, DEFAULT_UI_STRINGS.get(key, key))
        if kwargs:
            try:
                return template.format(**kwargs)
            except (KeyError, ValueError, IndexError):
                return template
        return template

    def _get_session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self.session_headers)
            self._thread_local.session = session
            with self._sessions_lock:
                self._active_sessions.append(session)
        return session

    def _close_session(self) -> None:
        """Closes a thread-local Session if one has been created."""
        session = getattr(self._thread_local, "session", None)
        if session is not None:
            try:
                session.close()
            except Exception:
                logger.debug("Failed to close requests.Session", exc_info=True)
            try:
                del self._thread_local.session
            except AttributeError:
                self._thread_local.session = None
                
    def close_all_sessions(self) -> None:
        """Closes all known thread-local Sessions.

        Only sessions from fetch_playlist_channels() go here (see _get_session/
        _close_session). Per-channel scanning (check_channel/_scan_channel_stream)
        creates requests.Session for the channel and closes it itself (see check_channel.
        _worker) without registering here.

        Call when scanning is stopped and the playlist is changed. Threads stuck
        inside requests, their sessions will not be closed - this is a limitation of the model, but they are alive
        workers will release the sockets immediately.
        """
        with self._sessions_lock:
            sessions = list(self._active_sessions)
            self._active_sessions.clear()
        if sessions:
            logger.info("Closing %d active session(s)", len(sessions))
        for session in sessions:
            try:
                session.close()
            except Exception:
                logger.debug("Failed to close requests.Session", exc_info=True)
        # Clean thread-local of the current thread (if any)
        self._close_session()

    def register_response(self, r: requests.Response) -> None:
        with self._active_responses_lock:
            self._active_responses.append(r)

    def unregister_response(self, r: requests.Response) -> None:
        with self._active_responses_lock:
            try:
                self._active_responses.remove(r)
            except ValueError:
                pass

    def abort_active_responses(self) -> None:
        """Closes still open HTTP responses, unblocking dangling iter_content()
        in per-channel workers. Without this, scan_thread after request_stop() would live until
        hard_timeout of each worker (scan_timeout * watchdog_multiplier + 3):
        iter_content() cannot be interrupted externally other than by closing the socket.

        r.close() from another thread is the standard way to unblock a blocking thread
        recv(): on Windows and Linux, closing a socket returns a hanging read() with
        error, it turns into ConnectionError and is routinely caught in _worker as
        requests.RequestException. No side effects: by the time _stop_event is called
        is already enabled, and scan_loop does not pass the results of interrupted workers to the UI
        (is_scanning check at each iteration of as_completed and generation check)."""
        with self._active_responses_lock:
            responses = list(self._active_responses)
            self._active_responses.clear()
        for r in responses:
            try:
                r.close()
            except Exception:
                logger.debug("Response.close() failed during abort", exc_info=True)

    def effective_tree_colors(self) -> Dict[str, Dict[str, str]]:
        """tree_colors with self.color_saturation multiplier applied.

        This is what is passed to tag_configure(). self.tree_colors remains clean
        base (as in the config / DEFAULT_TREE_COLORS), and the saturation is superimposed
        here every time anew and is not stored in a modified form - therefore
        dragging the slider in the settings does not corrupt the basic values irreversibly,
        even if the user edits tree_colors manually."""
        factor = self.color_saturation
        if abs(factor - 1.0) < 1e-9:
            return {tag: dict(colors) for tag, colors in self.tree_colors.items()}
        result: Dict[str, Dict[str, str]] = {}
        for tag, colors in self.tree_colors.items():
            adjusted = dict(colors)
            if "background" in adjusted:
                adjusted["background"] = _scale_hex_color_saturation(
                    adjusted["background"], factor, pull_toward_mid=True
                )
            result[tag] = adjusted
        return result

    def apply_scan_settings(self, scan_timeout: Any, parallel: Any, min_bitrate_kbps: Any) -> None:
        """Validates (clamps into the acceptable range) and applies three scan settings:
        timeout, parallelism, minimum bitrate.

        Single entry point for load_config() and GUI settings window to allow valid
        ranges and order of validation were consistent. When non-numeric/incorrect
        value, the default value for the field is taken. Also syncs
        MAX_HANGING_THREADS and recreates the semaphore of hung threads if parallel
        changed.
        """
        self.scan_timeout = _clamp_int(
            scan_timeout, RUNTIME.scan_timeout_min_sec, RUNTIME.scan_timeout_max_sec, RUNTIME.default_scan_timeout
        )
        self.parallel = _clamp_int(
            parallel, RUNTIME.parallel_min, RUNTIME.parallel_max, RUNTIME.default_parallel
        )
        self.min_bitrate_kbps = _clamp_int(
            min_bitrate_kbps,
            RUNTIME.min_bitrate_setting_kbps,
            max(RUNTIME.min_bitrate_setting_kbps, self.thresholds.error_bitrate_kbps),
            RUNTIME.default_min_bitrate_kbps,
        )
        new_max = self._compute_max_hanging_threads(self.parallel)
        if new_max != getattr(self, "MAX_HANGING_THREADS", None):
            self.MAX_HANGING_THREADS = new_max
            self._hanging_semaphore = threading.Semaphore(new_max)

    def load_config(self) -> None:
        # Migration flag ui_strings. True — when reading the config, they were found
        # keys that are no longer in DEFAULT_UI_STRINGS (obsolete after
        # refactoring). In this case, __init__ after load_config() immediately
        # rewrites the config so that new lines appear in JSON, and
        # the obsolete ones have left it.
        #
        # Initialization at the beginning is required: the flag below is only set
        # at the very end of the try block (see edit 2). With an exception in the middle
        # reading it remains False, and overwriting partially read
        # condition does not occur.
        self._ui_strings_migrated = False
        
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.vlc_path = data.get('vlc_path', self.vlc_path)
                self.scan_timeout = data.get('scan_timeout', self.scan_timeout)
                self.parallel = data.get('parallel', self.parallel)
                self.min_bitrate_kbps = data.get('min_bitrate_kbps', self.min_bitrate_kbps)
                self.current_playlist_idx = data.get('current_playlist_idx', -1)

                urls = data.get('playlist_urls', [""] * MAX_PLAYLISTS)
                names = data.get('playlist_names', [""] * MAX_PLAYLISTS)

                if not isinstance(urls, list):
                    logger.warning(
                        "playlist_urls in config has type %s, expected list — resetting to defaults",
                        type(urls).__name__,
                    )
                    urls = [""] * MAX_PLAYLISTS
                if not isinstance(names, list):
                    logger.warning(
                        "playlist_names in config has type %s, expected list — resetting to defaults",
                        type(names).__name__,
                    )
                    names = [""] * MAX_PLAYLISTS

                # We bring the elements to str and trim/cut to MAX_PLAYLISTS
                urls = [str(u) if u is not None else "" for u in urls]
                names = [str(n) if n is not None else "" for n in names]
                while len(urls) < MAX_PLAYLISTS:
                    urls.append("")
                while len(names) < MAX_PLAYLISTS:
                    names.append("")
                self.playlist_urls = urls[:MAX_PLAYLISTS]
                self.playlist_names = names[:MAX_PLAYLISTS]

                raw_preload = data.get("preload_playlist", "")
                if isinstance(raw_preload, str):
                    self.preload_playlist = raw_preload.strip()
                else:
                    self.preload_playlist = ""

                active_names = {
                    (self.playlist_names[i] or "").strip()
                    for i in range(MAX_PLAYLISTS)
                    if (self.playlist_names[i] or "").strip()
                    and (self.playlist_urls[i] or "").strip()
                }
                if self.preload_playlist and self.preload_playlist not in active_names:
                    logger.warning(
                        "preload_playlist %r not found in configured playlists — ignored",
                        self.preload_playlist,
                    )
                    self.preload_playlist = ""

                th_data = data.get('thresholds') or {}
                self.thresholds = _validate_thresholds(th_data)
                
                # Channel prefixes (optional)
                raw_no_alert = data.get("no_alert_prefixes")
                if isinstance(raw_no_alert, (list, tuple)):
                    self.no_alert_prefixes = tuple(
                        str(p).strip().lower() for p in raw_no_alert if str(p).strip()
                    )
                else:
                    self.no_alert_prefixes = ()

                raw_scrambled = data.get("known_scrambled_prefixes")
                if isinstance(raw_scrambled, (list, tuple)):
                    self.known_scrambled_prefixes = tuple(
                        str(p).strip().lower() for p in raw_scrambled if str(p).strip()
                    )
                else:
                    self.known_scrambled_prefixes = ()

                ui_data = data.get('ui_strings') or {}
                self.ui_strings = dict(DEFAULT_UI_STRINGS)
                # We roll only those keys that are in the current
                # DEFAULT_UI_STRINGS. The keys remaining in the config from
                # previous versions (for example, detail_no_audio after
                # split into detail_no_audio_not_declared /
                # detail_no_audio_no_packets), are discarded - otherwise they
                # would end up in self.ui_strings and with every save_config()
                # would be returned to JSON, that is, would remain there
                # forever as dead code.
                #
                # Custom keys that are not in DEFAULT_UI_STRINGS,
                # are also filtered out. It's safe: the code is accessed
                # only to keys from DEFAULT_UI_STRINGS (see IPTVScanner.s),
                # and arbitrary keys in the config were never read.
                for _k, _v in ui_data.items():
                    if isinstance(_v, str) and _k in DEFAULT_UI_STRINGS:
                        self.ui_strings[_k] = _v
                # Mark the config for overwriting if the set of keys is in the file
                # differs from the current one (obsolete ones are discarded and/or
                # new ones have appeared - now or after a future update
                # DEFAULT_UI_STRINGS). The flag is read in __init__ immediately
                # after self.load_config(): save_config is called there,
                # so that JSON immediately contains the actual set of rows, and not
                # I was waiting for the next settings change.
                self._ui_strings_migrated = (
                    set(ui_data.keys()) != set(DEFAULT_UI_STRINGS.keys())
                )
                # The detail_errors template from older versions contains {avg} (medium
                # chunk size - metric removed as uninformative). No replacement
                # str.format() would fail with a KeyError and appear raw in the table
                # template.
                if "{avg" in self.ui_strings.get("detail_errors", ""):
                    self.ui_strings["detail_errors"] = DEFAULT_UI_STRINGS["detail_errors"]
                    self._ui_strings_migrated = True

                self.tree_colors = _validate_tree_colors(data.get('tree_colors'))
                self.column_widths = _validate_column_widths(data.get('column_widths'))

                vpn_data = data.get('vpn') or {}
                if isinstance(vpn_data, dict):
                    self.vpn_enabled = bool(vpn_data.get('enabled', False))
                    raw_conn = vpn_data.get('connection_name', '')
                    self.vpn_connection_name = str(raw_conn).strip() if isinstance(raw_conn, str) else ""
                    raw_scope = vpn_data.get('all_user')
                    self.vpn_connection_all_user = raw_scope if isinstance(raw_scope, bool) else None
                else:
                    self.vpn_enabled = False
                    self.vpn_connection_name = ""
                    self.vpn_connection_all_user = None
                if self.vpn_enabled and not self.vpn_connection_name:
                    # Connection name lost/not specified - enabled without
                    # the checkbox is meaningless and will be silently ignored
                    # in the rest of the code, so we explicitly disable it here.
                    self.vpn_enabled = False
                try:
                    saturation = float(data.get('color_saturation', COLOR_SATURATION_DEFAULT))
                except (TypeError, ValueError):
                    saturation = COLOR_SATURATION_DEFAULT
                self.color_saturation = max(COLOR_SATURATION_MIN, min(COLOR_SATURATION_MAX, saturation))

                self.apply_scan_settings(self.scan_timeout, self.parallel, self.min_bitrate_kbps)
                try:
                    idx = int(self.current_playlist_idx)
                except (TypeError, ValueError):
                    idx = -1
                if not (-1 <= idx < MAX_PLAYLISTS):
                    idx = -1
                self.current_playlist_idx = idx
            except Exception as e:
                # Reset in case the flag managed to become True at the end
                # try block, and then an exception was thrown from a later
                # operations (there are no such operations now, but this is more reliable: save_config
                # when overwriting a partially read state, write
                # it is forbidden).
                self._ui_strings_migrated = False
                logger.exception(
                    "Error reading config: %s. Falling back to defaults.", e
                )
        else:
            self.save_config()

    def save_config(self) -> None:
        # IMPORTANT: both snapshot generation (active/data) and file writing are performed under
        # one _config_lock (RLock). If lock protected only the record, it would not save
        # would be from a logically mixed snapshot (for example, when the GUI thread changes
        # playlist_names/urls between reading and writing). All the way "read status
        # -> generate data -> write" is atomic relative to other save_config()
        # and reading playlist arrays under the same lock.
        with self._config_lock:
            active = self.get_active_playlists()
            active_names = {name for _, name, _ in active}
            if self.preload_playlist not in active_names:
                self.preload_playlist = ""

            data = {
                'vlc_path': self.vlc_path,
                'scan_timeout': self.scan_timeout,
                'parallel': self.parallel,
                'min_bitrate_kbps': self.min_bitrate_kbps,
                'playlist_names': self.playlist_names,
                'playlist_urls': self.playlist_urls,
                'no_alert_prefixes': list(self.no_alert_prefixes),
                'known_scrambled_prefixes': list(self.known_scrambled_prefixes),
                # Always written (including an empty line and without active
                # playlists) - so that the field is visible and editable in
                # scanner_config.json immediately after creation, along with
                # other settings from the Settings window.
                'preload_playlist': self.preload_playlist,
            }
            data.update({
                'current_playlist_idx': self.current_playlist_idx,
                'thresholds': asdict(self.thresholds),
                'ui_strings': self.ui_strings,
                'tree_colors': self.tree_colors,
                'column_widths': self.column_widths,
                'color_saturation': self.color_saturation,
                'vpn': {
                    'enabled': self.vpn_enabled,
                    'connection_name': self.vpn_connection_name,
                    'all_user': self.vpn_connection_all_user,
                },
            })

            tmp_file = CONFIG_FILE.with_suffix(".tmp")
            try:
                with tmp_file.open("w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                tmp_file.replace(CONFIG_FILE)
            except Exception as e:
                Path(tmp_file).unlink(missing_ok=True)
                logger.exception("Error saving config: %s", e)

    def get_active_playlists(self) -> List[Tuple[int, str, str]]:
        # _config_lock - the same lock that protects the playlist_names/ mutation
        # playlist_urls (see close_settings and _load_playlist_worker). RLock
        # allows save_config() to safely call this method from within
        # already captured lock (see save_config above).
        result = []
        with self._config_lock:
            for i in range(MAX_PLAYLISTS):
                name = (self.playlist_names[i] or "").strip()
                url = (self.playlist_urls[i] or "").strip()
                if name and url:
                    result.append((i, name, url))
        return result

    def reset_advanced_config_to_defaults(self) -> None:
        """Resets “hidden” sections of the config to defaults.

        Does not affect parameters that the user controls from the window
        Settings: VLC, playlists/preload, timeout/parallel/min_bitrate,
        color saturation, VPN.
        """
        with self._config_lock:
            self.thresholds = Thresholds()
            self.ui_strings = dict(DEFAULT_UI_STRINGS)
            self.tree_colors = {
                tag: dict(colors) for tag, colors in DEFAULT_TREE_COLORS.items()
            }
            self.column_widths = {
                col: dict(vals) for col, vals in DEFAULT_COLUMN_WIDTHS.items()
            }
            self.no_alert_prefixes = ()
            self.known_scrambled_prefixes = ()
        self.save_config()
        
    @staticmethod
    def _find_extinf_name_comma(body: str) -> int:
        """The index of the comma separating #EXTINF attributes from the name, or -1.

        This is the first comma OUTSIDE double quotes: commas inside attribute values
        (group-title="News, Sport") are not separators.
        """
        in_quotes = False
        for i, ch in enumerate(body):
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == "," and not in_quotes:
                return i
        # Unpaired quote (broken attribute): parsing by quotes is unreliable -
        # we roll back to the previous “first comma” behavior.
        if body.count('"') % 2:
            return body.find(",")
        return -1

    @staticmethod
    def _parse_extinf_name(line: str) -> str:
        """Gets the channel name from the #EXTINF string.

        Name - text after the first comma outside the quotes (commas inside the name
        are saved). If it is empty, the tvg-name attribute is taken. If he is not there either -
        returns "" (the caller will substitute Channel_N).

        Supports:
          #EXTINF:-1,Channel name
          #EXTINF:-1 tvg-id="..." group-title="News, Sport",Channel name
          #EXTINF:0.5,Title, with, commas
          #EXTINF:-1 tvg-name="Name", (no name after comma)
        """
        body = line
        if ":" in body:
            body = body.split(":", 1)[1]
        comma = IPTVScanner._find_extinf_name_comma(body)
        attrs = body if comma < 0 else body[:comma]
        if comma >= 0:
            name = body[comma + 1:].strip()
            if name:
                return name
        m = _EXTINF_TVG_NAME_RE.search(attrs)
        if m:
            return (m.group(1) if m.group(1) is not None else m.group(2)).strip()
        return ""

    def fetch_playlist_channels(self, url: str) -> List[Channel]:
        """Parses an M3U/M3U8 playlist, extracting only the URL and channel name.

        Rules (common for M3U and M3U8):
          * lines starting with '#' are comments and tags (#EXTINF, #EXTGRP,
            #EXTVLCOPT, #KODIPROP, #EXTM3U with attributes, etc.) - are skipped;
          * a non-empty string without a '#' at the beginning is a URL;
          * the channel name is taken from the nearest preceding #EXTINF.

        The body is read by chunks with hard ceilings (MAX_PLAYLIST_BYTES,
        MAX_PLAYLIST_CHANNELS, MAX_PLAYLIST_LINE_LENGTH): resp.text/splitlines()
        would materialize the entire answer, and the large/trash playlist would be exhausted
        memory before we had time to reject it; so the body is readable
        chunks with a hard limit before decoding and splitlines.
        """
        try:
            # verify=True explicitly: playlists can be hosted on https hosting, and
            # the TLS policy should be fixed here, not
            # requests are implied by default. The CA source is described in
            # block "TLS trust store" at the beginning of the module.
            resp = self._get_session().get(url, timeout=20, verify=True, stream=True)
            try:
                resp.raise_for_status()

                # Quick screening by Content-Length (if the server sent it):
                # don’t waste time downloading something that is obviously too large
                # bodies. This is only optimization - the server may not send
                # headline or lie, so the main defense is the counter
                # byte below.
                declared_len = resp.headers.get("Content-Length")
                if declared_len is not None:
                    try:
                        if int(declared_len) > MAX_PLAYLIST_BYTES:
                            logger.error(
                                "Playlist %s declares Content-Length=%s > limit %d — "
                                "download aborted before reading the body",
                                _redact_url(url), declared_len, MAX_PLAYLIST_BYTES,
                            )
                            return []
                    except ValueError:
                        # Non-numeric Content-Length - simply ignored.
                        pass

                # We read the body in chunks, with a hard byte limit on
                # sum of unpacked bytes (requests transparent
                # decompresses gzip/deflate into iter_content - zip bomb too
                # caught by this counter).
                body_chunks: List[bytes] = []
                total_bytes = 0
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_PLAYLIST_BYTES:
                        logger.error(
                            "Playlist %s exceeds the size limit "
                            "(read %d bytes, limit %d) — download aborted",
                            _redact_url(url), total_bytes, MAX_PLAYLIST_BYTES,
                        )
                        return []
                    body_chunks.append(chunk)
            finally:
                try:
                    resp.close()
                except Exception:
                    logger.debug(
                        "Failed to close the playlist response", exc_info=True,
                    )

            raw = b"".join(body_chunks)

            # We decode the playlist body ourselves, and not through resp.text.
            #
            # 1) Lack of charset in Content-Type. requests in this
            #    case sets resp.encoding = "ISO-8859-1" (archaic
            #    defaults to RFC 2616 for text/*). For M3U this is not true:
            #    providers write UTF-8 and Cyrillic in channel names
            #    turns into trash. We respect resp.encoding only if
            #    the server EXPLICITLY specified charset in the Content-Type; otherwise we work
            #    as with UTF-8.
            # 2) utf-8-sig instead of utf-8 - cuts off the leading UTF-8 BOM.
            #    Files with BOM (Notepad, part of playlist generators) without
            #    this is given by the first line "\ufeff#EXTM3U": it is not
            #    starts with '#' and is therefore interpreted as a URL →
            #    phantom Channel_0 and shift of all real channels by
            # one. utf-8-sig is regular utf-8 with auto-detection
            #    BOM: if there is no BOM, the behavior is identical to utf-8.
            #
            # Checking `"charset=" in content_type` (substring in
            # header) is needed because resp.encoding itself does not distinguish
            # "charset declared explicitly" from "requests substituted ISO-8859-1
            # default for text/*". Both situations give non-None
            # resp.encoding; the difference is only in Content-Type.
            content_type = (resp.headers.get("Content-Type") or "").lower()
            declared = (resp.encoding or "").lower().replace("-", "").replace("_", "")
            if "charset=" in content_type and declared and declared != "utf8":
                # `declared` non-empty => resp.encoding not None; explicit check
                # you need mypy (type resp.encoding - Optional[str]).
                encoding = resp.encoding or "utf-8-sig"
            else:
                encoding = "utf-8-sig"
            try:
                text = raw.decode(encoding, errors="replace")
            except LookupError:
                logger.warning(
                    "Playlist %s: unknown declared encoding %r — "
                    "falling back to UTF-8",
                    _redact_url(url), resp.encoding,
                )
                text = raw.decode("utf-8-sig", errors="replace")

            new_channels: List[Channel] = []
            count = 0
            last_extinf_name: Optional[str] = None
            truncated = False

            for raw_line in text.splitlines():
                if count >= MAX_PLAYLIST_CHANNELS:
                    truncated = True
                    break

                line = raw_line.strip()

                # We skip empty lines and comments/tags,
                # but we still extract the name from #EXTINF.
                if not line or line.startswith("#"):
                    if line.upper().startswith("#EXTINF"):
                        last_extinf_name = self._parse_extinf_name(line)
                    continue

                # Cutoff based on the length of one line: without it “one line without
                # transfers of 10 MB" would remain valid (from the point of view
                # MAX_PLAYLIST_BYTES) playlist with one “channel”, URL
                # which would fly to requests as the request address.
                if len(line) > MAX_PLAYLIST_LINE_LENGTH:
                    logger.warning(
                        "Playlist %s: skipping an over-long line "
                        "(%d chars, limit %d) — likely a malformed entry",
                        _redact_url(url), len(line), MAX_PLAYLIST_LINE_LENGTH,
                    )
                    continue

                # A non-empty string without '#' is a URL.
                name = last_extinf_name or f"Channel_{count}"
                new_channels.append(Channel(name, line))
                count += 1
                last_extinf_name = None

            if truncated:
                logger.warning(
                    "Playlist %s has more than %d channels — only the first %d "
                    "were kept (the rest were discarded to keep the scanner "
                    "responsive)",
                    _redact_url(url), MAX_PLAYLIST_CHANNELS,
                    MAX_PLAYLIST_CHANNELS,
                )

            return new_channels

        except requests.RequestException as e:
            logger.error(
                "Error loading playlist %s: %s",
                _redact_url(url), self._shorten_request_error(e),
            )
            return []
        except Exception:
            logger.exception("Error loading playlist %s", _redact_url(url))
            return []
        finally:
            self._close_session()
        
    @property
    def thread_join_timeout(self) -> float:
        """How long is it reasonable to wait for scan_thread to complete after request_stop().

        Upper bound for one check_channel() task:
          RUNTIME.hanging_slot_wait_timeout_sec (waiting for slot)
          + self._check_channel_hard_timeout (worker budget + buffer)
        Plus RUNTIME.scan_thread_join_margin_sec margin for overhead
        shutdown/as_completed etc.

        Both components are read from the current values at the time
        call: if RUNTIME.hanging_slot_wait_timeout_sec or
        scan_timeout/watchdog_multiplier will change, this border
        will automatically increase (no manual synchronization required).
        """
        return max(
            RUNTIME.scan_thread_join_min_timeout,
            (
                RUNTIME.hanging_slot_wait_timeout_sec
                + self._check_channel_hard_timeout
                + RUNTIME.scan_thread_join_margin_sec
            ),
        )

    @property
    def _check_channel_hard_timeout(self) -> float:
        """Timeout (sec) to wait for _worker() to complete inside check_channel()."""
        return self.scan_timeout * self.thresholds.watchdog_multiplier + 3.0

    @property
    def is_scanning(self) -> bool:
        """True while scanning is active.

        Read-only wrapper over self._stop_event - see comment in __init__
        about why this is a single flag and not a pair (bool + Event).
        """
        return not self._stop_event.is_set()

    def request_stop(self) -> None:
        """Scanning stop signal."""
        self._stop_event.set()
    
    def is_stop_requested(self) -> bool:
        """True if scanning should be stopped."""
        return self._stop_event.is_set()

    def clear_stop(self) -> None:
        """Marks the start of a new scan (is_scanning becomes True)."""
        self._stop_event.clear()
        self._abandoned_total = 0
        self._hanging_soft_resets = 0
        self._last_hanging_soft_reset = 0.0
        with self._fatal_scan_lock:
            self._fatal_scan_message = None
        # Resetting cooldowns accumulated during the previous stop
        with self._cooldowns_lock:
            self._fail_cooldowns.clear()
        with self._internal_error_lock:
            self._internal_error_seen.clear()

    def reset_issue_tracking_state(self) -> None:
        """Resets per-channel-key problem/alert tracking structures.

        _fail_cooldowns and _internal_error_seen are reset to clear_stop() at startup
        each scan. _last_issue_status does not have such a reset (only pop() when
        return the channel to OK, see check_channel), so if the playlist is changed frequently
        without running scans, all three structures would accumulate alert_key ((url, name))
        channels that are no longer in any playlist. The keys do not interfere with work, but this
        Memory leak when running for a very long time.

        Call when loading a new playlist - together with alerts.clear() (see.
        _on_playlist_loaded / _on_reset_complete). clear_stop() refers to
        the life cycle of a SCAN, not a playlist."""
        with self._cooldowns_lock:
            self._fail_cooldowns.clear()
        with self._internal_error_lock:
            self._internal_error_seen.clear()
        with self._issue_log_lock:
            self._last_issue_status.clear()

    def _log_channel_issue(
        self, is_no_alert: bool, level: int, msg: str, *args, **kwargs
    ) -> None:
        """The only point of logging problems for a specific channel is inside
        check_channel(). Centralized on purpose: record suppression for
        'added/test' channels (is_no_alert, see NO_ALERT_PREFIX) are not allowed in one place
        accidentally forgetting when editing, unlike checks spread throughout the code
        `if not is_no_alert: logger....`."""
        if is_no_alert:
            return
        logger.log(level, msg, *args, **kwargs)

    def check_channel(self, channel: Channel, *,
                  bypass_cooldown: bool = False) -> ScanResult:
        """Analysis of one channel with a strict general timeout and taking into account suspended threads.

        Before starting _worker, the self._hanging_semaphore slot is captured. If the flow
        fits into hard_timeout, the slot is freed upon completion of the call. If
        hangs (for example, DNS resolve - such blocking calls using Python
        do not interrupt), the slot is occupied until the stuck thread terminates itself. When busy
        all MAX_HANGING_THREADS slots, acquire() waits no longer
        RUNTIME.hanging_slot_wait_timeout_sec.

        acquire() deliberately with a timeout: while waiting indefinitely and never
        returning network operations (dead DNS/socket without OS timeout) after
        exhaustion of slots, the scanner would stop working forever - workers would be blocked at
        acquire(), and executor.shutdown(wait=True) in scan_loop() would wait for them indefinitely
        even after "Stop". Therefore, if the expectation fails, it is immediately given up
        CONNECT_FAILED: the channel will be rechecked in the next cycle if
        time the slot will become free.
        """
        if self.is_stop_requested():
            return ScanResult(
                channel=channel,
                status=Status.CONNECT_FAILED,
                details=self.s("detail_no_data"),
                connect_reason=ConnectFailReason.CANCELLED,
            )

        key = channel.alert_key
        is_no_alert = _name_has_prefix(channel.name, self.no_alert_prefixes)
        result: List[ScanResult] = []
        abandoned = threading.Event()
        slot_released = False
        slot_lock = threading.Lock()

        # The reference to the CURRENT semaphore is captured now rather than read through
        # self._hanging_semaphore inside _release_slot(): _maybe_cleanup_hanging_locked()
        # periodically RECREATES the semaphore to get rid of slots leaked due to
        # forever stuck workers. If _release_slot() were to read the attribute again,
        # a long-hanging worker, which reached finally AFTER its re-creation, has been released
        # would be a NEW semaphore: its counter would exceed MAX_HANGING_THREADS (over-release),
        # and more checks than allowed would be performed at the same time. Release of the same
        # a semaphore that was acquire()ed eliminates this.
        semaphore = self._hanging_semaphore

        def _release_slot() -> None:
            nonlocal slot_released
            with slot_lock:
                if slot_released:
                    return
                slot_released = True
            semaphore.release()

        if not semaphore.acquire(timeout=RUNTIME.hanging_slot_wait_timeout_sec):
            with self._hanging_lock:
                current = self._hanging_count
            self._log_channel_issue(
                is_no_alert, logging.WARNING,
                "Channel %r (%s): no free check slot after %.1f s "
                "(hanging threads: %d/%d) — CONNECT_FAILED without attempting a connection",
                channel.name, _redact_url(channel.url),
                RUNTIME.hanging_slot_wait_timeout_sec,
                current, self.MAX_HANGING_THREADS,
            )
            # === Cooldown here too ===
            with self._cooldowns_lock:
                self._fail_cooldowns[key] = time.monotonic() + RUNTIME.connect_fail_cooldown_sec
            return ScanResult(
                channel, Status.CONNECT_FAILED, self.s("detail_too_many_hanging"),
                connect_reason=ConnectFailReason.HANGING_LIMIT,
            )

        if self.is_stop_requested():
            _release_slot()
            return ScanResult(
                channel=channel,
                status=Status.CONNECT_FAILED,
                details=self.s("detail_no_data"),
                connect_reason=ConnectFailReason.TIMEOUT,
            )

        now = time.monotonic()
        with self._hanging_lock:
            self._maybe_cleanup_hanging_locked(now)
        with self._cooldowns_lock:
            self._cleanup_fail_cooldowns_locked(now)
            cooldown_until = self._fail_cooldowns.get(key, 0.0)
            if now < cooldown_until and not bypass_cooldown:
                remaining = cooldown_until - now
                logger.debug(
                    "Channel %r is in cooldown for another %.1f s after CONNECT_FAILED",
                    channel.name, remaining
                )
                _release_slot()          # the slot has already been captured - release it
                return ScanResult(
                    channel, Status.CONNECT_FAILED,
                    self.s("detail_cooldown", remaining=remaining),
                    connect_reason=ConnectFailReason.COOLDOWN,
                )

        def _worker() -> None:
            # The session belongs only to this worker thread and is closed by it in finally
            # (except abandoned - see contract below).
            # Thread-local cache (self._get_session) is not used here: check_channel()
            # starts a NEW threading.Thread on each channel, threading.local dies
            # along with it, reuse between iterations is impossible, and sessions would accumulate in
            # _active_sessions to close_all_sessions() (socket leak when running for hours
            # work). Keep-alive between different channels is already weak (different hosts), so
            # the session is created and closed explicitly.
            session = requests.Session()
            session.headers.update(self.session_headers)
            try:
                if self.is_stop_requested():
                    # _worker() returns None - the result goes outside
                    # only via result.append(...) (see other threads
                    # below); _release_slot() does finally on exit.
                    result.append(ScanResult(
                        channel=channel,
                        status=Status.CONNECT_FAILED,
                        details=self.s("detail_no_data"),
                        connect_reason=ConnectFailReason.CANCELLED,
                    ))
                    return
                
                deadline = (
                    time.monotonic()
                    + self.scan_timeout * self.thresholds.watchdog_multiplier
                )
                metrics_or_early = self._scan_channel_stream(channel, deadline, session)
                if isinstance(metrics_or_early, ScanResult):
                    result.append(metrics_or_early)
                else:
                    result.append(self._classify_channel(channel, metrics_or_early))
            except requests.RequestException as e:
                # Deduplication: if “Network error...” was already written for the channel (current status
                # CONNECT_FAILED), the record is not repeated at each scan iteration (mechanism
                # _last_issue_status). Difference in exception text (Read timed out vs Connect
                # timed out) does not reset deduplication: key - (name, url), value - status
                # CONNECT_FAILED; until the status changes (or the channel returns to OK - then
                # post-processing below will delete the key itself), nothing is written to the log.
                with self._issue_log_lock:
                    already_logged = (
                        self._last_issue_status.get(key) == Status.CONNECT_FAILED
                    )
                    if not already_logged:
                        self._last_issue_status[key] = Status.CONNECT_FAILED
                if not already_logged:
                    self._log_channel_issue(
                        is_no_alert, logging.WARNING,
                        "Network error for channel %r (%s): %s",
                        channel.name, _redact_url(channel.url), e,
                    )
                result.append(ScanResult(
                    channel, Status.CONNECT_FAILED, self._shorten_request_error(e),
                    connect_reason=ConnectFailReason.NETWORK,
                ))
            except Exception as e:
                if self.is_stop_requested():
                    # Not an internal error, but a regular custom Stop: abort_active_responses()
                    # closed r from another thread, iter_content() threw ValueError/
                    # ChunkedEncodingError not caught in except requests.RequestException (depends
                    # from urllib3 version). The result is still overwritten in CONNECT_FAILED below
                    # (see is_stop_requested()), but log it as "Internal analyzer error"
                    # with traceback would be misleading when parsing logs.
                    result.append(ScanResult(
                        channel, Status.CONNECT_FAILED, self.s("detail_no_data"),
                        connect_reason=ConnectFailReason.CANCELLED,
                    ))
                else:
                    with self._internal_error_lock:
                        first_seen = key not in self._internal_error_seen
                        if first_seen:
                            self._internal_error_seen.add(key)
                    self._log_channel_issue(
                        is_no_alert, logging.ERROR,
                        "Internal analyzer error for channel %r (%s)%s",
                        channel.name, channel.url,
                        "" if first_seen else " (traceback suppressed: already logged for this channel during this scan)",
                        exc_info=first_seen,
                    )
                    result.append(ScanResult(
                        channel, Status.INTERNAL_ERROR, self._shorten_request_error(e)
                    ))
            finally:
                # The slot is ALWAYS freed up here, regardless of the abandoned decision at the moment
                # checks. If when "not abandoned" the release was executed only by the main thread
                # after t.join(hard_timeout), a narrow window would appear: the worker has already passed finally
                # with abandoned=False, and t.is_alive() in the main thread also returned True - main
                # the thread would decide "abandoned" and not release the slot, relying on the finally worker,
                # who has already worked it out without release. The slot would be lost forever. Unconditional
                # (idempotent due to slot_released) release here guarantees exactly one
                # release() in any order of events.
                if abandoned.is_set():
                    # CONTRACT: when abandoned.is_set() it is FORBIDDEN to call session.close() and any
                    # other operations with requests.Session/socket - the thread is considered hung (usually
                    # inside getaddrinfo or a blocking read), and such a call itself may hang.
                    # The session remains alive with the thread; in self._active_sessions it is not
                    # registered, so there is no accumulation.
                    with self._hanging_lock:
                        self._hanging_count = max(0, self._hanging_count - 1)
                else:
                    try:
                        session.close()
                    except Exception:
                        logger.debug("Failed to close requests.Session", exc_info=True)
                _release_slot()

        hard_timeout = self._check_channel_hard_timeout
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=hard_timeout)

        if t.is_alive():
            abandoned.set()
            with self._hanging_lock:
                self._hanging_count += 1
                self._abandoned_total += 1
                current = self._hanging_count
                total_abandoned = self._abandoned_total
            self._log_channel_issue(
                is_no_alert, logging.WARNING,
                "Channel %r (%s) exceeded the hard timeout of %.1f s — CONNECT_FAILED "
                "(hanging threads: %d/%d)",
                channel.name, _redact_url(channel.url),
                hard_timeout, current, self.MAX_HANGING_THREADS,
            )
            # The slot is NOT freed - finally is responsible for it inside _worker()
            if total_abandoned >= self._max_abandoned_threads():
                logger.error(
                    "Too many hung network threads (%d) — further scanning stopped",
                    total_abandoned,
                )
                self._report_fatal_scan_error(
                    self.s("detail_hanging_abandoned", count=total_abandoned)
                )
            result_obj = ScanResult(
                channel, Status.CONNECT_FAILED, "Hard timeout / DNS",
                connect_reason=ConnectFailReason.TIMEOUT,
            )
        else:
            _release_slot()
            if result:
                result_obj = result[0]
            else:
                result_obj = ScanResult(channel, Status.INTERNAL_ERROR, "No result from worker")

        if self.is_stop_requested() and result_obj.status != Status.CONNECT_FAILED:
            result_obj = ScanResult(
                channel=channel,
                status=Status.CONNECT_FAILED,
                details=self.s("detail_no_data"),
                connect_reason=ConnectFailReason.TIMEOUT,
            )

        # === Cooldown after CONNECT_FAILED / reset on success ===
        # We do not set cooldown if the scan has already been asked to stop -
        # otherwise a quick Stop→Start turns normal channels into "Cooldown"
        # due to closed sessions/aborted requests.
        if result_obj.status == Status.CONNECT_FAILED and not self._stop_event.is_set():
            with self._cooldowns_lock:
                self._fail_cooldowns[key] = time.monotonic() + RUNTIME.connect_fail_cooldown_sec
        elif result_obj.status in OK_STATUSES:
            with self._cooldowns_lock:
                self._fail_cooldowns.pop(key, None)

        is_ok = result_obj.status in OK_STATUSES
        with self._issue_log_lock:
            if is_ok:
                self._last_issue_status.pop(key, None)
                log_issue = False
            elif self._last_issue_status.get(key) == result_obj.status:
                log_issue = False
            else:
                self._last_issue_status[key] = result_obj.status
                log_issue = True

        if not is_ok:
            if log_issue:
                self._log_channel_issue(
                    is_no_alert, logging.INFO,
                    "Channel %r → %s | %s%s",
                    channel.name, self.s(result_obj.status), result_obj.details,
                    f" | connect_reason={result_obj.connect_reason.value}" if result_obj.connect_reason else ""
                )
        else:
            logger.debug(
                "Channel %r → %s | %s%s",
                channel.name, self.s(result_obj.status), result_obj.details,
                f" | connect_reason={result_obj.connect_reason.value}" if result_obj.connect_reason else ""
            )

        return result_obj

    def _read_deadline_reached(
            self, start_time: float, deadline: float,
            analyzer: "TSStreamAnalyzer", now: Optional[float] = None,
        ) -> bool:
        """With a small real channel bitrate (for example, background stream ~200 kbps)
        few TS packets arrive for a fixed scan_timeout, and periodic
        the PMT section may not enter the window by pure chance, although the channel is working.

        If by the end of scan_timeout neither the video PID nor a valid PMT section has been caught
        (the classification would inevitably go to ERRORS "PMT not received"), the channel is given
        additional time until the hard deadline (scan_timeout *
        watchdog_multiplier). This stock has already been reserved by watchdog in
        check_channel() (hard_timeout and thread_join_timeout are calculated from scan_timeout *
        watchdog_multiplier).

        For channels for which PMT/video is determined normally within scan_timeout,
        it has no effect.
        """
        if now is None:
            now = time.monotonic()
        if now >= deadline:
            return True
        if now - start_time < self.scan_timeout:
            return False
        metrics = analyzer.metrics
        pmt_still_pending = not metrics.video_pids and not metrics.pmt_parsed
        return not pmt_still_pending

    def _scan_channel_stream(
            self, channel: Channel, deadline: float, session: requests.Session
        ) -> Union[ScanMetrics, ScanResult]:
        th = self.thresholds
        analyzer = TSStreamAnalyzer()
        ts_buffer = bytearray()
        total_bytes = 0     # total bytes read
        read_count = 0      # number of readings (for debug log)
        last_packet_time: Optional[float] = None
        # Maximum pause between two consecutive readings. Reading size
        # is small (READ_PACKET_COUNT), so pause = real delivery delay, not
        # buffer filling time.
        max_chunk_gap = 0.0
        gap_violations = 0   # The number of times the pause has exceeded th.max_allowed_gap_sec (see _gap_is_error).
        garbage_bytes = 0

        start_time = time.monotonic()
        first_data_time: Optional[float] = None
        # Read-timeout must simultaneously:
        #   * be > th.max_allowed_gap_sec + 1.0 so that the max_chunk_gap metric has time
        #     record a one-time excess and bring the matter to the ERRORS classification
        #     (not ReadTimeout -> CONNECT_FAILED). Otherwise flow with rare but not
        #     deadly pauses between chunks would always fall into CONNECT_FAILED,
        #     bypassing the more informative ERRORS with details on the gap;
        #   * cover your own cycle deadline (scan_timeout * watchdog_multiplier),
        #     otherwise the request would terminate before the loop could exit
        #     _read_deadline_reached() - that is, on a slow channel with a large
        #     scan_timeout ReadTimeout would fire first and “eat up” the result;
        #   * stay strictly less than hard_timeout in check_channel()
        #     (scan_timeout * watchdog_multiplier + 3.0) so that the worker thread has time
        # return ScanResult rather than being discarded as abandoned.
        read_timeout = max(
            th.max_allowed_gap_sec + 1.0,
            float(self.scan_timeout) * self.thresholds.watchdog_multiplier,
        )

        r = None
        try:
            fetcher = StreamFetcher(session, self.session_headers)
            r = fetcher.open_stream(channel.url, 2.0, read_timeout)
            # Register BEFORE raise_for_status() and before the first iter_content():
            # the window between open_stream() and the start of reading can also be
            # long (headings may not arrive immediately), and Stop in this window
            # must be able to interrupt the worker.
            self.register_response(r)
            try:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=TS_PACKET_SIZE * READ_PACKET_COUNT):
                    if self.is_stop_requested():
                        return ScanResult(
                            channel=channel,
                            status=Status.CONNECT_FAILED,
                            details=self.s("detail_no_data"),
                            connect_reason=ConnectFailReason.CANCELLED,
                        )
                    now = time.monotonic()
                    if self._read_deadline_reached(start_time, deadline, analyzer, now):
                        break
                    size = len(chunk)
                    if not size:
                        continue
                    if first_data_time is None:
                        first_data_time = now
                    if last_packet_time is not None:
                        gap = now - last_packet_time
                        if gap > max_chunk_gap:
                            max_chunk_gap = gap
                        if gap > th.max_allowed_gap_sec:
                            gap_violations += 1
                    last_packet_time = now
                    total_bytes += size
                    read_count += 1

                    ts_buffer.extend(chunk)

                    # --- buffer overgrowth protection ---
                    # If the buffer has become too large, leave only the tail,
                    # sufficient to search for synchronization. One rare O(N)
                    # instead of many small dels from the beginning.
                    if len(ts_buffer) > MAX_TS_BUFFER:
                        keep = TS_PACKET_SIZE * 4
                        garbage_bytes += len(ts_buffer) - keep
                        del ts_buffer[:-keep]

                    sync_pos = find_ts_sync(ts_buffer)
                    if sync_pos < 0:
                        if len(ts_buffer) > TS_PACKET_SIZE * 3:
                            discard = len(ts_buffer) - TS_PACKET_SIZE * 2
                            if discard > 0:
                                garbage_bytes += discard
                            del ts_buffer[:-TS_PACKET_SIZE * 2]
                        if self._read_deadline_reached(start_time, deadline, analyzer):
                            break
                        continue

                    # The main package parsing cycle.
                    #
                    # IMPORTANT (performance/GIL): packets are not cut from the beginning of the buffer by
                    # one (`del ts_buffer[:TS_PACKET_SIZE]` is O(len(ts_buffer)) memmove on
                    # EACH packet when reading READ_PACKET_COUNT packets at a time). With parallel
                    # scanning this could monopolize the GIL for a long time in the thread, where
                    # a resink has occurred (the buffer is already bloated with garbage); the rest of the threads couldn't keep up
                    # would read its sockets, and a live streaming server has the right to drop packets
                    # for a lagging client. From the outside it looks like a simultaneous series
                    # "random" cc_err on the entire group of channels at once, although the reason is in the scanner, and
                    # not in the sources.
                    #
                    # Therefore, the `pos` cursor is used without a physical shift per packet:
                    # the buffer is compacted (`del ts_buffer[:pos]`) ONCE after parsing everything
                    # chunka.
                    pos = sync_pos
                    if sync_pos > 0:
                        garbage_bytes += sync_pos
                    buf_len = len(ts_buffer)
                    while buf_len - pos >= TS_PACKET_SIZE:
                        if self.is_stop_requested():
                            return ScanResult(
                                channel=channel,
                                status=Status.CONNECT_FAILED,
                                details=self.s("detail_no_data"),
                                connect_reason=ConnectFailReason.CANCELLED,
                            )

                        if ts_buffer[pos] != 0x47:
                            resync_pos = find_resync_pos(ts_buffer, pos + 1)
                            if resync_pos < 0:
                                remaining = buf_len - pos
                                if remaining > TS_PACKET_SIZE:
                                    tail_keep = TS_PACKET_SIZE - 1
                                    garbage_bytes += remaining - tail_keep
                                    pos = buf_len - tail_keep
                                break
                            garbage_bytes += resync_pos - pos
                            pos = resync_pos
                            continue

                        # Normal package
                        packet = bytes(ts_buffer[pos:pos + TS_PACKET_SIZE])
                        pos += TS_PACKET_SIZE
                        analyzer.process_packet(packet)

                    if pos > 0:
                        del ts_buffer[:pos]

                    if self._read_deadline_reached(start_time, deadline, analyzer):
                        break
            
            finally:
                self.unregister_response(r)
            
        finally:
            if r is not None:
                try:
                    r.close()
                except Exception:
                    logger.debug("Failed to close HTTP response", exc_info=True)

        end_time = time.monotonic()
        duration = ((end_time - first_data_time) if first_data_time is not None
                    else (end_time - start_time))
        metrics = analyzer.finalize()
        metrics.garbage_bytes = garbage_bytes
        metrics.gap_violations = gap_violations

        if duration < th.min_scan_duration_sec or total_bytes < th.min_total_bytes:
            return ScanResult(channel, Status.CONNECT_FAILED, self.s("detail_no_data"),
                               connect_reason=ConnectFailReason.NO_DATA)

        # New NOT_TS check instead of dead sync-ratio
        if (total_bytes > th.min_total_bytes_for_garbage_check and
                garbage_bytes / total_bytes > th.max_garbage_ratio):
            return ScanResult(channel, Status.NOT_TS, self.s(
                "detail_garbage",
                garbage=garbage_bytes,
                total=total_bytes,
                ratio=garbage_bytes / total_bytes,
            ))

        useful_bytes = max(0, (metrics.total_ts_packets - metrics.null_packets) * TS_PACKET_SIZE)  # Useful bitrate TS, no NULL packets PID 0x1FFF.
        bitrate_kbps = (useful_bytes * 8 / 1000) / duration if duration > 0 else 0.0

        metrics.duration = duration
        metrics.bitrate_kbps = bitrate_kbps
        metrics.details_short = self.s("detail_bitrate", br=bitrate_kbps)
        metrics.max_chunk_gap = max_chunk_gap
        logger.debug(
            "Analyzed channel %r: duration=%.2fs ts=%d bitrate=%.1f kbps "
            "video=%s audio=%s scrambled_video=%d/%d pes_headers=%d/%d pus "
            "pes_scrambled=%d "
            "cc_errors=%d tei=%d max_chunk_gap=%.3fs gap_violations=%d reads=%d "
            "pat=%s pmt=%s pmt_pid_pkts=%d pmt_sections=%d/%d "
            "garbage=%d (%.1f%%)",
            channel.name, metrics.duration, metrics.total_ts_packets,
            metrics.bitrate_kbps,
            sorted(metrics.video_pids.items()), sorted(metrics.audio_pids.items()),
            metrics.scrambled_video, metrics.total_video_packets,
            metrics.pes_header_count, metrics.video_pus_count,
            metrics.pes_scrambled_count, sum(metrics.continuity_errors_by_pid.values()),
            metrics.tei_packets, metrics.max_chunk_gap, gap_violations, read_count,
            metrics.pat_parsed, metrics.pmt_parsed,
            metrics.pmt_pid_packets, metrics.pmt_sections_valid, metrics.pmt_sections_seen,
            metrics.garbage_bytes,
            (metrics.garbage_bytes / total_bytes * 100) if total_bytes else 0.0,
        )
        return metrics

    def _check_stuffing(self, metrics: ScanMetrics) -> Optional[str]:
        """Sign of an 'almost empty' video stream: there are very few packets, but the declared
        bitrate is high (typical case for a stream full of stuffing packets
        instead of a real video). General check for MPEG2 and H.264/HEVC branches,
        so that the condition does not have to be duplicated in each of them."""
        th = self.thresholds
        if (metrics.total_video_packets < th.max_video_packets_for_stuffing_check and
                metrics.bitrate_kbps > th.min_bitrate_for_stuffing_check_kbps and
                metrics.video_payload_bytes < th.max_payload_bytes_for_stuffing_check):
            return self.s(
                "detail_few_video",
                pkts=metrics.total_video_packets,
                bytes=metrics.video_payload_bytes
            )
        return None
        
    def _codec_prefix(self, video_pids: Dict[int, int]) -> str:
        is_mpeg2 = any(st in MPEG2_STREAM_TYPES for st in video_pids.values())
        is_h264  = any(st in H264_STREAM_TYPES for st in video_pids.values())
        is_hevc  = any(st in HEVC_STREAM_TYPES for st in video_pids.values())
        if is_mpeg2 and not (is_h264 or is_hevc):
            return "MPEG2 | "
        if is_h264 and not is_hevc and not is_mpeg2:
            return "H.264 | "
        if is_hevc and not is_h264 and not is_mpeg2:
            return "HEVC | "
        if is_mpeg2 or is_h264 or is_hevc:
            parts = []
            if is_mpeg2:
                parts.append("MPEG2")
            if is_h264:
                parts.append("H.264")
            if is_hevc:
                parts.append("HEVC")
            return "+".join(parts) + " | "
        return ""

    def _useful_video_kbps(self, metrics: ScanMetrics) -> float:
        """Video bitrate is ES without padding (filler-NAL for H.264/HEVC, zero stuffing for MPEG-2)."""
        duration = max(metrics.duration, self.thresholds.min_scan_duration_sec)
        useful = max(0, metrics.video_es_bytes - metrics.video_filler_bytes)
        return useful * 8 / 1000 / duration

    def _video_filler_ratio(self, metrics: ScanMetrics) -> float:
        if metrics.video_es_bytes <= 0:
            return 0.0
        return metrics.video_filler_bytes / metrics.video_es_bytes

    def _is_video_filler_padded(self, metrics: ScanMetrics) -> bool:
        """Video PID clogged filler-NAL: transport bitrate is high, but useful
        data (slices/SEI/parameters) - units to tens of kbit/s. This is the way out
        encoder without input signal (black/empty frame, finished to CBR).

        Previously, such a stream received OK: filler was also taken into account in video_payload_bytes,
        and in bitrate_kbps, and checking the picture (modern_vcl_count >= 2) only
        I was convinced that VCL-NALs existed at all, but did not look at their volume.
        The condition is double (filler share AND small useful bitrate), so that honest
        A CBR channel with a filler did not receive a false NO_PICTURE.
        """
        th = self.thresholds
        if (metrics.video_es_bytes <= 0
                or metrics.total_video_packets < th.min_video_packets_for_picture_check):
            return False
        if self._video_filler_ratio(metrics) < th.min_video_filler_ratio:
            return False
        useful_kbps = self._useful_video_kbps(metrics)
        if metrics.mpeg2_width and metrics.mpeg2_height:
            bits_per_px_sec = useful_kbps * 1000 / (metrics.mpeg2_width * metrics.mpeg2_height)
            return bits_per_px_sec < th.min_useful_mpeg2_bits_per_pixel_sec
        return useful_kbps < th.min_useful_video_kbps

    def _audio_fill_ratio(self, metrics: ScanMetrics) -> float:
        es = sum(metrics.audio_es_bytes_by_pid.values())
        if es <= 0:
            return 0.0
        return sum(metrics.audio_fill_bytes_by_pid.values()) / es

    def _is_audio_fill_only(self, metrics: ScanMetrics) -> bool:
        """True if ALL declared audio tracks are AAC, and each consists of
        fill/silence (packets are coming, there is a bitrate, but there is no sound).

        If there are non-AAC tracks (MP2/AC-3/...), fill is determined from them
        it’s impossible - then we carefully return False (it’s better to remain silent).
        At least one “live” track (for example, eng with a dead rus) is also False.
        """
        th = self.thresholds
        if not metrics.audio_pids:
            return False
        duration = max(metrics.duration, th.min_scan_duration_sec)
        for pid, stype in metrics.audio_pids.items():
            if stype not in AAC_STREAM_TYPES:
                return False
            es = metrics.audio_es_bytes_by_pid.get(pid, 0)
            if es < th.min_audio_es_bytes_for_fill_check:
                return False
            fill = metrics.audio_fill_bytes_by_pid.get(pid, 0)
            if fill / es < th.min_audio_fill_ratio:
                return False
            if (es - fill) * 8 / 1000 / duration >= th.min_useful_audio_kbps:
                return False
        return True

    def _tei_ratio(self, metrics: ScanMetrics) -> float:
        total = metrics.total_ts_packets - metrics.null_packets
        return metrics.tei_packets / total if total > 0 else 0.0

    def _is_tei_bad(self, metrics: ScanMetrics) -> bool:
        return self._tei_ratio(metrics) > self.thresholds.max_tei_ratio

    def _tei_suffix(self, metrics: ScanMetrics) -> str:
        """\" TEI:n\" for details (same as cc_err); empty if there were no TEI packets."""
        return self.s("detail_tei", tei=metrics.tei_packets) if metrics.tei_packets else ""

    def _is_audio_scrambled(self, metrics: ScanMetrics) -> bool:
        """All audio packages are scrambled (with clear video there is no sound). On
        rare in practice, but the check is trivial and does not give false positives:
        the NO_AUDIO branch is reached only after eliminating all video problems."""
        th = self.thresholds
        if not metrics.audio_pids or metrics.total_audio_packets < th.min_audio_packets_for_clear_check:
            return False
        return (metrics.scrambled_audio / metrics.total_audio_packets
                >= th.min_scrambled_ratio_for_no_card)

    def _classify_transport_only(
        self, channel: Channel, metrics: ScanMetrics, ok_status: Status,
        cc_pids: Dict[int, int], codec_prefix: str, ok_suffix: str = "",
    ) -> ScanResult:
        """Classification by transport layer only (bitrate, pauses, CC, TEI)
        for channels whose contents the scanner cannot check: obviously
        scrambled (OK*) and with an unparsable video codec (OK**)."""
        th = self.thresholds
        if metrics.bitrate_kbps < self.min_bitrate_kbps:
            return ScanResult(channel, Status.DEAD, f"{codec_prefix}{metrics.details_short}",
                              metrics=metrics)
        continuity_errors = sum(metrics.continuity_errors_by_pid.get(pid, 0) for pid in cc_pids)
        if (
            metrics.bitrate_kbps < th.error_bitrate_kbps
            or self._is_gap_error(metrics, continuity_errors)
            or self._is_cc_bad(metrics, continuity_errors)
            or self._is_tei_bad(metrics)
        ):
            details = self.s(
                "detail_errors", codec=codec_prefix, br=metrics.bitrate_kbps,
                gap=metrics.max_chunk_gap, cc=continuity_errors,
            ) + self._tei_suffix(metrics)
            return ScanResult(channel, Status.ERRORS, details, metrics=metrics)
        details = f"{codec_prefix}{metrics.details_short}{ok_suffix}"
        if continuity_errors > 0:
            details += self.s("detail_ok_cc", cc=continuity_errors)
        details += self._tei_suffix(metrics)
        return ScanResult(channel, ok_status, details, metrics=metrics)

    def _log_unsupported_video(self, channel: Channel, types: str) -> None:
        """Once per session per channel: video in a codec that is not analyzed."""
        key = channel.alert_key
        with self._issue_log_lock:
            if key in self._unsupported_logged:
                return
            self._unsupported_logged.add(key)
        logger.info(
            "Channel %r: video stream_type %s is not analyzed (unsupported codec); "
            "only transport-level checks applied (status OK**)",
            channel.name, types,
        )

    def _is_radio(self, metrics: ScanMetrics) -> bool:
        th = self.thresholds
        return (
            metrics.pmt_parsed
            and bool(metrics.audio_pids)
            and not metrics.video_pids
            and metrics.total_ts_packets > th.min_ts_packets_for_radio_check
        )

    def _is_no_audio(self, metrics: ScanMetrics, has_video_pids: bool) -> bool:
        """Status.NO_AUDIO ("No sound") - mirror case to RADIO: video is normal
        (the branch is checked in _classify_channel only after excluding all
        priority video problems - DEAD/ERRORS/MODULE_HUNG/"picture breaks"/
        NO_PICTURE, otherwise the channel would receive OK), but there would be no sound at all. Sound counts
        missing in two cases: (a) PMT does not declare a single audio track;
        (b) the track was declared, but not a single packet was received along it during the entire scan
        (audio-ES is dead, for example the audio part of the encoder is broken). For the viewer both
        cases are the same - silence. It's not "audio partially scrambled"
        (audio_clear=False for non-empty audio_pids and total_audio_packets>0): that
        the situation is separate and is not deliberately touched upon here.

        Safety-net: if PMT announces an ES stream not recognized as either video or
        known sound code (AUDIO_STREAM_TYPES / DVB_AUDIO_DESCRIPTOR_TAGS), neither
        obviously non-sound (data/teletext/subtitles - KNOWN_NON_AUDIO_STREAM_TYPES /
        DVB_NON_AUDIO_DESCRIPTOR_TAGS), this may be sound in an unfamiliar codec
        (MPEG-H 3D Audio, DRA, Opus-in-TS, proprietary muxers). List of famous
        codes cannot be exhaustive, so if the stream is unidentified NO_AUDIO
        not exhibited: it is better to remain silent when unsure than to falsely report
        problem on a working channel."""
        return (
            has_video_pids
            and metrics.pmt_parsed
            and not metrics.unclassified_pids
            and (
                not metrics.audio_pids
                or metrics.total_audio_packets == 0
                # there are tracks and packets are coming, but these are just fill bytes (silence)
                or self._is_audio_fill_only(metrics)
                # there are tracks and packets are coming, but everything is scrambled
                or self._is_audio_scrambled(metrics)
            )
        )

    def _scrambled_ratio(self, metrics: ScanMetrics) -> float:
        if not metrics.total_video_packets:
            return 0.0
        return metrics.scrambled_video / metrics.total_video_packets

    def _is_effectively_scrambled(self, metrics: ScanMetrics, has_video_pids: bool) -> bool:
        th = self.thresholds
        ratio = self._scrambled_ratio(metrics)
        return (
            (has_video_pids
             and metrics.total_video_packets > th.min_video_packets_for_scramble_check
             and ratio >= th.min_scrambled_ratio_for_no_card)
            or
            (metrics.pes_scrambled_count > th.min_pes_scrambled_count
             and metrics.total_video_packets > th.min_video_packets_for_pes_scramble_check)
        )

    def _is_audio_clear(self, metrics: ScanMetrics) -> bool:
        th = self.thresholds
        if not metrics.audio_pids or metrics.total_audio_packets < th.min_audio_packets_for_clear_check:
            return False
        return (metrics.scrambled_audio / metrics.total_audio_packets) < th.max_scrambled_audio_ratio_for_clear

    def _detect_no_picture(
        self,
        metrics: ScanMetrics,
        has_video_pids: bool,
        is_mpeg2: bool,
        is_modern: bool,
    ) -> Tuple[bool, str]:
        """Returns (no_picture, details)."""
        if not has_video_pids:
            return False, ""
        th = self.thresholds

        if (metrics.total_video_packets >= th.min_video_packets_for_empty_payload_check
                and metrics.video_payload_bytes < th.min_video_payload_bytes):
            return True, self.s(
                "detail_video_no_data",
                bytes=metrics.video_payload_bytes,
                pkts=metrics.total_video_packets,
            )

        if is_mpeg2:
            if (metrics.total_video_packets >= th.min_video_packets_for_picture_check
                    and (metrics.mpeg2_picture_count < th.min_picture_codes
                         or metrics.mpeg2_slice_count < th.min_slice_codes)):
                return True, self.s(
                    "detail_mpeg2_codes",
                    pic=metrics.mpeg2_picture_count,
                    slice=metrics.mpeg2_slice_count,
                    seq=metrics.mpeg2_sequence_count,
                    gop=metrics.mpeg2_gop_count,
                    pes=metrics.pes_header_count,
                    pus=metrics.video_pus_count,
                )
            if self._is_video_filler_padded(metrics):
                return True, self.s(
                    "detail_video_filler",
                    ratio=self._video_filler_ratio(metrics) * 100,
                    useful=self._useful_video_kbps(metrics),
                    total=metrics.bitrate_kbps,
                )
            stuffing = self._check_stuffing(metrics)
            if stuffing:
                return True, stuffing
        elif is_modern:
            if (metrics.total_video_packets >= th.min_video_packets_for_picture_check
                    and metrics.modern_vcl_count < th.min_modern_vcl_nals):
                return True, self.s(
                    "detail_modern_nals",
                    vcl=metrics.modern_vcl_count,
                    param=metrics.modern_param_count,
                    pes=metrics.pes_header_count,
                    pus=metrics.video_pus_count,
                )
            if self._is_video_filler_padded(metrics):
                return True, self.s(
                    "detail_video_filler",
                    ratio=self._video_filler_ratio(metrics) * 100,
                    useful=self._useful_video_kbps(metrics),
                    total=metrics.bitrate_kbps,
                )
            stuffing = self._check_stuffing(metrics)
            if stuffing:
                return True, stuffing

        return False, ""

    def _is_partial_scramble(
        self, metrics: ScanMetrics, has_video_pids: bool, scrambled_ratio: float
    ) -> bool:
        th = self.thresholds
        return (
            has_video_pids
            and metrics.total_video_packets > th.min_video_packets_for_scramble_check
            and th.min_scrambled_ratio_for_partial <= scrambled_ratio < th.min_scrambled_ratio_for_no_card
        )

    def _payload_looks_encrypted(self, metrics: ScanMetrics) -> bool:
        """True if there is enough PUS on the video PID, but there are almost no PES headers.

        In MPEG-TS video is always packed in PES (00 00 01 Ex at the beginning
        payload_unit_start). If there are PUS flags, but these headers are not -
        the payload is not structured like MPEG, but looks like a cipher.
        This is a typical CI/CAM failure: the module has reset transport_scrambling_control
        (packets “as if in the open”), but the payload was never decrypted.
        A broken encoder does not allow this: the muxer writes PES regardless of
        whether the personnel gathered inside.
        """
        th = self.thresholds
        if metrics.video_pus_count < th.min_video_pus_for_pes_check:
            return False
        return (
            metrics.pes_header_count / metrics.video_pus_count
            <= th.max_pes_header_ratio_for_encrypted_payload
        )

    def _is_module_hung(
        self,
        metrics: ScanMetrics,
        has_video_pids: bool,
        effectively_scrambled: bool,
        no_picture: bool,
        partial_scramble: bool,
    ) -> bool:
        """MODULE_HUNG - the picture is not assembled, and there is a signal that CI/CAM is to blame.

        Two independent signs (one is enough):

        1. partial_scramble (scrambled_ratio in the range
           [min_scrambled_ratio_for_partial, min_scrambled_ratio_for_no_card)
           - see _is_partial_scramble). A typical picture of a module that
           decrypts every other time: some video packets go undecrypted.

        2. transport_scrambling_control is already 0 (the channel is “open” according to the TS header),
           but the payload remained encrypted: there are no PES headers when
           a sufficient number of PUS - see _payload_looks_encrypted. It happens
           when CAM/CI hangs and resets scrambling flags, do not
           decrypting the payload.

        The case of “enough video data has arrived, there is no picture, scrambling
        no, but the PES headers are in place" is NOT included here - this is a broken encoder /
        incorrect PID, not CI. It is classified separately through
        _is_garbled_video() (Status.ERRORS)."""
        if not has_video_pids or effectively_scrambled or not no_picture:
            return False
        if partial_scramble:
            return True
        return self._payload_looks_encrypted(metrics)

    def _is_garbled_video(
        self,
        metrics: ScanMetrics,
        has_video_pids: bool,
        effectively_scrambled: bool,
        no_picture: bool,
        partial_scramble: bool,
    ) -> bool:
        """“The picture breaks” - there is enough video data (in terms of volume and number of packets),
        The PES headers are in place (the muxer is live), but there is no valid image in them, and this
        NOT related to scrambling: neither effectively_scrambled nor
        partial_scramble, nor "payload as cipher" (_payload_looks_encrypted).

        Unlike MODULE_HUNG, there is no signal that CI/CAM is to blame: most often it is
        broken frames on the source side (curve encoder, transcoder) or incorrect
        specific video PID/codec. The case differs from NO_PICTURE in volume
        data: NO_PICTURE is a “blank/black screen” (not enough bytes), and here there are bytes
        There are a lot of PES, but the frames from them do not add up.

        There is no separate status, so as not to multiply statuses and colors: in _classify_channel
        this is the general Status.ERRORS (the color is the same as other errors), the only difference is
        text details."""
        th = self.thresholds
        return (
            has_video_pids
            and not effectively_scrambled
            and not partial_scramble
            and no_picture
            and metrics.video_payload_bytes >= th.min_video_payload_bytes
            and metrics.total_video_packets >= th.min_video_packets_for_picture_check
            and metrics.pes_header_count >= th.min_pes_headers_for_garbled
            and not self._payload_looks_encrypted(metrics)
            # A lot of bytes and PES are in place, but the bytes are filler: they are “empty” and not
            # “frames are beating”, so let it remain NO_PICTURE.
            and not self._is_video_filler_padded(metrics)
        )

    def _is_cc_bad(self, metrics: ScanMetrics, continuity_errors: int) -> bool:
        """continuity_error - almost always a lost TS packet; for compressed video
        (especially H.264/HEVC with long chains of P/B frames) even a small number
        losses are noticeable to the eye as a jerk/freezing of the frame to the next reference point.
        The threshold should catch “already twitching”, and not just “the flow has collapsed”.

        max_continuity_errors=4 - “floor of noise”, not ceiling of disaster: one-time
        cc_err within these limits are not considered a channel error (of the same order as
        gap_single_violation_max_cc_err=2, which _is_gap_error distinguishes "single
        blip"). A tolerance is added above the floor, proportional to the actual
        scan duration (~max_continuity_errors_per_sec events per second) so that
        long scans (scan_timeout more than the default 4 s) were not unfair
        stricter, and short ones softer. When scan_timeout=4 s and
        max_continuity_errors_per_sec=1.0 the final tolerance is 4, that is
        continuity_errors=5 already gives ERRORS.
        """
        th = self.thresholds
        duration = max(metrics.duration, th.min_scan_duration_sec)
        allowed = max(
            th.max_continuity_errors,
            int(th.max_continuity_errors_per_sec * duration),
        )
        return (
            continuity_errors > allowed
            or (
                metrics.total_video_packets > th.min_video_packets_for_cc_ratio_check
                and continuity_errors / metrics.total_video_packets > th.max_continuity_error_ratio
            )
        )

    def _is_gap_error(self, metrics: ScanMetrics, continuity_errors: int) -> bool:
        """True if max_chunk_gap should be considered a real channel error.

        Single exceedance of th.max_allowed_gap_sec without noticeable loss
        TS packets (low cc_err) - a typical picture of one TCP retransmit
        with minimal RTO: delivery was delayed for a second or two, but the data
        we still got there, the stream didn’t degrade. This shouldn't happen on its own
        throw the channel into ERRORS. But if there were pauses above the threshold in one scan
        several - this already looks like a really unstable channel (see.
        Thresholds.gap_violations_error_threshold), and then flag the error
        regardless of cc_err. If there is exactly one excess, additionally
        we play it safe: if it does arrive with a noticeable loss of packets
        (cc_err above gap_single_violation_max_cc_err) - also considered an error,
        because then it is no longer a “pure” self-healing blip."""
        th = self.thresholds
        if metrics.max_chunk_gap <= th.max_allowed_gap_sec:
            return False
        if metrics.gap_violations >= th.gap_violations_error_threshold:
            return True
        return continuity_errors > th.gap_single_violation_max_cc_err

    def _classify_known_scrambled_channel(
        self, channel: Channel, metrics: ScanMetrics
    ) -> ScanResult:
        """Simplified classification for obviously scrambled channels
        (name starts with "scrambled"/"added/scrambled", not case sensitive
        - see _name_has_prefix). Scrambling is expected here and
        in itself is not a sign of a problem, so branches NO_CARD/MODULE_HUNG/
        NO_PICTURE (and their thresholds min_scrambled_ratio_for_*, etc.) for such
        channels are not involved at all. Only the transport layer is checked:
        PMT and video PID must be present (without this there is no "success"
        meaning - RADIO for such channels is also not considered, even if
        formally only audio is visible), the bitrate is not lower than the minimum, the stream is not
        torn (gap/CC/TEI). If everything is ok - Status.OK_SCRAMBLED
        (“OK*”): formal success with obviously encrypted video.
        CONNECT_FAILED and NOT_TS do not apply here - they are cut off earlier,
        before calling _classify_channel, and are applied equally for all
        channels regardless of this special case."""
        has_video_pids = bool(metrics.video_pids)
        codec_prefix = self._codec_prefix(metrics.video_pids)

        if not has_video_pids or not metrics.pmt_parsed:
            details = self.s(
                "detail_scrambled_no_pmt_or_video",
                pmt=metrics.pmt_parsed, video=has_video_pids,
            )
            return ScanResult(channel, Status.ERRORS, details, metrics=metrics)

        return self._classify_transport_only(
            channel, metrics, Status.OK_SCRAMBLED, metrics.video_pids, codec_prefix,
        )

    def _classify_channel(self, channel: Channel, metrics: ScanMetrics) -> ScanResult:
        """Classification of the channel according to accumulated metrics.

        Status priority (first one to trigger wins):
          1. RADIO
          2. NO_CARD / MODULE_HUNG (by audio_clear)
          3. ERRORS (PMT missing)
          4. MODULE_HUNG (partial_scramble OR payload encrypted at TSC=0)
          5. ERRORS (“the picture breaks” - PES is in place, there are no frames)
          6. NO_PICTURE
          7. DEAD
          8. ERRORS (bitrate / gap / cc / TEI)
          9. NO_AUDIO (video is ok, but no sound at all)
          10. OK
        """
        if _name_has_prefix(channel.name, self.known_scrambled_prefixes):
            return self._classify_known_scrambled_channel(channel, metrics)

        th = self.thresholds
        video_pids = metrics.video_pids
        has_video_pids = bool(video_pids)

        # There is video, but in a codec that the scanner does not understand (MPEG-4 Visual,
        # VVC, AVS...): you cannot assert “error” - we only check the transport
        # and set OK** (“not checked deeply”). Comes before RADIO: otherwise TV channel
        # with incomprehensible video and normal sound, it would be mistaken for radio.
        if not has_video_pids and metrics.pmt_parsed and metrics.unsupported_video_pids:
            types = ", ".join(
                f"0x{st:02X}" for st in sorted(set(metrics.unsupported_video_pids.values()))
            )
            self._log_unsupported_video(channel, types)
            return self._classify_transport_only(
                channel, metrics, Status.OK_UNSUPPORTED, metrics.unsupported_video_pids, "",
                ok_suffix=self.s("detail_unsupported_video", types=types),
            )

        is_mpeg2 = any(st in MPEG2_STREAM_TYPES for st in video_pids.values())
        is_h264  = any(st in H264_STREAM_TYPES for st in video_pids.values())
        is_hevc  = any(st in HEVC_STREAM_TYPES for st in video_pids.values())
        is_modern = is_h264 or is_hevc
        codec_prefix = self._codec_prefix(video_pids)

        continuity_errors = sum(
            metrics.continuity_errors_by_pid.get(pid, 0) for pid in video_pids
        )
        scrambled_ratio = self._scrambled_ratio(metrics)
        effectively_scrambled = self._is_effectively_scrambled(metrics, has_video_pids)
        no_picture, no_picture_details = self._detect_no_picture(
            metrics, has_video_pids, is_mpeg2, is_modern
        )
        partial_scramble = self._is_partial_scramble(metrics, has_video_pids, scrambled_ratio)
        module_hung = self._is_module_hung(
            metrics, has_video_pids, effectively_scrambled, no_picture, partial_scramble
        )
        garbled = self._is_garbled_video(
            metrics, has_video_pids, effectively_scrambled, no_picture, partial_scramble
        )
        cc_bad = self._is_cc_bad(metrics, continuity_errors)
        tei_bad = self._is_tei_bad(metrics)
        audio_clear = self._is_audio_clear(metrics) if has_video_pids else False
        no_audio = self._is_no_audio(metrics, has_video_pids)

        # branch - which priority branch worked (see list above), only
        # for the debug log below; does not affect the classification result itself.
        if self._is_radio(metrics):
            status = Status.RADIO
            branch = "1_radio"
            details = self.s("detail_bitrate", br=metrics.bitrate_kbps)

        elif effectively_scrambled or (
            not has_video_pids
            and metrics.scrambled_any_pid > th.scrambled_all_packets_threshold
            and metrics.total_ts_packets > th.min_ts_packets_for_full_scramble_check
        ):
            # audio_clear reflects only audio codes recognized by the scanner
            # (see _is_audio_clear/parse_pmt_section). If PMT contains
            # unknown ES stream (metrics.unclassified_pids - potentially
            # sound in an unrecognized codec, see _is_no_audio), we do not have
            # direct grounds for asserting that audio is “unclean” - it’s more correct
            # get MODULE_HUNG (specific diagnosis "looks like a failure
            # CAM/CI module"), and no less informative NO_CARD. Unlike
            # NO_AUDIO here is not a question of "false alarm on a working
            # channel vs silence" - the channel has already been recognized as problematic in any case
            # (video is scrambled), we are only talking about which of the two
            # "problem" statuses more accurately describe what is happening.
            if has_video_pids and (audio_clear or metrics.unclassified_pids) and metrics.pmt_parsed:
                status = Status.MODULE_HUNG
                branch = "2_no_card_module_hung_audio_clear"
                ratio_pct = scrambled_ratio * 100
                if audio_clear:
                    audio_part = f"audio clear ({metrics.scrambled_audio}/{metrics.total_audio_packets})"
                else:
                    audio_part = "audio: unrecognized codec, assumed not scrambled"
                details = (
                    f"{codec_prefix}video scrambled {metrics.scrambled_video}/"
                    f"{metrics.total_video_packets} ({ratio_pct:.0f}%), {audio_part}"
                )
            else:
                status = Status.NO_CARD
                branch = "2_no_card"
                if has_video_pids:
                    details = self.s(
                        "detail_no_card_video",
                        codec=codec_prefix,
                        scr=metrics.scrambled_video,
                        total=metrics.total_video_packets,
                        pes=metrics.pes_scrambled_count,
                    )
                else:
                    details = self.s(
                        "detail_no_card_all",
                        scr=metrics.scrambled_any_pid,
                        total=metrics.total_ts_packets,
                    )

        elif not has_video_pids and not metrics.pmt_parsed:
            status = Status.ERRORS
            branch = "3_errors_pmt_missing"
            details = self.s(
                "detail_pmt_missing",
                dur=metrics.duration,
                pkts=metrics.total_ts_packets,
                pat=metrics.pat_parsed,
                pmt=len(metrics.pmt_pid_to_program),
                pmt_pkts=metrics.pmt_pid_packets,
                pmt_valid=metrics.pmt_sections_valid,
                pmt_sections=metrics.pmt_sections_seen,
            )

        elif module_hung:
            status = Status.MODULE_HUNG
            if partial_scramble:
                branch = "4_module_hung_partial"
                ratio_pct = scrambled_ratio * 100
                details = f"{codec_prefix}{no_picture_details} (mix scrambled: {ratio_pct:.1f}%)"
            else:
                branch = "4_module_hung_encrypted_payload"
                details = f"{codec_prefix}" + self.s(
                    "detail_module_hung_encrypted",
                    picture=no_picture_details,
                )

        elif garbled:
            status = Status.ERRORS
            branch = "5_errors_garbled"
            details = f"{codec_prefix}{self.s('detail_garbled', details=no_picture_details)}"

        elif no_picture:
            status = Status.NO_PICTURE
            branch = "6_no_picture"
            details = f"{codec_prefix}{no_picture_details}"

        elif metrics.bitrate_kbps < self.min_bitrate_kbps:
            status = Status.DEAD
            branch = "7_dead_low_bitrate"
            details = f"{codec_prefix}{metrics.details_short}"

        elif (
            metrics.bitrate_kbps < th.error_bitrate_kbps
            or self._is_gap_error(metrics, continuity_errors)
            or cc_bad
            or tei_bad
        ):
            status = Status.ERRORS
            branch = "8_errors_bitrate_gap_cc"
            details = self.s(
                "detail_errors",
                codec=codec_prefix,
                br=metrics.bitrate_kbps,
                gap=metrics.max_chunk_gap,
                cc=continuity_errors,
            ) + self._tei_suffix(metrics)

        elif no_audio:
            status = Status.NO_AUDIO
            branch = "9_no_audio"
            # _is_no_audio() combines two different cases (see its docstring):
            # (a) PMT did not declare a single audio track; (b) path
            # declared, but not a single packet was received for it during the entire scan.
            # For the viewer, both are silence, so the status is the same, but
            # The reason is different and the diagnostic address differs for it.
            # We distinguish in details - both in the logs and in the UI table.
            if metrics.audio_pids:
                # The declared PIDs are in a stable order, so that two
                # successive redraws of the same line are not
                # gave visually different text due to different order
                # keys in dict.
                pids_str = ", ".join(str(p) for p in sorted(metrics.audio_pids))
                if self._is_audio_scrambled(metrics):
                    audio_detail = self.s(
                        "detail_no_audio_scrambled",
                        pids=pids_str,
                        scr=metrics.scrambled_audio / metrics.total_audio_packets * 100,
                    )
                elif metrics.total_audio_packets > 0:
                    # packets are coming (otherwise “no packets” would work) → fill/silence
                    audio_detail = self.s(
                        "detail_no_audio_fill",
                        pids=pids_str,
                        fill=self._audio_fill_ratio(metrics) * 100,
                    )
                else:
                    audio_detail = self.s("detail_no_audio_no_packets", pids=pids_str)
            else:
                audio_detail = self.s("detail_no_audio_not_declared")
            details = f"{codec_prefix}{metrics.details_short}{audio_detail}"
            if continuity_errors > 0:
                details += self.s("detail_ok_cc", cc=continuity_errors)
            details += self._tei_suffix(metrics)

        else:
            status = Status.OK
            branch = "10_ok"
            details = f"{codec_prefix}{metrics.details_short}"
            if continuity_errors > 0:
                details += self.s("detail_ok_cc", cc=continuity_errors)
            details += self._tei_suffix(metrics)

        logger.debug(
            "Classify %r: branch=%s status=%s bitrate=%.1fkbps gap=%.3fs "
            "cc_err=%d audio_cc_err=%d tei=%d scrambled_ratio=%.2f effectively_scrambled=%s partial_scramble=%s "
            "audio_clear=%s no_audio=%s no_picture=%s module_hung=%s garbled=%s "
            "pes_headers=%d/%d pus pmt_parsed=%s has_video=%s",
            channel.name, branch, status.value,
            metrics.bitrate_kbps, metrics.max_chunk_gap,
            continuity_errors,
            sum(metrics.continuity_errors_by_pid.get(pid, 0) for pid in metrics.audio_pids),
            metrics.tei_packets, scrambled_ratio, effectively_scrambled, partial_scramble,
            audio_clear, no_audio, no_picture, module_hung, garbled,
            metrics.pes_header_count, metrics.video_pus_count,
            metrics.pmt_parsed, has_video_pids,
        )

        return ScanResult(channel, status, details, metrics=metrics)

    def launch_vlc(self, url: str) -> bool:
        if not Path(self.vlc_path).exists():
            messagebox.showerror(
                self.s("msg_error_title"),
                self.s("msg_vlc_not_found", path=self.vlc_path)
            )
            return False
        try:
            subprocess.Popen([self.vlc_path, url])
            return True
        except Exception as e:
            messagebox.showerror(self.s("msg_vlc_error"), str(e))
            return False


class ScanController:
    """Thin controller for scan/download playlist lifecycle.

    Owns generation tokens and a link to the scan worker stream to
    The GUI did not mix UI logic with background task coordination. GUI subscribes
    to results through callbacks (update_channel_row, etc.), and start/stop
    and cutting off obsolete callbacks go through this layer.
    """

    def __init__(self, scanner: "IPTVScanner") -> None:
        self.scanner = scanner
        self.scan_generation = GenerationToken()
        self.load_generation = GenerationToken()
        self.scan_thread: Optional[threading.Thread] = None

    def bump_scan_generation(self) -> GenerationToken:
        self.scan_generation = self.scan_generation.bump()
        return self.scan_generation

    def invalidate_scan_generation(self) -> GenerationToken:
        """Cuts off all callbacks of the current scan that are already in the Tk queue.

        Call (from GUI thread) when Stop/pause due to loss of connection/
        at the beginning of recovery / closing the window - and not just at the next Start
        (start_scan_thread raises generation itself)."""
        return self.bump_scan_generation()

    def invalidate_load_generation(self) -> GenerationToken:
        """Cuts off the result of a playlist loading that is still in progress."""
        self.load_generation = self.load_generation.bump()
        return self.load_generation

    def start_scan_thread(self, target: Callable[..., None]) -> GenerationToken:
        """Resets the stop flag, raises generation and starts the daemon thread."""
        self.scanner.clear_stop()
        gen = self.bump_scan_generation()
        self.scan_thread = threading.Thread(target=target, daemon=True)
        self.scan_thread.start()
        return gen

    def join_scan_thread(self) -> bool:
        """True if the thread has terminated (or was not present)."""
        t = self.scan_thread
        if t is None or not t.is_alive():
            return True
        t.join(timeout=self.scanner.thread_join_timeout)
        return not t.is_alive()

class _VpnSessionWatch:
    """Unified VPN session monitoring state for health monitor.

    Decides that the VPN session has changed or is lost, not by “naked” ifIndex:
    Windows RAS adapters reuse ifIndex when reconnecting the same
    profile, and the local IP is usually saved too (the server issues an address from the pool
    by account). With a quick manual Disable→Connect ifIndex comparison
    would not notice anything, although Windows has already demolished everything tied to the interface
    routes (our /32 to the udpxy host and to the DNS VPN adapter); the scan would continue
    fall into ConnectTimeout until soft path recovery is triggered, and the VPN does not
    would be transferred to the "System" status (_vpn_owned_by_us would remain True for
    someone else's session).

    The decision is made based on four independent criteria, in descending order
    reliability:

      1. The adapter with our ifIndex is not in GetAdaptersAddresses → invalidate.
         Typically in the middle of a RAS-handshake: the kernel demolished the old interface object,
         a new one has not yet been created;
      2. OperStatus of the adapter is not Up → invalidate;
      3. 64-bit traffic counters (InOctets/OutOctets, GetIfEntry2/
         MIB_IF_ROW2) rolled back relative to the peak accumulated over
         session → invalidate. Counters are reset when the object is recreated
         interface in the kernel even with the same ifIndex - this is a direct observation
         “we have a new interface”;
      4. ALL of our /32s disappeared from the routing table with a live adapter →
         the session is rescheduled or the routes are moved differently; the reaction is the same.

    Signs 1 and 2 catch short sessions in the handshake phase: when polling once every
    RUNTIME.vpn_watch_poll_interval_sec (default 250 ms, see
    _network_health_loop) at least one tick is guaranteed to fall within the interval
    length from a second (L2TP/SSTP). Signs 3 and 4 catch "quiet" re-creations without
    intermediate Down.

    Tri-state: get_interface_status() and get_interface_counters() return None
    when reading through iphlpapi fails (the single API error is "don't know" and not
    "session changed"); vpn.routes_snapshot() can also return None. Such
    The tick is skipped entirely, the miss counter is not affected.

    Protection against false positives:
      * comparison is made with the peak of counters per session (prev_peak), and not with
        previous tick: driver bounce 1% down will not work, but reset to 0
        - always, without thresholds and without “two samples in a row”. The peak is reset
        only after confirmed invalidation (see reset());
      * route checking (feature 4) is enabled via ROUTES_SETTLE_SEC after
        their settings: between the helper response and the visible entry in the table there is
        gap, and precheck/connect_and_route themselves are briefly reinstalled
        routes;
      * for sign 4 you need alive == 0 for total > 0; missing PART of the routes -
        rather “someone erased the record” than demolition of the interface, and requires
        MISS_STREAK_TO_FIRE consecutive “bad” ticks.
    """

    # How many consecutive monitor ticks should “all our routes” show
    # dead" (sign 4) before invalidating the session.
    MISS_STREAK_TO_FIRE = 3
    # Grace after setting the routes, during which their absence
    # is not considered an anomaly.
    ROUTES_SETTLE_SEC = 2.5

    def __init__(self) -> None:
        # The object is read from the health monitor thread and written from the GUI thread
        # and from background workers (precheck, reconnect), so the state
        # kept under lock and key: without it, the monitor tick could already be seen
        # updated list of routes along with the old timestamp
        # and count the newly delivered /32 as “lost”.
        self._lock = threading.RLock()
        # Generation surveillance. Increments only in reset()/adopt() -
        # that is, for each transition “we observe another session (or even
        # We don’t see anything).” check() removes my_gen under lock, then
        # goes to iphlpapi without a lock, then - if _gen has changed - it knows
        # that the snapshot peak_*/miss_streak is already out of date, and silently exits, not
        # writing back and not returning reason based on old peaks.
        #
        # The specific race this closes: between snapshots
        # peaks and writing them back could be worked by reset()/adopt() -
        # for example, the user manually reconnected the VPN, the GUI did
        # adopt() with new sessions, and still holding the monitor in my hands
        # old peak_in=10000. Fresh new session counters (in=50) in this
        # case mistakenly went to "counters_reset" while alive
        # ifIndex=37 (RAS reuses the index) - false invalidate
        # over the newly accepted system session.
        self._gen: int = 0
        self._session: Optional[Any] = None
        self._routes: List[Tuple[str, int]] = []
        self._routes_since: float = 0.0
        self._miss_streak: int = 0
        self._peak_if_index: Optional[int] = None
        self._peak_in_octets: Optional[int] = None
        self._peak_out_octets: Optional[int] = None

    # ---------------- session status ----------------

    def reset(self) -> None:
        """Full reset - with invalidate, sleep, network loss, status change
        to “don’t rely on VPN.” We also forget the routes: they are either already
        are dead or will be reinstalled by the next precheck."""
        with self._lock:
            self._gen += 1
            self._session = None
            self._routes = []
            self._routes_since = 0.0
            self._miss_streak = 0
            self._peak_if_index = None
            self._peak_in_octets = None
            self._peak_out_octets = None

    def adopt(self, session: Optional[Any]) -> None:
        """Accept the session as current, without considering it a shift."""
        with self._lock:
            self._gen += 1
            self._session = session
            self._miss_streak = 0
            # New session - the old counter peak belongs to a different one
            # (or not yet existing) interface, reset: the following
            # check() will set the base point again.
            self._peak_if_index = None
            self._peak_in_octets = None
            self._peak_out_octets = None

    # ---------------- mirror of our routes ----------------

    # set_routes() does NOT touch _gen: routes are a separate mirror with their own
    # versioned (_routes_since, see _check_routes), and its update is not
    # should invalidate in-flight check of the same session.
    def set_routes(self, routes: Optional[Any], if_index_fallback: Optional[int] = None) -> None:
        """Remember the routes that we (via the helper) set.

        `routes` — list [[ip, if_index, gateway], ...] from the response
        vpn.connect_and_route(). The format can be parsed tolerably: element, from
        which ip and if_index are not retrieved is simply ignored -
        the mirror should not be able to drop the monitor.
        """
        parsed: List[Tuple[str, int]] = []
        for item in (routes or []):
            try:
                ip = str(item[0])
                idx = int(item[1]) if len(item) > 1 and item[1] is not None else None
            except (TypeError, ValueError, IndexError):
                continue
            if idx is None:
                idx = if_index_fallback
            if idx is None:
                continue
            try:
                # We don’t let garbage into the mirror: count_alive_routes() anyway
                # will filter such records from total, but then total is silent
                # would disagree with what is shown in the log.
                ipaddress.IPv4Address(ip)
            except (ipaddress.AddressValueError, ValueError):
                continue
            parsed.append((ip, int(idx)))
        with self._lock:
            self._routes = parsed
            self._routes_since = time.monotonic()
            self._miss_streak = 0
        logger.debug("VPN watch: tracking %d of our routes", len(parsed))

    def routes(self) -> List[Tuple[str, int]]:
        """A copy of our routes mirror [(ip, if_index), ...]."""
        with self._lock:
            return list(self._routes)

    # ---------------- actual check ----------------

    def check(self, cur: Any) -> Optional[str]:
        # Contract: cur is not None. Caller(_poll_vpn_health_tick and
        # _run_intentional_l2_reset) handles the case separately
        # session is None (observation reset via reset()) and before check()
        # doesn't get him. If in the future a caller appears ready to transfer
        # None, processing needs to be added exactly there - expected here
        # real VpnSession.
        with self._lock:
            self._session = cur
            my_gen = self._gen
            routes = list(self._routes)
            routes_since = self._routes_since
            peak_if_index = self._peak_if_index
            peak_in = self._peak_in_octets
            peak_out = self._peak_out_octets

        if vpn is not None:
            # Signs 1-2: the adapter is missing or its OperStatus is not Up.
            try:
                status = vpn.get_interface_status(cur.if_index)
            except Exception:
                logger.debug("get_interface_status() failed", exc_info=True)
                status = None
            if status == "missing":
                with self._lock:
                    if self._gen != my_gen:
                        return None
                    self._miss_streak = 0
                logger.warning(
                    "VPN adapter (ifIndex=%s) vanished from "
                    "GetAdaptersAddresses while relied upon — invalidating",
                    cur.if_index,
                )
                return "adapter_missing"
            if status == "down":
                with self._lock:
                    if self._gen != my_gen:
                        return None
                    self._miss_streak = 0
                logger.warning(
                    "VPN adapter (ifIndex=%s) OperStatus is not Up while "
                    "relied upon — invalidating",
                    cur.if_index,
                )
                return "adapter_down"
            # status in ("up", None): either the adapter is definitely alive or not
            # managed to read the status (tri-state “I don’t know”) - in both
            # In cases, we move on to the remaining characteristics.

            # Symptom 3: Interface traffic counters have rolled back.
            try:
                counters = vpn.get_interface_counters(cur.if_index)
            except Exception:
                logger.debug("get_interface_counters() failed", exc_info=True)
                counters = None
            if counters is not None:
                invalidate = False
                with self._lock:
                    if self._gen != my_gen:
                        # While we were outside the lock, reset()/adopt() had already
                        # switched the monitoring state to another (or
                        # no) session. Our image peak_* describes
                        # outdated state: compare fresh ones with it
                        # counters are not allowed (will give false counters_reset,
                        # if ifIndex is reused), and write peak_*
                        # You can’t go back either (it’s just been erased
                        # installed new database from adopt()/reset()).
                        # The next tick will start from a clean state.
                        return None
                    if peak_if_index != cur.if_index:
                        # First observation of counters for this ifIndex
                        # (new session or just turned on this
                        # check) - there is nothing to compare with, we just put
                        # base point.
                        self._peak_if_index = cur.if_index
                        self._peak_in_octets = counters.in_octets
                        self._peak_out_octets = counters.out_octets
                    elif (
                        (peak_in is not None and counters.in_octets < peak_in)
                        or (peak_out is not None and counters.out_octets < peak_out)
                    ):
                        self._miss_streak = 0
                        invalidate = True
                        # We deliberately do not touch the peak here: it is reset
                        # only via adopt()/reset() after confirmed
                        # invalidation (see class docstring).
                    else:
                        new_peak_in = (
                            max(peak_in, counters.in_octets)
                            if peak_in is not None else counters.in_octets
                        )
                        new_peak_out = (
                            max(peak_out, counters.out_octets)
                            if peak_out is not None else counters.out_octets
                        )
                        if new_peak_in != peak_in or new_peak_out != peak_out:
                            self._peak_in_octets = new_peak_in
                            self._peak_out_octets = new_peak_out
                if invalidate:
                    logger.warning(
                        "VPN interface traffic counters went backwards on "
                        "ifIndex=%s (InOctets %s -> %s, OutOctets %s -> %s) "
                        "— the kernel interface object was recreated; "
                        "invalidating session",
                        cur.if_index, peak_in, counters.in_octets,
                        peak_out, counters.out_octets,
                    )
                    return "counters_reset"

        # Sign 4: our /32 routes. Own race protection -
        # comparison of _routes_since taken in the same snapshot above.
        return self._check_routes(cur, routes, routes_since)

    def _check_routes(self, cur: Any, routes: List[Tuple[str, int]],
                       routes_since: float) -> Optional[str]:
        if not routes or vpn is None:
            return None
        if (time.monotonic() - routes_since) < self.ROUTES_SETTLE_SEC:
            return None
        
        # Pre-check: if set_routes() has already worked since our
        # snapshot in check(), we do not spend ~1 ms on Win32 table reading,
        # the result of which will still be discarded by the final
        # post check below.
        #
        # This is ONLY optimization: correctness is guaranteed by post-checking
        # under the lock after the physical photograph (at the end of the method), and she
        # remains the only source of truth. Here we are just narrowing down
        # a window in which we do obviously useless work.
        with self._lock:
            if self._routes_since != routes_since:
                return None
        
        try:
            snap = vpn.routes_snapshot()
        except Exception:
            logger.debug("routes_snapshot() failed", exc_info=True)
            snap = None
        if snap is None:
            # We didn’t read the table - the tick was skipped, we don’t touch the streak:
            # “I don’t know” should not be accumulated as “bad”.
            return None
        alive, total = vpn.count_alive_routes(routes, snap)
        if total == 0:
            return None
        if alive > 0:
            with self._lock:
                self._miss_streak = 0
            return None

        with self._lock:
            # While the check was underway, the routes could have been reinstalled
            # (precheck/soft recovery) - then the result is no longer relevant.
            if self._routes_since != routes_since:
                return None
            self._miss_streak += 1
            streak = self._miss_streak
            if streak >= self.MISS_STREAK_TO_FIRE:
                self._miss_streak = 0
        if streak < self.MISS_STREAK_TO_FIRE:
            logger.debug(
                "All %d of our VPN routes missing (streak %d/%d, ifIndex=%s)",
                total, streak, self.MISS_STREAK_TO_FIRE, cur.if_index,
            )
            return None
        logger.warning(
            "All %d of our /32 routes vanished while VPN adapter is still up "
            "(ifIndex=%s, local_ip=%s) — the RAS tunnel was almost certainly "
            "re-established on the same ifIndex; invalidating session",
            total, cur.if_index, cur.local_ip or "<not assigned>",
        )
        return "our_routes_vanished"


class RecoveryState:
    """Unified storage of ScannerGUI recovery/connectivity state.

    Composite conditions of the form `_internet_down or _recovery_in_progress or not
    _vpn_relied_upon` are written once, as named predicates, not
    duplicated by code. Device:
      * fields are grouped by LIFETIME (modes / VPN session / episode /
        disposable flags) and not by place of use;
      * compound conditions - predicates: in one place it is written what it means
        “higher priority recovery is in progress”, etc.;
      * __slots__: a typo in the field name when writing gives an AttributeError, not
        silently starts a new attribute.

    The class only stores state: WHO sets the flags and WHEN determines
    ScannerGUI handlers (_on_internet_lost, _on_vpn_session_invalidated, etc.).

    Threads: simple field assignment atomically under GIL (background workers write in
    `vpn_owned_by_us`). Read-modify-write
    `bump_epoch()` is executed only from the GUI thread (all call points are
    event handlers going through root.after).
    """

    __slots__ = (
        "epoch",
        "internet_down", "recovery_in_progress",
        "path_recovery_in_progress", "path_recovery_deferred",
        "path_recovery_epoch", "path_recovery_reason", "path_recovery_last_mono",
        "vpn_relied_upon", "vpn_owned_by_us",
        "soft_recovery_attempted", "connect_fail_batch_streak",
        "lock",
        "intentional_network_reset", "intentional_reset_kind",
        "intentional_reset_epoch", "intentional_reset_deadline",
    )

    def __init__(self) -> None:
        # ── Generation of attempts to restore connectivity ──────────────────
        # Monotonically growing. Any new event (network/VPN disappeared,
        # network restored, closing the window) bumps it - background threads
        # (VPN retry cycle, delayed guard timer, soft path recovery),
        # launched with an outdated generation, at the next check they will
        # are completed without performing unnecessary/conflicting actions.
        self.epoch: int = 0

        # ── “Modes” of connectivity ───────────────────── ─────────────────────
        # True while NetworkHealthMonitor is counting physical connectivity
        # lost (scan pause for this reason).
        self.internet_down: bool = False
        # True while there is a background attempt to reconnect the VPN after a break
        # (see _on_vpn_dropped / _vpn_reconnect_retry_worker) - for this time
        # manual start of the scan is blocked so as not to run connect_and_route
        # in parallel from two places.
        self.recovery_in_progress: bool = False

        # ── Soft recovery when the path degrades to udpxy ──────────────────
        # Separately from recovery_in_progress (the one about the lack of a network/VPN).
        self.path_recovery_in_progress: bool = False
        # True if the previous entry _path_quality_recovery_worker is forced
        # missed hygiene/route-refresh because scan_thread didn't have time
        # actually finish in thread_join_timeout (see this method and
        # _retry_deferred_path_recovery) - soft recovery does not have rights
        # touch DNS/ARP/routes while the previous scan stream is still alive.
        self.path_recovery_deferred: bool = False
        # The era and reason with which the current soft recovery started.
        # They are recorded in the GUI thread at the moment of the decision “launch” and
        # reused in deferred retry: decision made in
        # specific epoch of connectivity, and any later event
        # (network/VPN/close/wake) makes it obsolete -
        # destructive steps are required to check this.
        self.path_recovery_epoch: int = 0
        self.path_recovery_reason: str = "unknown"
        # Monotonous time of the last start of soft recovery (cooldown).
        self.path_recovery_last_mono: float = 0.0

        # ──VPN session ───────────────────────── ─────────────────────────
        # True, if the status label is now "Connected"/"System" - that is
        # The scanner really relies on this VPN tunnel right now.
        # Maintained centrally in _set_vpn_status().
        self.vpn_relied_upon: bool = False
        # True, if we raised the VPN in this session.
        self.vpn_owned_by_us: bool = False

        # ── Episode of the “dead path” (reset via reset_episode) ───
        # True after one soft recovery attempt in the current “episode”
        # dead path. Resets upon successful precheck/probe or
        # at invalidate/internet_lost. While True - repeated soft recovery
        # we don’t launch; when post-probe is repeated, only popup + idle fails.
        self.soft_recovery_attempted: bool = False
        # Consecutive batches, where all results are CONNECT_FAILED
        # (see scan_loop → soft recovery).
        self.connect_fail_batch_streak: int = 0

        # ── Controlled L2-reset (Wi-Fi soft reset / adapter restart) ─
        # True, while OUR own worker intentionally drops the physical
        # interface (_network_recovery_aggressive). While the flag is cocked,
        # loss of network and associated VPN adapter dropouts - expected
        # a consequence of the operation, not a connectivity event: the monitor does not call
        # _on_internet_lost and does not invalidate the VPN. This is a separate state
        # (see phase), and not “temporary return”: after reset, the worker must
        # perform a post-check (physical link → VPN → precheck/proxy), and
        # if the link does not return, escalate to the usual path.
        self.intentional_network_reset: bool = False
        self.intentional_reset_kind: str = ""
        # The epoch in which reset was “reserved” (for logs/diagnostics;
        # the decision to cancel is made atomically in begin_intentional_reset).
        self.intentional_reset_epoch: int = 0
        # Monotonous deadline-watchdog: after it the flag is considered removed,
        # even if the worker did not reach finally (freeze/killed thread).
        self.intentional_reset_deadline: float = 0.0
        # Lock for ATOMIC transitions between threads. Not necessary for everyone
        # reads (single assignment is atomic under GIL), and for two pairs
        # “checked → occupied”:
        # * worker: begin_intentional_reset() (is there no network/VPN-recovery →
        #     cock the flag) <-> GUI: _on_internet_lost() (is the flag not cocked?
        #     flag → internet_down=True);
        #   * GUI: _on_vpn_session_invalidated() (check + recovery_in_
        #     progress=True) <-> the same begin_intentional_reset().
        # Without it, there was a race window between check and action.
        self.lock = threading.RLock()

    # ── Operations ──────────────────────────── ────────────────────────────
    def begin_intentional_reset(
        self, epoch: Optional[int], kind: str, max_sec: float, closing: bool
    ) -> bool:
        """Atomically “reserve” the current epoch for a controlled one
        L2-reset. False - the context is already out of date (closing, changing epoch,
        network/VPN-recovery, or another reset is already in progress): destructive
        the command cannot be sent. Called by the LAST worker before
        helper's command; its pair is end_intentional_reset()
        in finally."""
        with self.lock:
            if closing:
                return False
            if epoch is not None and epoch != self.epoch:
                return False
            if self.network_recovery_active or self.intentional_reset_active:
                return False
            self.intentional_network_reset = True
            self.intentional_reset_kind = kind
            self.intentional_reset_epoch = self.epoch
            self.intentional_reset_deadline = time.monotonic() + max_sec
            return True

    def end_intentional_reset(self) -> None:
        with self.lock:
            self.intentional_network_reset = False
            self.intentional_reset_kind = ""
            self.intentional_reset_deadline = 0.0

    def bump_epoch(self) -> int:
        """Start a new era of connectivity; returns a new value.
        Only from the GUI thread (read-modify-write)."""
        self.epoch += 1
        return self.epoch

    def reset_episode(self) -> None:
        """Start the “dead path episode” with a clean slate: allow a new one
        soft recovery and reset the CONNECT_FAILED batch counter."""
        self.soft_recovery_attempted = False
        self.connect_fail_batch_streak = 0

    # ── Predicates (single place for compound conditions) ──────────────────
    @property
    def network_recovery_active(self) -> bool:
        """There is a higher priority network/VPN recovery in progress: there is no network or
        The VPN is reconnecting. Path-recovery is NOT included here."""
        return self.internet_down or self.recovery_in_progress

    @property
    def any_recovery_active(self) -> bool:
        """Any recovery, including soft path recovery. This is how it is checked
        Is it possible to start scanning / accept path-quality samples now?"""
        return (
            self.internet_down
            or self.recovery_in_progress
            or self.path_recovery_in_progress
        )

    @property
    def intentional_reset_active(self) -> bool:
        """Our own controlled L2-reset is underway. With watchdog: flag,
        Having survived its deadline, it is considered cancelled."""
        return (
            self.intentional_network_reset
            and time.monotonic() <= self.intentional_reset_deadline
        )

    @property
    def vpn_watch_inactive(self) -> bool:
        """VPN session monitoring is not relevant: there is no network, recovery is in progress,
        our own L2-reset is in progress (the VPN adapter then normally
        "sags" — this is not a session drop; the verdict is made by the post-check
        after the reset), or we do not rely on VPN at all. The inverse
        condition is "may poll VPN health / react to its drop".
        """
        return (
            self.internet_down
            or self.recovery_in_progress
            or self.intentional_reset_active
            or not self.vpn_relied_upon
        )

    @property
    def phase(self) -> str:
        """Explicit semantics on top of a set of flags (derived meaning, not
        stored - there can be no discrepancy). Priority is from the “owner”
        states to a lower priority. Not FSM: transitions still
        are specified by the flags themselves; phase is needed for logs and invariants.
        (CLOSING / WAKE_RECOVERY are not expressed here: closure lives in
        ScannerGUI._closing, and waking up is just bump epoch + guard.)"""
        if self.intentional_reset_active:
            return "INTENTIONAL_L2_RESET"
        if self.internet_down:
            return "NETWORK_DOWN"
        if self.recovery_in_progress:
            return "VPN_RECOVERY"
        if self.path_recovery_in_progress:
            return "PATH_RECOVERY"
        return "NORMAL"

    def invariant_violations(self) -> List[str]:
        """Combinations of flags that should not exist by design. Only
        diagnostics (log), the condition does not “fix”.

        The following are NOT knowingly considered a violation:
          * path_recovery_in_progress + internet_down - legal transition:
            soft recovery was already launched, and then the network actually disappeared; worker
            will see the change of era and will not take destructive steps;
          * “L2-reset in progress, internet_down=False, recovery_in_progress=False”
            - this is just the normal state in the middle of reset (now it is also
            marked intentional_network_reset).
        """
        bad: List[str] = []
        if self.internet_down and self.recovery_in_progress:
            bad.append("internet_down + recovery_in_progress")
        if self.intentional_reset_active:
            if self.internet_down:
                bad.append("intentional_reset + internet_down")
            if self.recovery_in_progress:
                bad.append("intentional_reset + recovery_in_progress")
            if not self.path_recovery_in_progress:
                bad.append("intentional_reset without path_recovery_in_progress")
        return bad

    @property
    def path_recovery_active(self) -> bool:
        """Soft path recovery still “owns” the system: the worker is working
        (in_progress) or waits for a deferred retry (deferred). Flag
        in_progress between _on_path_quality_recovery_done and start
        the repeated worker is reset at ~500 ms, so without deferred
        in this window the recovery would appear complete."""
        return self.path_recovery_in_progress or self.path_recovery_deferred

    def superseded_or_offline(self, epoch: int) -> bool:
        """For workers running under `epoch`: True if their event
        outdated (the era has changed) or there is no network - the work must be interrupted."""
        return epoch != self.epoch or self.internet_down


class ScannerGUI:
    # ── Read-only facade above self._rs (see RecoveryState) ────────────────────
    # The names are READABLE (there are many of them throughout the code, including in background threads).
    # You need to write using self._rs.<field>: assignment to a property without a setter right away
    # fails with AttributeError so that the missing entry location does not turn into
    # silent bug.
    @property
    def _net_epoch(self) -> int:
        return self._rs.epoch

    @property
    def _internet_down(self) -> bool:
        return self._rs.internet_down

    @property
    def _recovery_in_progress(self) -> bool:
        return self._rs.recovery_in_progress

    @property
    def _path_recovery_in_progress(self) -> bool:
        return self._rs.path_recovery_in_progress

    @property
    def _path_recovery_deferred(self) -> bool:
        return self._rs.path_recovery_deferred

    @property
    def _path_recovery_epoch(self) -> int:
        return self._rs.path_recovery_epoch

    @property
    def _path_recovery_reason(self) -> str:
        return self._rs.path_recovery_reason

    @property
    def _path_recovery_last_mono(self) -> float:
        return self._rs.path_recovery_last_mono

    @property
    def _vpn_relied_upon(self) -> bool:
        return self._rs.vpn_relied_upon

    @property
    def _vpn_owned_by_us(self) -> bool:
        return self._rs.vpn_owned_by_us

    @property
    def _soft_recovery_attempted(self) -> bool:
        return self._rs.soft_recovery_attempted

    @property
    def _connect_fail_batch_streak(self) -> int:
        return self._rs.connect_fail_batch_streak

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.scanner = IPTVScanner()
        self.controller = ScanController(self.scanner)
        self.tree_items: Dict[int, str] = {}
        self.sound_enabled: bool = True
        self.playlist_buttons: List[ttk.Button] = []
        self.settings_window: Optional[tk.Toplevel] = None
        # The entire recovery/connectivity state is in one object (see RecoveryState).
        self._rs = RecoveryState()
        self._vpn_apply_in_progress: bool = False
        self._closing = False
        # Coalescing queue for _post_to_gui_coalesced(): key -> (fn, args).
        self._gui_coalesced: Dict[str, Tuple[Callable[..., Any], tuple]] = {}
        self._gui_coalesced_lock = threading.Lock()
        # True while deferred _refresh_alerts() is scheduled (GUI thread).
        self._alert_refresh_scheduled = False
        self._app_stop_event = threading.Event()
        self._vpn_cleanup_lock = threading.Lock()
        self._vpn_cleanup_done = False
        # --- Network Health Monitor. Pause/recovery flags (_internet_down,
        # _vpn_relied_upon, _recovery_in_progress, ...) live in self._rs —
        # see RecoveryState and read-only facade at the beginning of the class.
        # True while a background thread confirms with an authority check
        # suspicion "VPN has disappeared" (see _confirm_vpn_dropped) - does not work
        # parallel monitor ticks to produce several such checks
        # together.
        self._vpn_drop_confirm_pending: bool = False
        # Monitor VPN session while _vpn_relied_upon: session identity +
        # our liveliness /32. Comparing only by ifIndex would skip reconnection
        # RAS to the same index - see docstring _VpnSessionWatch.
        self._vpn_watch = _VpnSessionWatch()
        # No more than once every N seconds we run PowerShell-confirm for “System”
        # VPN when the FriendlyName of the adapter does not match the profile name (otherwise
        # every monitor tick would raise get_vpn_connected).
        self._last_system_vpn_confirm_mono: float = 0.0
        # Asynchronous polling _set_vpn_status_from_reality_async(): the flag does not work
        # parallel calls from the GUI thread spawn extra PowerShell processes
        # (within ~seconds simultaneous requests are meaningless - only important
        # final state), lock closes check-and-set flag from
        # racing between two almost simultaneous calls.
        self._vpn_status_from_reality_in_progress: bool = False
        self._vpn_status_from_reality_lock = threading.Lock()
        # Monotonic time since _is_internet_connected() has been stably False;
        # None = online or debounce not yet elapsed (avoids false "No Internet"
        # on a brief full-tunnel VPN drop).
        self._internet_down_since: Optional[float] = None
        # Set once when a pause detector sees is_scanning=True; not cleared by
        # a later detector so scan can resume after ALL pause causes are gone.
        self._scan_was_running_before_pause: bool = False
        # Path-quality samples for soft recovery (see RecoveryState.path_recovery_*
        # and RUNTIME.path_quality_*); separate from recovery_in_progress.
        self._path_quality_samples: List[bool] = []  # True = elevated cc_err
        self._path_quality_lock = threading.Lock()
        # Successful-precheck cache (TTL: RUNTIME.precheck_cache_ttl_sec).
        # Invalidated via _net_epoch on any connectivity event.
        self._precheck_ok_mono: Optional[float] = None
        self._precheck_epoch: int = -1
        # True while a background precheck has not yet delivered a matching-epoch
        # callback. Changing VPN in Settings mid-precheck must not leave the UI
        # stuck disabled (see _sett_apply_vpn_result).
        self._precheck_in_progress: bool = False
        self.setup_ui()
        self._init_vpn_status_label()
        self.root.protocol("WM_DELETE_WINDOW", self._on_main_window_close)
        atexit.register(self._vpn_atexit_cleanup)
        self._pending_auto_scan = False
        # If preload is specified, we block the buttons IMMEDIATELY, synchronously, even before the first
        # window drawing. This way the user won't see them momentarily active.
        # The real unlocking will happen in _on_playlist_loaded /
        # _on_playlist_load_failed, as with normal manual loading.
        if (self.scanner.preload_playlist or "").strip():
            self._set_controls_enabled(False)

        vpn_pending = (
            self.scanner.vpn_enabled and self.scanner.vpn_connection_name and
            vpn is not None and vpn.IS_WINDOWS
        )

        if vpn_pending:
            # If VPN is enabled in the settings, a UAC request is displayed at startup (see.
            # _startup_vpn_helper_worker). Until the user responds, the scanner will not
            # must neither load the playlist nor start the scan: otherwise the scan would start without
            # raised VPN, and the response to UAC would come too late. Therefore preload
            # playlist is postponed until the attempt to raise the helper is completed (successful or
            # no - waiting for a UAC decision should not be blocked longer than the attempt itself).
            #
            # The main window remains hidden (root.withdraw() in __main__) until
            # _on_startup_vpn_wait_done: first UAC system dialog, program window -
            # only after answering it.
            #
            # self_heal_client_on_startup() starts HERE, synchronously, BEFORE
            # launch_helper() (see _startup_recovery_then_helper_worker). This is the barrier:
            # if the new helper had time to get up and register before
            # self_heal would read state.json, self_heal would see "helper is alive, but owner
            # is still empty" and deleted state.json, which may describe another, not yet
            # a disconnected VPN session from a crashed previous launch. Recovery
            # must complete completely, and only then a new helper is raised.
            self._set_controls_enabled(False)
            threading.Thread(target=self._startup_recovery_then_helper_worker, daemon=True).start()
        else:
            # VPN fallback is not used - we show the window immediately (it was
            # hidden via root.withdraw() in __main__ so that the behavior when
            # at the start it was the same both when using a VPN and without it).
            self.root.deiconify()
            # After drawing the window: if necessary, load the playlist and start the scan.
            # There is no fixed delay: resistance to network failures immediately after start
            # provides a retry with a backoff directly around the network call (see
            # _load_playlist_worker).
            self.root.after(0, self._maybe_preload_playlist)

            # Self-healing: if last time it was the program (not the user)
            # manually) connected VPN and crashed before it could disconnect, VPN
            # is switching off now. Administrator rights are not needed (as is rasdial itself);
            # is always executed, even when the checkbox is turned off - the very fact of the remaining
            # state file serves as a signal. Here (vpn_pending == False) the new helper is not
            # rises, there is no race with launch_helper(), so self_heal can be launched in
            # a separate thread, without waiting for it before preloading. Barrier (branch
            # vpn_pending above) is needed only when a new helper is about to rise.
            if vpn is not None and vpn.IS_WINDOWS:
                threading.Thread(
                    target=vpn.self_heal_client_on_startup, daemon=True
                ).start()


        # Heartbeat for sleep/hibernation detection (see _heartbeat_tick).
        # Use time.monotonic() rather than time.time(): the system clock may
        # "jump" due to time translation/NTP correction without actual sleep, and this
        # would be mistaken for exiting hibernation, in vain launching recovery (VPN reset,
        # network hygiene, scan pause). On Windows monotonic() does not depend on manual
        # and NTP time corrections, but reflects the actual past time, including
        # sleep/hibernation - a large gap between ticks reliably means sleep.
        self._last_heartbeat_mono: float = time.monotonic()
        self.root.after(RUNTIME.heartbeat_interval_ms, self._heartbeat_tick)

        # Debounce for _on_system_woke_from_sleep: both independent channels
        # detections (root.after-timer and watchdog-stream below) detect
        # same break and both schedule the call via root.after(0, ...) -
        # without the debounce, the second call would re-run hygiene/pause/
        # recovery guard on top of the one already in progress. See _on_system_woke_from_sleep.
        self._last_wake_handled_mono: float = 0.0

        # Reserve channel of the same channel, completely independent of the Tcl/Tk timer
        # detection (see _heartbeat_watchdog_loop) - safety net in case
        # if the native root.after() doesn't fire in time after hibernation.
        threading.Thread(
            target=self._heartbeat_watchdog_loop, daemon=True
        ).start()

        # Network Health Monitor: a single shadow stream that tracks and
        # loss of Internet and interruption of an already used VPN tunnel -
        # see _network_health_loop.
        self._start_network_health_monitor()

    # --- proxy generation/scan_thread → ScanController (backwards compatible) ---
    @property
    def scan_generation(self) -> GenerationToken:
        return self.controller.scan_generation

    @scan_generation.setter
    def scan_generation(self, value: GenerationToken) -> None:
        self.controller.scan_generation = value

    @property
    def load_generation(self) -> GenerationToken:
        return self.controller.load_generation

    @load_generation.setter
    def load_generation(self, value: GenerationToken) -> None:
        self.controller.load_generation = value

    @property
    def scan_thread(self) -> Optional[threading.Thread]:
        return self.controller.scan_thread

    @scan_thread.setter
    def scan_thread(self, value: Optional[threading.Thread]) -> None:
        self.controller.scan_thread = value

    def setup_ui(self) -> None:
        sc = self.scanner
        # Treeview's base row height before first fit
        # (see _fit_tree_row_height). None = not yet defined.
        self._base_rowheight: Optional[int] = None
        self.root.title(sc.s("app_title"))
        
        icon_path = base_path / "logo.ico"
        if icon_path.is_file():
            try:
                self.root.iconbitmap(default=str(icon_path))
            except tk.TclError:
                logger.warning("Failed to set window icon from %s", icon_path)

        # Basic geometry; actual height can be reduced by
        # _fit_window_to_screen() to fit the screen working area (DPI scaling /
        # taskbar on laptops), with proportional list compression
        # channels and alert areas.
        self._default_window_width = 820
        self._default_window_height = 798
        self._default_tree_rows = 22
        self._default_alert_lines = 10
        self.root.geometry(f"{self._default_window_width}x{self._default_window_height}")
        self.root.minsize(600, 500)

        main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned.pack(fill="both", expand=True, padx=8, pady=8)

        top_frame = ttk.Frame(main_paned)
        main_paned.add(top_frame, weight=4)

        top_bar = ttk.Frame(top_frame, relief="groove", borderwidth=2)
        top_bar.pack(fill="x", padx=10, pady=(8, 4))

        ttk.Button(
            top_bar, text=sc.s("btn_settings"), command=self.open_settings, width=14
        ).pack(side="left", padx=8, pady=6)

        self.sound_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            top_bar, text=sc.s("chk_sound"), variable=self.sound_var, command=self.toggle_sound
        ).pack(side="right", padx=12, pady=6)

        self.prevent_sleep_var = tk.BooleanVar(value=False)
        self.prevent_sleep_chk = ttk.Checkbutton(
            top_bar, text=sc.s("chk_prevent_sleep"), variable=self.prevent_sleep_var,
            command=self.toggle_prevent_sleep
        )
        # On Linux/macOS SetThreadExecutionState is not available - checkbox only
        # we create, but do not show, so as not to mislead the user.
        if platform.system() == "Windows":
            self.prevent_sleep_chk.pack(side="right", padx=12, pady=6)

        btn_row = ttk.Frame(top_frame)
        btn_row.pack(fill="x", padx=10, pady=4)

        self.playlist_btn_frame = ttk.Frame(btn_row)
        self.playlist_btn_frame.pack(side="left", fill="x", expand=True)

        # width=22 ≈ 14 × 1.6 - under the longest line of the button: "⏳ Stops..."
        # (btn_stopping); the width of the ttk button is calculated in the average width of the font character,
        # rather than in pixels, and with a smaller width the text is cut off. anchor="center"
        # is set explicitly, although for ttk.Button this is the default value: in non-standard
        # Windows themes (with changed layout settings), the text could go to
        # left edge.
        self.scan_btn = ttk.Button(
            btn_row, text=sc.s("btn_start"), command=self.toggle_scan,
            width=22
        )
        self.scan_btn.pack(side="right", padx=(10, 0))
        
        # Minimum interval between successful Start↔Stop transitions.
        # Protects against spam with a button while the previous scan_thread is still
        # did not have time to completely stop/start.
        self._toggle_lock_until: float = 0.0
        self._TOGGLE_COOLDOWN_SEC = 0.45
        # F5 also works during scanning (see.
        # _on_f5_reload_playlist), so it has a separate cooldown:
        # key hold/bounce OS should not generate thread
        # playlist reloads.
        self._last_f5_mono: float = 0.0
        self._F5_COOLDOWN_SEC = 2.0

        # Status bar: "Current: <playlist>" on the left, "VPN: <status>" on the right
        # (align=right). The VPN label is always created, but is shown (pack) only if
        # VPN fallback is available in this build (see _init_vpn_status_label): on non-Windows
        # or without the vpn.py module there is nothing to show.
        status_row = ttk.Frame(top_frame)
        status_row.pack(fill="x", padx=12, pady=(0, 4))

        self.current_playlist_label = ttk.Label(
            status_row, text=sc.s("label_playlist_none"), font=("Arial", 10, "bold")
        )
        self.current_playlist_label.pack(side="left", anchor="w")

        self.vpn_status_label = ttk.Label(status_row, text="", font=("Arial", 10, "bold"))
        self.vpn_status_label.pack(side="right", anchor="e")

        list_frame = ttk.LabelFrame(top_frame, text=sc.s("frame_channels"))
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Like “Active Alerts”: the scrollbar is a child of the LabelFrame (on the right
        # frame edges), wood - with padx/pady, between them there is a gap from the wood padx.
        tree_container = ttk.Frame(list_frame)
        self.tree = ttk.Treeview(
            tree_container, columns=("status", "name", "bitrate"),
            show="headings", height=self._default_tree_rows
        )
        self.tree.heading("status", text=sc.s("col_status"))
        self.tree.heading("name", text=sc.s("col_name"))
        self.tree.heading("bitrate", text=sc.s("col_result"))

        for col in ("status", "name", "bitrate"):
            cw = sc.column_widths[col]
            self.tree.column(col, width=cw["width"], minwidth=cw["minwidth"], stretch=cw["stretch"])

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y", pady=5)
        tree_container.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self._on_tree_right_click)
        # Recalculation of line height for any change in tree size
        # (window resize, change font/DPI, appear/hide scrollbar) -
        # see _fit_tree_row_height.
        self.tree.bind("<Configure>", self._on_tree_self_configure)
        tree_container.bind("<Configure>", self._on_tree_configure)

        bottom_frame = ttk.Frame(main_paned)
        main_paned.add(bottom_frame, weight=1)

        alert_frame = ttk.LabelFrame(bottom_frame, text=sc.s("frame_alerts"))
        alert_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.alert_text = tk.Text(
            alert_frame, height=self._default_alert_lines, wrap="word", font=("Arial", 11)
        )
        alert_scrollbar = ttk.Scrollbar(alert_frame, orient="vertical", command=self.alert_text.yview)
        self.alert_text.configure(yscrollcommand=alert_scrollbar.set)
        alert_scrollbar.pack(side="right", fill="y", pady=5)
        self.alert_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        self.rebuild_playlist_buttons()
        # bind_all catches F5 no matter which widget has focus
        self.root.bind_all("<F5>", self._on_f5_reload_playlist)
        
        # Adjusting the vertical size to the screen working area
        # (Windows zoom / low desktop on laptops).
        self._fit_window_to_screen()

    def _get_work_area_height(self) -> int:
        """Height of the screen working area in pixels Tk (without taskbar).

        On Windows - SPI_GETWORKAREA (logical height taking into account DPI
        scaling process, the same coordinate system in which it works
        Tk itself - .geometry()/winfo_* is also seen by virtualized ones, not
        physical pixels in the absence of a DPI manifest, so compare
        one with the other is correct). On other platforms - winfo_screenheight().
        """
        if platform.system() == "Windows":
            try:
                class RECT(ctypes.Structure):
                    _fields_ = [
                        ("left", wintypes.LONG),
                        ("top", wintypes.LONG),
                        ("right", wintypes.LONG),
                        ("bottom", wintypes.LONG),
                    ]

                SPI_GETWORKAREA = 48
                rect = RECT()
                if ctypes.windll.user32.SystemParametersInfoW(
                    SPI_GETWORKAREA, 0, ctypes.byref(rect), 0
                ):
                    return max(1, int(rect.bottom - rect.top))
            except Exception:
                logger.debug("SPI_GETWORKAREA failed, falling back to winfo_screenheight", exc_info=True)
        try:
            return max(1, int(self.root.winfo_screenheight()))
        except tk.TclError:
            return self._default_window_height

    def _fit_window_to_screen(self) -> None:
        """If the base height of the window does not fit into the working area of the screen, it shrinks
        window vertically and proportionally reduces the number of visible Treeview rows
        (“Channels”) and Text (“Active Alerts”).

        Call after creating widgets in setup_ui(). Idempotent: if sufficient
        location on the screen does not change anything. SPI_GETWORKAREA (and winfo_screenheight in
        fallback) always describe the working area of the MAIN monitor; on
        multi-monitor systems, if the window is not on it, the adjustment will be
        approximate. For an application with one window on the main screen, this is
        acceptable, MonitorFromWindow/GetMonitorInfo are not needed for rare cases."""
        try:
            self.root.update_idletasks()
        except tk.TclError:
            return

        # Small margin: window frame/shadow/client area difference
        # from outer geometry on Windows.
        margin = 48
        work_h = self._get_work_area_height()
        max_h = max(self.root.minsize()[1], work_h - margin)
        desired_h = self._default_window_height
        if desired_h <= max_h:
            return

        scale = max_h / float(desired_h)
        new_h = max(self.root.minsize()[1], int(round(desired_h * scale)))
        # We do not inflate the width - only the height.
        self.root.geometry(f"{self._default_window_width}x{new_h}")

        tree_rows = max(8, int(round(self._default_tree_rows * scale)))
        alert_lines = max(4, int(round(self._default_alert_lines * scale)))
        try:
            self.tree.configure(height=tree_rows)
        except tk.TclError:
            logger.debug("Failed to resize Treeview height", exc_info=True)
        try:
            self.alert_text.configure(height=alert_lines)
        except tk.TclError:
            logger.debug("Failed to resize alert Text height", exc_info=True)

        logger.info(
            "Window height fitted to work area: screen_work=%d → geometry=%dx%d "
            "(tree_rows=%d, alert_lines=%d, scale=%.2f)",
            work_h, self._default_window_width, new_h, tree_rows, alert_lines, scale,
        )

    def _on_f5_reload_playlist(self, event=None) -> None:
        idx = self.scanner.current_playlist_idx

        if not (0 <= idx < MAX_PLAYLISTS):
            return

        # Rate-limit. F5 also works during a scan, and
        # each reboot is a scan stop, an HTTP request and
        # restarting the UI, so the limitation is mandatory. 2 s - with a margin
        # for the duration of the network request itself (preload retrays are not here
        # hit: F5 comes with is_preload=False).
        now = time.monotonic()
        if now - self._last_f5_mono < self._F5_COOLDOWN_SEC:
            logger.debug(
                "F5 playlist reload suppressed by cooldown "
                "(%.2f s remaining)",
                self._F5_COOLDOWN_SEC - (now - self._last_f5_mono),
            )
            return

        # “The playlist is already loading”: playlist buttons at this moment
        # disabled, cannot be clicked - F5 should not bypass the same protection,
        # otherwise, on top of the first _load_playlist_worker, the second one starts (extra
        # HTTP request; generation will cut off its result, but the UI will blink).
        if any(btn.instate(["disabled"]) for btn in self.playlist_buttons):
            return

        # load_selected_playlist
        # stops the scan in exactly the same way as clicking on
        # playlist button (request_stop + bump generation), and its worker
        # itself waits for the real death of scan_thread via _join_scan_thread().
        # While the scan is not stopped, the playlist buttons remain active -
        # F5's behavior becomes uniform with them.
        self._last_f5_mono = now
        self.load_selected_playlist(idx, force=True)


    def rebuild_playlist_buttons(self) -> None:
        for btn in self.playlist_buttons:
            btn.destroy()
        self.playlist_buttons.clear()
        for idx, name, url in self.scanner.get_active_playlists():
            btn = ttk.Button(
                self.playlist_btn_frame,
                text=name,
                command=functools.partial(self.load_selected_playlist, idx)
            )
            btn.pack(side="left", padx=3, pady=2)
            self.playlist_buttons.append(btn)

    def open_settings(self) -> None:
        if self.settings_window is not None and self.settings_window.winfo_exists():
            self.settings_window.lift()
            self.settings_window.focus_force()
            return
        sc = self.scanner
        win = tk.Toplevel(self.root)
        win.title(sc.s("settings_title"))
        # The height is adjusted to the content without expanding the playlist frame.
        win.geometry("630x540")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        win.focus_force()
        self.settings_window = win

        # Top line of settings: VLC frame + to the right of it a frame with location
        # scanner_config.json (see _data_dir()/DATA_DIR: the config can move to
        # %LOCALAPPDATA%, if the entry next to the program is prohibited by ACL - to the user
        # you need to see where exactly).
        fr_top_row = ttk.Frame(win)
        fr_top_row.pack(fill="x")

        fr_vlc = ttk.LabelFrame(fr_top_row, text=sc.s("frame_vlc"))
        fr_vlc.pack(side="left", fill="both", expand=True, padx=(12, 4), pady=8)
        ttk.Label(fr_vlc, text=sc.s("hint_vlc_double_click"), foreground="#555555").pack(
            side="top", anchor="w", padx=8, pady=(6, 0)
        )
        fr_vlc_row = ttk.Frame(fr_vlc)
        fr_vlc_row.pack(fill="x")
        self.sett_vlc_var = tk.StringVar(value=sc.vlc_path)
        ttk.Entry(fr_vlc_row, textvariable=self.sett_vlc_var, width=44).pack(
            side="left", padx=8, pady=6, fill="x", expand=True
        )
        ttk.Button(fr_vlc_row, text=sc.s("btn_browse"), command=self._sett_choose_vlc).pack(
            side="left", padx=8, pady=6
        )

        fr_config_loc = ttk.LabelFrame(fr_top_row, text=sc.s("frame_config_location"))
        fr_config_loc.pack(side="left", fill="y", padx=(4, 12), pady=8)
        fr_config_loc.configure(width=127)
        fr_config_loc.pack_propagate(False)
        ttk.Label(fr_config_loc, text=sc.s("label_config_location")).pack(
            side="top", pady=(8, 2)
        )
        ttk.Button(
            fr_config_loc, text=sc.s("btn_open_config_location"),
            command=self._sett_open_config_location,
        ).pack(side="top", pady=(0, 8))

        # Color saturation of lines. Needed due to a feature of Windows 11: when turned on
        # The HDR system discolors SDR applications on the way to the screen, and pastel
        # tree_colors become almost indistinguishable from white. Value above 100%
        # compensates for this in advance - the colors in the application are made more saturated than the nominal value.
        fr_sat = ttk.LabelFrame(win, text=sc.s("frame_color_saturation"))
        fr_sat.pack(fill="x", padx=12, pady=4)
        self.sett_saturation = tk.DoubleVar(value=sc.color_saturation)
        self.sett_saturation_label = ttk.Label(fr_sat, width=6, anchor="e")
        self._sett_update_saturation_label(sc.color_saturation)
        ttk.Scale(
            fr_sat, from_=COLOR_SATURATION_MIN, to=COLOR_SATURATION_MAX,
            orient="horizontal", variable=self.sett_saturation,
            command=self._sett_on_saturation_change,
        ).pack(side="left", padx=8, pady=6, fill="x", expand=True)
        self.sett_saturation_label.pack(side="left", padx=(0, 8), pady=6)
        ttk.Button(
            fr_sat, text=sc.s("btn_saturation_reset"),
            command=self._sett_reset_saturation, width=13,
        ).pack(side="left", padx=(0, 8), pady=6)

        fr_scan = ttk.LabelFrame(win, text=sc.s("frame_scan_params"))
        fr_scan.pack(fill="x", padx=12, pady=4)
        row = 0
        ttk.Label(fr_scan, text=sc.s("label_timeout")).grid(
            row=row, column=0, sticky="w", padx=8, pady=4
        )
        self.sett_timeout = tk.IntVar(value=sc.scan_timeout)
        ttk.Spinbox(
            fr_scan, from_=RUNTIME.scan_timeout_min_sec, to=RUNTIME.scan_timeout_max_sec,
            textvariable=self.sett_timeout, width=6
        ).grid(row=row, column=1, sticky="w", padx=4, pady=4)
        ttk.Label(fr_scan, text=sc.s("label_parallel")).grid(
            row=row, column=2, sticky="w", padx=(20, 4), pady=4
        )
        self.sett_parallel = tk.IntVar(value=sc.parallel)
        ttk.Spinbox(
            fr_scan, from_=RUNTIME.parallel_min, to=RUNTIME.parallel_max,
            textvariable=self.sett_parallel, width=6
        ).grid(row=row, column=3, sticky="w", padx=4, pady=4)
        ttk.Label(fr_scan, text=sc.s("label_min_bitrate")).grid(
            row=row, column=4, sticky="w", padx=(20, 4), pady=4
        )
        self.sett_min_br = tk.IntVar(value=sc.min_bitrate_kbps)
        ttk.Spinbox(
            fr_scan, from_=RUNTIME.min_bitrate_setting_kbps,
            to=max(RUNTIME.min_bitrate_setting_kbps, sc.thresholds.error_bitrate_kbps),
            textvariable=self.sett_min_br, width=8
        ).grid(row=row, column=5, sticky="w", padx=4, pady=4)

        fr_pl = ttk.LabelFrame(win, text=sc.s("frame_playlists"))
        # Content only (5 lines): expand=True left a huge void
        # below the fields at a fixed height of the settings window.
        fr_pl.pack(fill="x", padx=12, pady=8)
        self.sett_name_vars: List[tk.StringVar] = []
        self.sett_url_vars: List[tk.StringVar] = []
        self.sett_auto_vars: List[tk.BooleanVar] = []
        self.sett_auto_chks: List[ttk.Checkbutton] = []
        self._auto_updating = False   # recursion protection for programmatic set()

        # Grid: column 0 = Auto, 1 = name, 2 = URL - header and fields in the same columns.
        ttk.Label(fr_pl, text=sc.s("label_pl_auto")).grid(
            row=0, column=0, padx=(6, 4), pady=2, sticky="w"
        )
        ttk.Label(fr_pl, text=sc.s("label_pl_name")).grid(
            row=0, column=1, padx=4, pady=2, sticky="w"
        )
        ttk.Label(fr_pl, text=sc.s("label_pl_url")).grid(
            row=0, column=2, padx=4, pady=2, sticky="w"
        )

        # Which slot is currently selected as preload (by name)
        preload_name = (sc.preload_playlist or "").strip()
        selected_idx = -1
        if preload_name:
            for i in range(MAX_PLAYLISTS):
                if (sc.playlist_names[i] or "").strip() == preload_name:
                    selected_idx = i
                    break

        for i in range(MAX_PLAYLISTS):
            auto_var = tk.BooleanVar(value=(i == selected_idx))
            self.sett_auto_vars.append(auto_var)
            
            row_pady = (2, 8) if i == MAX_PLAYLISTS - 1 else 2

            chk = ttk.Checkbutton(
                fr_pl,
                variable=auto_var,
                command=functools.partial(self._on_preload_auto_toggle, i),
            )
            chk.grid(row=i + 1, column=0, padx=(6, 4), pady=row_pady, sticky="w")
            self.sett_auto_chks.append(chk)

            if selected_idx >= 0 and i != selected_idx:
                chk.config(state="disabled")

            name_var = tk.StringVar(value=sc.playlist_names[i] or "")
            url_var = tk.StringVar(value=sc.playlist_urls[i] or "")
            self.sett_name_vars.append(name_var)
            self.sett_url_vars.append(url_var)
            ttk.Entry(fr_pl, textvariable=name_var, width=22).grid(
                row=i + 1, column=1, padx=4, pady=row_pady, sticky="w"
            )
            ttk.Entry(fr_pl, textvariable=url_var, width=55).grid(
                row=i + 1, column=2, padx=4, pady=row_pady, sticky="ew"
            )

        fr_pl.columnconfigure(2, weight=1)

        # ---VPN fallback (see vpn.py) -------------------------------------
        # The section is not created if the vpn.py module is not available (for example, the file is not located
        # next to the scanner - see vpn import in the file header) or non-Windows platform:
        # the function does not physically work (WinAPI RAS/routes - Windows only), and
        # showing controls that don't work is pointless. In particular,
        # a clickable checkbox "Use VPN" could store vpn_enabled=True in
        # config, although the function will not work the next time it is launched.
        self._vpn_available = vpn is not None and vpn.IS_WINDOWS
        self._vpn_profile_options: Dict[str, Tuple[str, Optional[bool]]] = {}
        if self._vpn_available:
            fr_vpn = ttk.LabelFrame(win, text=sc.s("frame_vpn"))
            fr_vpn.pack(fill="x", padx=12, pady=4)

            vpn_row = ttk.Frame(fr_vpn)
            vpn_row.pack(fill="x")

            self.sett_vpn_enabled = tk.BooleanVar(value=sc.vpn_enabled)
            self.sett_vpn_chk = ttk.Checkbutton(
                vpn_row, text=sc.s("chk_vpn_enabled"), variable=self.sett_vpn_enabled
            )
            self.sett_vpn_chk.pack(side="left", padx=8, pady=6)
            # We press the signature “Connection:” and the combobox to the right edge.
            # IMPORTANT about pack(side="right"): each next widget is placed
            # LEFT of the previous one, so the combobox is packed first -
            # it will stand at the very right edge, and the signature will stand to the left of it.
            current_scope = sc.vpn_connection_all_user
            current_label = sc.vpn_connection_name
            if current_scope is True:
                current_label = f"{current_label} (All users)" if current_label else ""
            elif current_scope is False:
                current_label = f"{current_label} (User)" if current_label else ""
            self.sett_vpn_name = tk.StringVar(value=current_label)
            self.sett_vpn_combo = ttk.Combobox(
                vpn_row, textvariable=self.sett_vpn_name, width=30, state="readonly"
            )
            self.sett_vpn_combo.pack(side="right", padx=(4, 8), pady=6)
            ttk.Label(vpn_row, text=sc.s("label_vpn_connection")).pack(
                side="right", padx=(16, 4)
            )

            # Status - a separate line under the main one. On par with
            # "Connection:"/Combobox long text ("Loading list...") would supplant
            # signature "Connection:" - rows should not compete for width. Pinned down
            # right to appear under the VPN selection field.
            self.sett_vpn_status_var = tk.StringVar(value="")
            ttk.Label(
                fr_vpn, textvariable=self.sett_vpn_status_var, foreground="#555555"
            ).pack(side="top", anchor="e", padx=(8, 8), pady=(0, 6))

            self.sett_vpn_status_var.set(sc.s("vpn_status_loading"))
            threading.Thread(target=self._sett_load_vpn_names, daemon=True).start()
            # All VPN widgets have been created - now you can set their status.
            self._refresh_vpn_chk_state()
        # If VPN is not available, self.sett_vpn_enabled/sett_vpn_name/sett_vpn_combo/
        # sett_vpn_status_var are not deliberately created: close_settings() reads them
        # only with self._vpn_available, so vpn_enabled/vpn_connection_name/
        # vpn_connection_all_user in the config remains intact when saved.

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=12, pady=10)
        ttk.Button(
            btn_frame,
            text=sc.s("btn_reset_advanced"),
            command=self._sett_reset_advanced_config,
            width=24,
        ).pack(side="left")
        self.sett_close_btn = ttk.Button(
            btn_frame, text=sc.s("btn_close"), command=self.close_settings, width=16
        )
        self.sett_close_btn.pack(side="right")

        # Adjusting the vertical size to the actual composition of the window.
        #
        # The "VPN" section is created only with self._vpn_available (vpn.py
        # imported and we are on Windows). If it is not there, the contents of the window
        # in short, and a hard height of 540 would leave a large empty band
        # under the "Reset"/"Close" buttons (pack without expand=True: widgets
        # occupy only the required height, and the excess window remains
        # empty at the very bottom).
        #
        # winfo_reqheight() returns the height that the window's contents
        # requests from the pack manager. update_idletasks() is required:
        # pack recalculates the geometry precisely in the idle phase, and before it
        # winfo_reqheight() can return the value counted up to
        # packaging of the latest widgets.
        #
        # min(540, …) - ceiling: if, with future improvements, the contents
        # will be higher than the original 540 px, the window will not “climb out” beyond the usual
        # size (resizable(False, False) would not give the user this
        # fix it by hand). The width remains the same - it does not depend
        # depending on the presence of a VPN section.
        win.update_idletasks()
        target_height = min(540, win.winfo_reqheight())
        win.geometry(f"630x{target_height}")

        win.protocol("WM_DELETE_WINDOW", self.close_settings)

    def _sett_load_vpn_names(self) -> None:
        """Background thread: List of VPN connections via PowerShell (read,
        does not require administrator rights - see vpn.list_connection_names)."""
        assert vpn is not None  # only called when vpn is not None (see calling code)
        try:
            profiles = vpn.list_connection_profiles()
        except Exception:
            logger.exception("Failed to get the list of VPN connections")
            profiles = []
        self._post_to_gui(self._sett_apply_vpn_names, profiles)

    def _sett_apply_vpn_names(self, profiles: List[dict]) -> None:
        # Scheduled via root.after from a background thread (see _sett_load_vpn_names).
        # The usual case is that the settings window is closed before the list of profiles arrives -
        # covered by the winfo_exists() check below. A rare case - the entire root is destroyed
        # (see _close_worker): then winfo_exists() on the “rotten” widget throws
        # tk.TclError rather than returning False. Therefore, the entire method is wrapped: the rest
        # working with settings window widgets will also not survive the destruction of root between
        # two lines.
        try:
            self._sett_apply_vpn_names_impl(profiles)
        except tk.TclError:
            logger.debug(
                "_sett_apply_vpn_names: window/application already destroyed",
                exc_info=True,
            )

    def _sett_apply_vpn_names_impl(self, profiles: List[dict]) -> None:
        if self.settings_window is None or not self.settings_window.winfo_exists():
            return
        self._vpn_profile_options.clear()
        duplicate_names: Dict[str, int] = {}
        for item in profiles:
            duplicate_names[item["name"]] = duplicate_names.get(item["name"], 0) + 1

        values = []
        for item in profiles:
            name = str(item["name"])
            all_user = bool(item["all_user"])
            if duplicate_names[name] > 1:
                label = f"{name} (All users)" if all_user else f"{name} (User)"
            else:
                label = name
            if label in self._vpn_profile_options:
                label = f"{label} [{('All users' if all_user else 'User')}]"
            self._vpn_profile_options[label] = (name, all_user)
            values.append(label)

        current_name = self.scanner.vpn_connection_name
        current_scope = self.scanner.vpn_connection_all_user
        selected = None
        for label, (name, scope) in self._vpn_profile_options.items():
            if name == current_name and (current_scope is None or scope == current_scope):
                selected = label
                break
        self.sett_vpn_combo.config(values=values)
        if selected:
            self.sett_vpn_name.set(selected)
        elif not self.sett_vpn_name.get() and values:
            self.sett_vpn_name.set(values[0])
        self.sett_vpn_status_var.set("" if values else self.scanner.s("vpn_status_none_found"))


    def _sett_update_saturation_label(self, value: float) -> None:
        self.sett_saturation_label.config(text=f"{value * 100:.0f}%")

    def _sett_on_saturation_change(self, value_str: str) -> None:
        try:
            value = float(value_str)
        except (TypeError, ValueError):
            return
        self._sett_update_saturation_label(value)
        # Live preview: immediately paint the current tree, nothing yet
        # saving to the config (save occurs only in close_settings(),
        # as for other settings in this window).
        self.scanner.color_saturation = value
        self.apply_tree_colors()

    def _sett_reset_saturation(self) -> None:
        self.sett_saturation.set(COLOR_SATURATION_DEFAULT)
        self._sett_on_saturation_change(str(COLOR_SATURATION_DEFAULT))

    def _sett_reset_advanced_config(self) -> None:
        """Reset thresholds/ui_strings/colors/prefixes - with confirmation."""
        sc = self.scanner
        parent = self.settings_window if (
            self.settings_window is not None and self.settings_window.winfo_exists()
        ) else self.root
        if not messagebox.askyesno(
            sc.s("msg_reset_advanced_title"),
            sc.s("msg_reset_advanced_confirm"),
            parent=parent,
        ):
            return
        sc.reset_advanced_config_to_defaults()
        # The row colors are applied immediately (we do not reset the saturation from the window).
        self.apply_tree_colors()
        messagebox.showinfo(
            sc.s("msg_reset_advanced_title"),
            sc.s("msg_reset_advanced_done"),
            parent=parent,
        )

    def _sett_choose_vlc(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.settings_window,
            title="VLC",
            filetypes=[("VLC", "vlc.exe"), ("All files", "*.*")]
        )
        if path:
            self.sett_vlc_var.set(path)

    def _sett_open_config_location(self) -> None:
        """Opens the folder in Explorer where scanner_config.json is located.

        CONFIG_FILE points to DATA_DIR (see _data_dir()/DATA_DIR at level
        module): this is the installation directory or %LOCALAPPDATA%/IPTV_Scanner, if the entry
        ACL is prohibited next to the program (for example, installation in Program Files).
        """
        folder = CONFIG_FILE.parent
        try:
            folder.mkdir(parents=True, exist_ok=True)
            if platform.system() == "Windows":
                os.startfile(str(folder))
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except OSError as e:
            logger.exception("Failed to open the folder containing scanner_config.json: %s", folder)
            messagebox.showerror(
                self.scanner.s("msg_attention"),
                self.scanner.s("msg_open_config_location_error", path=str(folder), error=str(e)),
                parent=self.settings_window or self.root,
            )

    def _on_preload_auto_toggle(self, idx: int) -> None:
        """Exclusive selection of preload playlist (behavior like a radio button).

        - Marked one → all others are removed and become disabled.
        - Removed the only one checked → all checkboxes are active and empty again."""
        if getattr(self, "_auto_updating", False):
            return
        if not hasattr(self, "sett_auto_vars") or not self.sett_auto_vars:
            return

        self._auto_updating = True
        try:
            if self.sett_auto_vars[idx].get():
                # We chose this slot - we extinguish the rest
                for j, var in enumerate(self.sett_auto_vars):
                    if j != idx:
                        var.set(False)
                        self.sett_auto_chks[j].config(state="disabled")
                    else:
                        self.sett_auto_chks[j].config(state="normal")
            else:
                # Unchecked the only checkbox - everyone is available again
                for chk in self.sett_auto_chks:
                    chk.config(state="normal")
        finally:
            self._auto_updating = False

    def close_settings(self) -> None:
        if self.settings_window is None or not self.settings_window.winfo_exists():
            return
        if getattr(self, "_vpn_apply_in_progress", False):
            # The settings window close handler may fire repeatedly (the "Close" button
            # and the system cross are tied to one method) while the previous call is still
            # applies VPN settings (possibly waiting for a response to the UAC request shown).
            # The callback is ignored to avoid prompting UAC twice.
            return
        sc = self.scanner
        new_names = []
        new_urls = []
        for i in range(MAX_PLAYLISTS):
            name = self.sett_name_vars[i].get().strip()
            url = self.sett_url_vars[i].get().strip()
            if (name and not url) or (url and not name):
                messagebox.showerror(
                    sc.s("msg_error"),
                    sc.s("msg_playlist_incomplete", n=i + 1),
                    parent=self.settings_window
                )
                return
            new_names.append(name)
            new_urls.append(url)

        if self._vpn_available:
            new_vpn_enabled = bool(self.sett_vpn_enabled.get())
            selected_label = self.sett_vpn_name.get().strip()
            new_vpn_conn = ""
            new_vpn_scope = sc.vpn_connection_all_user
            if selected_label in self._vpn_profile_options:
                new_vpn_conn, selected_scope = self._vpn_profile_options[selected_label]
                same_name_count = sum(
                    1 for name, _scope in self._vpn_profile_options.values() if name == new_vpn_conn
                )
                new_vpn_scope = (
                    sc.vpn_connection_all_user
                    if sc.vpn_connection_all_user is None and same_name_count == 1
                    else selected_scope
                )
            elif selected_label:
                # The old saved name may be temporarily missing from the list.
                new_vpn_conn = selected_label
            if new_vpn_enabled and not new_vpn_conn:
                messagebox.showerror(
                    sc.s("msg_error"), sc.s("msg_vpn_no_connection_selected"),
                    parent=self.settings_window
                )
                return
        else:
            # There is no VPN section in this window (the module is not available/not Windows), there is nothing to read:
            # values from the config are saved without changes, widgets sett_vpn_* in this
            # scripts don't exist.
            new_vpn_enabled = sc.vpn_enabled
            new_vpn_conn = sc.vpn_connection_name
            new_vpn_scope = sc.vpn_connection_all_user

        with sc._config_lock:
            old_idx = sc.current_playlist_idx
            old_url = ""
            if 0 <= old_idx < MAX_PLAYLISTS:
                old_url = (sc.playlist_urls[old_idx] or "").strip()
        sc.vlc_path = self.sett_vlc_var.get().strip()
        sc.color_saturation = max(
            COLOR_SATURATION_MIN, min(COLOR_SATURATION_MAX, self.sett_saturation.get())
        )

        def _safe_int(var, default):
            try:
                return var.get()
            except (tk.TclError, ValueError):
                return default

        # Spinbox does not prohibit you from manually entering a number outside [from_, to] (or even
        # non-numeric text, which will cause IntVar.get() to throw a TclError), so
        # apply_scan_settings() here clamps the values in the same way as with
        # reading the config in load_config().
        sc.apply_scan_settings(
            _safe_int(self.sett_timeout, sc.scan_timeout),
            _safe_int(self.sett_parallel, sc.parallel),
            _safe_int(self.sett_min_br, sc.min_bitrate_kbps),
        )
        with sc._config_lock:
            sc.playlist_names = new_names
            sc.playlist_urls = new_urls
        self.rebuild_playlist_buttons()
        # Preload playlist from the Auto column
        new_preload = ""
        for i in range(MAX_PLAYLISTS):
            if self.sett_auto_vars[i].get():
                name = (new_names[i] or "").strip()
                if name:
                    new_preload = name
                # if the name is empty, we assume that preload is not selected
                break
        sc.preload_playlist = new_preload
        need_reset = False
        if old_idx >= 0:
            if not (new_names[old_idx] and new_urls[old_idx]):
                need_reset = True
            elif new_urls[old_idx].strip() != old_url:
                need_reset = True

        vpn_changed = (
            new_vpn_enabled != sc.vpn_enabled
            or new_vpn_conn != sc.vpn_connection_name
            or new_vpn_scope != sc.vpn_connection_all_user
        )
        if vpn_changed and self._vpn_available:
            self._vpn_apply_in_progress = True
            self.sett_close_btn.config(state="disabled")
            self.sett_vpn_status_var.set(sc.s("vpn_status_applying"))
            # Invalidate any in-flight recovery worker (typical case:
            # _vpn_reconnect_retry_worker, already spinning after more
            # early VPN break) BEFORE running _sett_finish_vpn_and_close.
            # Without this bump, the epoch of that worker still coincides, and he
            # at the next iteration (or after a short backoff) it can
            # raise the VPN again - right on top of disconnect_and_unroute,
            # which at this time disconnects the session. This is the same
            # bump_epoch() which makes the successful path
            # (_sett_apply_vpn_result) at the end, just earlier - so that
            # the worker managed to SEE the epoch change and ended, and not
            # just to reset the precheck cache.
            self._rs.bump_epoch()
            if not new_vpn_enabled:
                # Turn off the checkbox - actual shutdown (rasdial/
                # routes) will happen in the background thread below; reflect this
                # in the header of the main window immediately, without waiting for its end.
                # _set_vpn_status() also resets _vpn_watch and
                # vpn_relied_upon, so NetworkHealthMonitor stops
                # keep an eye on the session that we are about to demolish.
                self._set_vpn_status("vpn_state_disconnecting")
            self.settings_window.protocol("WM_DELETE_WINDOW", lambda: None)
            threading.Thread(
                target=self._sett_finish_vpn_and_close,
                args=(new_vpn_enabled, new_vpn_conn, new_vpn_scope, need_reset),
                daemon=True,
            ).start()
            return

        # The VPN state has not changed (or the module/platform does not support VPN fallback) —
        # the window closes synchronously.
        sc.vpn_enabled = new_vpn_enabled
        sc.vpn_connection_name = new_vpn_conn
        sc.vpn_connection_all_user = new_vpn_scope
        sc.save_config()
        if need_reset:
            self._reset_to_idle()
        self.settings_window.destroy()
        self.settings_window = None

    def _sett_finish_vpn_and_close(self, new_enabled: bool, new_conn: str,
                                    new_scope: Optional[bool], need_reset: bool) -> None:
        """Background thread: raises/stops elevated helper according to new
        checkbox state. The UAC request (if needed) is here.

        When result == "declined" (the user was denied rights when the VPN was enabled)
        _sett_apply_vpn_result will roll back vpn_enabled to False: without a checkmark helper
        useless, otherwise to re-request you would have to remove and install it
        again. Other failures (timeout / not_found / integrity) checkbox not
        roll back - the problem there is not an explicit refusal of the user."""
        assert vpn is not None  # called only from the vpn is not None branch (see close_settings)
        result = "ok"
        try:
            helper_alive = vpn.is_helper_alive(timeout=1.0)
            if new_enabled:
                # If the user changed the VPN profile (name or scope) without turning off the checkbox,
                # the old connection (if we raised it) needs to be disconnected: otherwise
                # connect_and_route() would raise the NEW profile on top on the next scan
                # connected old one, both would be connected, and routing would become
                # unpredictable. disconnect_and_unroute() is safe to call when old
                # VPN “not ours” (will only remove our host routes, return owned=False, nothing
                # without disabling), so when changing the profile it is called unconditionally, before
                # connecting a new one.
                old_conn = self.scanner.vpn_connection_name
                old_scope = self.scanner.vpn_connection_all_user
                profile_changed = bool(old_conn) and (
                    old_conn != new_conn or old_scope != new_scope
                )
                if profile_changed and helper_alive:
                    try:
                        vpn.disconnect_and_unroute(base_path, old_conn, all_user=old_scope)
                    except Exception:
                        logger.exception(
                            "Failed to disconnect the previous VPN profile %r while switching to %r",
                            old_conn, new_conn,
                        )
                if not helper_alive:
                    result = vpn.launch_helper(base_path)
                # If the helper is already alive (for example, the VPN was turned on earlier in the same session), the new
                # UAC request is not needed; The NEW profile will be connected the next time you start the scan in
                # connect_and_route().
            else:
                # Turn off the checkbox - remove the VPN (if we connected it)
                # and routes right now, without waiting for the program to close.
                try:
                    vpn.disconnect_and_unroute(base_path, self.scanner.vpn_connection_name,
                                              all_user=self.scanner.vpn_connection_all_user)
                except Exception:
                    logger.exception("Failed to disconnect VPN after the checkbox was cleared")
                if helper_alive:
                    vpn.stop_helper()
        except Exception:
            logger.exception("Failed to apply VPN settings")
            result = "timeout"
        self._post_to_gui(self._sett_apply_vpn_result, new_enabled, new_conn, new_scope, result, need_reset)

    def _sett_apply_vpn_result(self, new_enabled: bool, new_conn: str, new_scope: Optional[bool],
                                result: str, need_reset: bool) -> None:
        self._vpn_apply_in_progress = False
        sc = self.scanner
        try:
            effective_enabled = new_enabled
            # Refusal of UAC when trying to ENABLE VPN: helper is not raised,
            # leaving vpn_enabled=True is pointless - repeat request
            # I would have to uncheck the box and check it again. Profile name
            # We save it so that we don’t have to select it again the next time we turn it on.
            if new_enabled and result == "declined":
                effective_enabled = False
                logger.info(
                    "UAC declined while enabling VPN — vpn_enabled rolled back to False"
                )

            sc.vpn_enabled = effective_enabled
            sc.vpn_connection_name = new_conn
            sc.vpn_connection_all_user = new_scope
            sc.save_config()
            self._precheck_ok_mono = None
            self._rs.bump_epoch()
            if not effective_enabled:
                self._rs.vpn_owned_by_us = False
            self._set_vpn_status("vpn_state_disconnected")
            self._update_vpn_status_visibility()
            if new_enabled and result != "ok":
                parent = self.settings_window if (
                    self.settings_window is not None and self.settings_window.winfo_exists()
                ) else self.root
                msg_key = {
                    "declined": "vpn_status_uac_declined",
                    "timeout": "vpn_status_helper_timeout",
                    "not_found": "vpn_status_helper_not_found",
                    "integrity": "vpn_status_helper_integrity",
                }.get(result, "vpn_status_helper_timeout")
                messagebox.showinfo(sc.s("msg_attention"), sc.s(msg_key), parent=parent)
            # Precheck was running, and the user changed the VPN (removed/installed
            # tick, changed profile). In-flight worker after bump_epoch
            # will be rejected by the matching check - without restarting the UI
            # would remain forever on “Network check...” / disabled.
            was_prechecking = self._precheck_in_progress
            if need_reset:
                self._precheck_in_progress = False
                self._reset_to_idle()
            elif was_prechecking and not self._closing:
                self._precheck_in_progress = False
                logger.info(
                    "VPN settings changed during precheck — restarting "
                    "network check under new settings (vpn_enabled=%s)",
                    sc.vpn_enabled,
                )
                self._set_controls_enabled(False)
                self.scan_btn.config(text=self.scanner.s("btn_precheck"))
                self._start_scan_if_idle()
                if (
                    not self._precheck_in_progress
                    and not self.scanner.is_scanning
                    and (self.scan_thread is None or not self.scan_thread.is_alive())
                ):
                    self._set_controls_enabled(True)
                    self._set_idle_ui()
        finally:
            # Whatever happened above (save_config() failed on disk, messagebox raised
            # TclError, etc.), the settings window must not stay open with the system
            # close button disabled (close_settings() temporarily replaces the protocol
            # with lambda: None before starting the background thread, and restores it
            # only here). The window is closed in any case, not only on the happy path.
            if self.settings_window is not None:
                try:
                    if self.settings_window.winfo_exists():
                        self.settings_window.destroy()
                except tk.TclError:
                    logger.debug(
                        "settings_window was already destroyed by the time "
                        "_sett_apply_vpn_result ran", exc_info=True,
                    )
                self.settings_window = None

    def _invalidate_scan_callbacks(self) -> None:
        """GUI thread. Invalidates all results of the current
        скана, которые scan_loop уже успел поставить в очередь Tk (см.
        проверку generation в _update_channel_row_impl).

        IMPORTANT: Call AFTER scanner.request_stop(). scan_loop decides for itself
        when to exit, by is_scanning; if generation had changed earlier
        stop flag, the stream would momentarily see “the generation is outdated, but the scan
        still going."

        Needed for Stop, pause due to loss of connection, start of soft recovery and
        closing the window. Change playlist / reset_to_idle / Start is raised
        generation themselves."""
        self.controller.invalidate_scan_generation()

    def _reset_to_idle(self) -> None:
        self.scan_generation = self.scan_generation.bump()
        self.load_generation = self.load_generation.bump()
        gen = self.load_generation
        self.scanner.request_stop()
        self.scan_btn.config(text=self.scanner.s("btn_start"))
        self._set_controls_enabled(False)
        threading.Thread(target=self._reset_to_idle_worker, args=(gen,), daemon=True).start()

    def _join_scan_thread(self) -> bool:
        return self.controller.join_scan_thread()
        
    def _set_stopping_ui(self) -> None:
        """Shows “Stopping...” and blocks the button until the thread dies."""
        self.scan_btn.config(
            text=self.scanner.s("btn_stopping"),
            state="disabled",
        )
        self._refresh_vpn_chk_state()

    def _set_idle_ui(self) -> None:
        """Returns the button to the “Launch” state."""
        self.scan_btn.config(
            text=self.scanner.s("btn_start"),
            state="normal",
        )
        # An additional short lock after the thread has actually died.
        self._toggle_lock_until = max(
            self._toggle_lock_until,
            time.monotonic() + 0.25,
        )
        self._refresh_vpn_chk_state()

    def _reset_to_idle_worker(self, gen: GenerationToken) -> None:
        if not self._join_scan_thread():
            self._post_to_gui(lambda: messagebox.showwarning(
                self.scanner.s("msg_stop_title"),
                self.scanner.s("msg_stop_timeout")
            ))
            self._post_to_gui(self._on_reset_failed)
            return
        self.scanner.close_all_sessions()
        if gen != self.load_generation:
            return
        with self.scanner._channels_lock:
            self.scanner.channels.clear()
            self.scanner.current_playlist_idx = -1
            self.scanner.last_index = 0
        self.scanner.save_config()
        self._post_to_gui(self._on_reset_complete, gen)

    def _on_reset_failed(self) -> None:
        self._set_controls_enabled(True)
        self._set_idle_ui()

    def _on_reset_complete(self, gen: GenerationToken) -> None:
        if gen != self.load_generation:
            return
        # Playlist reset - no resume item.
        self._scan_was_running_before_pause = False
        self._set_controls_enabled(True)
        self._set_idle_ui()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tree_items.clear()
        self.tree.yview_moveto(0)
        with self.scanner._alerts_lock:
            self.scanner.alerts.clear()
        self.scanner.reset_issue_tracking_state()
        self.alert_text.delete("1.0", tk.END)
        self.current_playlist_label.config(text=self.scanner.s("label_playlist_none"))

    @staticmethod
    def _play_beeps_async(beeps: List[Tuple[int, int]], gap: float = 0.0) -> None:
        # One shared stream with a limited queue (see _SoundPlayer):
        # mass signals collapse rather than generate a flow for each one.
        _SOUND_PLAYER.play(beeps, gap)

    def toggle_sound(self) -> None:
        self.sound_enabled = self.sound_var.get()
        # See detailed comment in toggle_prevent_sleep - same technique
        # It is also needed here in case of accidental repeated “pressing” of the key.
        self.root.focus_set()

    def toggle_prevent_sleep(self) -> None:
        """Enables/disables prohibiting Windows from going into sleep/hibernation while running
        programs via SetThreadExecutionState. ES_CONTINUOUS without flags resets
        prohibition—the normal behavior of the power system returns. When closing
        Windows applications itself cancel the request (see MSDN), reset it when
        no need to exit.

        After clicking, the checkbox remains in keyboard focus, and Space is the standard
        Tk key for "tap" focused widget. Therefore, Space, pressed,
        for example, to wake up a dark screen after sleep, it goes into the application and
        silently switches the checkbox back. To prevent this from happening, after clicking
        Focus is given to the entire window: it does not respond to Space/Enter."""
        self.root.focus_set()
        if platform.system() != "Windows":
            return
        enabled = self.prevent_sleep_var.get()
        try:
            flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if enabled else 0)
            ctypes.windll.kernel32.SetThreadExecutionState(flags)
            logger.info(
                "Sleep prevention %s (SetThreadExecutionState flags=0x%08X)",
                "enabled" if enabled else "disabled", flags,
            )
        except Exception:
            logger.warning(
                "Failed to change sleep-prevention state via SetThreadExecutionState",
                exc_info=True,
            )

    def _heartbeat_tick(self) -> None:
        """Every RUNTIME.heartbeat_interval_ms checks the actual elapsed time with
        expected: a large gap means the computer was sleeping or hibernating
        (see comment at RUNTIME.heartbeat_interval_ms).

        This is the main detection channel, but it depends on the Tcl/Tk timer
        (root.after), and on Windows it is partially tied to the system tick counter:
        after REAL hibernation, the counter may be reset upon reboot, and
        The timer goes off much later than expected. Independent backup channel -
        _heartbeat_watchdog_loop.

        Use time.monotonic() rather than time.time(): system clock translation
        (manual/NTP/administrator) should not simulate waking up from sleep (see
        comment from self._last_heartbeat_mono)."""
        now_mono = time.monotonic()
        gap = now_mono - self._last_heartbeat_mono
        self._last_heartbeat_mono = now_mono
        if gap > RUNTIME.hibernation_gap_threshold_sec:
            self._on_system_woke_from_sleep(gap)
        self.root.after(RUNTIME.heartbeat_interval_ms, self._heartbeat_tick)

    def _heartbeat_watchdog_loop(self) -> None:
        """Backup "heartbeat", duplicating _heartbeat_tick, but independent of the timer
        Tcl/Tk: Runs in a separate thread on time.sleep() rather than root.after().
        After true hibernation, root.after() sometimes wakes up with a large
        late (see _heartbeat_tick), and then the break notices this thread first
        and pauses the scan.

        Duplication is safe: _on_system_woke_from_sleep() is idempotent - if
        the main timer has already paused the scan, scanner.is_scanning by the time
        the trigger of this thread is already False, and the call does nothing. In GUI thread
        control is transferred via _post_to_gui (root.after), and not directly
        accessing widgets from someone else's stream.

        Like _heartbeat_tick, it uses time.monotonic() rather than time.time()
        (see comment from self._last_heartbeat_mono).
        """
        last_mono = time.monotonic()
        while not self._app_stop_event.wait(RUNTIME.heartbeat_interval_ms / 1000.0):
            now_mono = time.monotonic()
            gap = now_mono - last_mono
            last_mono = now_mono
            if gap > RUNTIME.hibernation_gap_threshold_sec:
                self._post_to_gui(self._on_system_woke_from_sleep, gap)

    def _on_system_woke_from_sleep(self, gap_sec: float) -> None:
        # Debounce: _heartbeat_tick (root.after) and _heartbeat_watchdog_loop (separate
        # flow) - two independent channels detecting the same discontinuity, and both
        # call this method. Without debounce, the second call would restart
        # hygiene-flow, increased _net_epoch again and reinstalled recovery guard.
        # Threshold - two heartbeat intervals: with a margin enough to collapse a pair
        # calls from one awakening, but not absorb two different awakenings in a row.
        now_mono = time.monotonic()
        debounce_sec = 2.0 * RUNTIME.heartbeat_interval_ms / 1000.0
        if now_mono - self._last_wake_handled_mono < debounce_sec:
            logger.debug(
                "Duplicate wake detection suppressed "
                "(repeat from the second detection channel)."
            )
            return
        self._last_wake_handled_mono = now_mono

        # The VPN tunnel (if used) does not sleep/hibernate. Before that
        # moment the label could show the inherited “Connected”, and without this
        # line the next transition would look like "Connected" -> "Connection" in
        # bypass "Disabled". The actual state will be determined later: when resuming
        # scan (see _start_scan_if_idle) or will remain "Disabled" if the scan is not
        # started (was idle).
        self._set_vpn_status("vpn_state_disconnected")
        self._rs.vpn_owned_by_us = False
        self._vpn_watch.reset()
        logger.info("Heartbeat gap of %.0f s detected (likely sleep/hibernation).", gap_sec)

        threading.Thread(
            target=self._network_hygiene_light,
            daemon=True, name="hygiene-after-wake",
        ).start()

        # Single pause/resume pipeline - shared with NetworkHealthMonitor
        # (Internet loss, VPN interruption), see _pause_for_connectivity_issue.
        self._pause_for_connectivity_issue()
        self._maybe_schedule_recovery_resume()

    def _resume_scan_after_sleep(self, attempts_left: int = 20) -> None:
        # The previous scan_thread might not have had time to stop yet (executor.
        # shutdown(wait=True) inside scan_loop) so its completion is awaited
        # short approaches, rather than one fixed pause (similar to
        # _load_playlist_worker).
        # Method name is historical (originally only sleep/hibernation): now it's generic
        # "pre-renewal" scan, also used after the Internet is restored
        # and VPN reconnections - see _finish_recovery_guard.
        if self.scan_thread is not None and self.scan_thread.is_alive():
            if attempts_left > 0:
                self.root.after(500, self._resume_scan_after_sleep, attempts_left - 1)
            return
        self._start_scan_if_idle()

    # ------------------------------------------------------------------
    # Network Health Monitor
    #
    # Single background thread polling once in RUNTIME.network_poll_interval_sec
    # (at least once per second) - both during scanning and idle time:
    # 1) presence of a network - ctypes + GetAdaptersAddresses (physical link + gateway,
    #      regardless of the system VPN state - see _is_internet_connected
    #   2) while _vpn_relied_upon - ifIndex/availability of VPN adapter via
    #      GetAdaptersAddresses(get_interface_info). Changing ifIndex without long
    #      down = reconnect user; adapter missing when owned-tunnel = drop
    #      without PowerShell-confirm (otherwise a quick Disconnect→Connect would cancel
    #      recovery). For “System” VPN confirmation via get_vpn_connected,
    #      with rate-limit ~3 s.
    #
    # VPN-invalidation goes to _on_vpn_session_invalidated → short settle →
    # connect_and_route or force-refresh routes. General pause pipeline
    # sleep/network loss: _pause_for_connectivity_issue / _finish_recovery_guard.
    # UI transitions - only from the GUI thread (root.after).
    # ------------------------------------------------------------------

    def _start_network_health_monitor(self) -> None:
        if platform.system() != "Windows":
            return
        threading.Thread(target=self._network_health_loop, daemon=True).start()

    def _network_health_loop(self) -> None:
        # vpn may be None (the module did not load) - the monitor is still the same
        # should monitor network loss via _is_internet_connected.
        was_up: Optional[bool] = True
        internet_up_since: Optional[float] = None
        # The cycle rotates in rapid increments (RUNTIME.vpn_watch_poll_interval_sec), but
        # expensive physical check (_is_internet_connected(), full bypass
        # GetAdaptersAddresses) executes no more often than RUNTIME.network_poll_interval_sec
        # (see comment for RUNTIME fields). On intermediate "fast" ticks
        # only the cheap _poll_vpn_health_tick() is executed (see _VpnSessionWatch).
        next_internet_check_mono = 0.0
        while not self._app_stop_event.wait(RUNTIME.vpn_watch_poll_interval_sec):
            if time.monotonic() < next_internet_check_mono:
                # Intermediate “fast” tick - only VPN health, cadence
                # We do not touch the physical network check.
                if self._rs.vpn_watch_inactive:
                    continue
                self._poll_vpn_health_tick()
                continue
            next_internet_check_mono = time.monotonic() + RUNTIME.network_poll_interval_sec

            try:
                up = self._is_internet_connected()
            except Exception:
                logger.debug("is_internet_connected() failed", exc_info=True)
                up = None
            if up is None:
                continue

            # --- Internet vs VPN ---
            # _is_internet_connected() looks at the physical adapter (GetAdaptersAddresses)
            # and excludes VPN adapters (PPP/Tunnel), so
            # does not go out just by disconnecting the VPN tunnel while the physical network is alive.
            # Debounce below is insurance against a very short physical link flop. If
            # the scanner relies on a VPN (or VPN-recovery is in progress), a break in the VPN itself is a separate issue
            # VPN branch below, not _on_internet_lost.
            if not up:
                if self._rs.intentional_reset_active:
                    # The physical interface is deliberately omitted by OUR worker (Wi-Fi soft reset /
                    # adapter restart). This is not a connectivity event: debounce is not fired, was_up /
                    # epoch/VPN are not affected. The verdict comes from the worker’s post-check: if the link is not
                    # returned, he himself escalates to _on_internet_lost; if the flag is removed, but the network is still
                    # not yet, the next tick will start the debounce from scratch.
                    self._internet_down_since = None
                    internet_up_since = None
                    continue
                was_up = False
                internet_up_since = None
                # Debounce real network loss. Do not skip the tick when _vpn_relied_upon:
                # a zombie VPN can stay Connected after uplink loss and must be
                # force-killed by _on_internet_lost.
                # Only debounce 2.5 s protects against a short flap of a physical link, and not
                # "eternal" ignore.
                now = time.monotonic()
                if self._internet_down_since is None:
                    self._internet_down_since = now
                if (now - self._internet_down_since) >= RUNTIME.debounce_sec:
                    self._post_to_gui(self._on_internet_lost)
                # In parallel, you can watch ifIndex VPN (for logs/early
                # invalidate), but this is NOT a replacement for internet_lost.
                if (
                    not self._rs.vpn_watch_inactive
                    and vpn is not None
                ):
                    self._poll_vpn_health_tick()
                continue

            # up == True
            self._internet_down_since = None
            if not was_up:
                # Debounce and on "up" (symmetrical to "down" above, 2.5 s):
                # on flappy network instant _on_internet_restored on first
                # True tick would lead to frequent restarts if the network
                # still continues to twitch back and forth.
                now = time.monotonic()
                if internet_up_since is None:
                    internet_up_since = now
                if (now - internet_up_since) >= RUNTIME.debounce_sec:
                    was_up = True
                    internet_up_since = None
                    self._post_to_gui(self._on_internet_restored)
                else:
                    continue
            else:
                internet_up_since = None

            if self._rs.vpn_watch_inactive:
                continue
            self._poll_vpn_health_tick()
            
    def _is_internet_connected(self) -> Optional[bool]:
        """Principle: GetAdaptersAddresses
        (IP Helper), not WinInet InternetGetConnectedState.

        InternetGetConnectedState is not suitable: when the system VPN is raised (first
        L2TP queue) it reflects the state of the tunnel, not the physical network, and after
        real break, the uplink still shows “connected” for a few more minutes, until
        Windows itself will not crash the VPN session. For a monitor that should
        detecting a break in seconds is unacceptable.

        Looks for at least one adapter in the Up state that is physical (not
        PPP/Tunnel - this is how most VPNs rise - and not loopback) and have
        designated gateway.

        Returns True/False, or None on non-Windows or API error. None NOT
        should be interpreted as "no network": the calling code should simply ignore
        such a tick, and not consider it a break signal.

        iphlpapi bindings (WinDLL, _IP_ADAPTER_ADDRESSES, argtypes/restype)
        moved to the modular level (see block above _WIFI_PROFILE_NAME_RE) -
        so as not to recreate them for each call from the monitor.
        """
        if platform.system() != "Windows":
            return None
        if not _IPHLPAPI_AVAILABLE:
            # On non-Windows this is already cut off above, and on Windows it is missing
            # bindings means that iphlpapi.dll did not load - the same
            # “I don’t know” scenario, same as when there is a call error.
            return None
        try:
            flags = _GAA_FLAG_INCLUDE_GATEWAYS | _GAA_FLAG_INCLUDE_PREFIX

            size = wintypes.ULONG(0)
            rc = _GetAdaptersAddresses(
                _AF_UNSPEC, flags, None, None, ctypes.byref(size)
            )
            if rc != _ERROR_BUFFER_OVERFLOW and rc != _ERROR_SUCCESS:
                logger.debug(
                    "_is_internet_connected: GetAdaptersAddresses (size) failed: %s", rc
                )
                return None
            if size.value == 0:
                return False

            buf = ctypes.create_string_buffer(size.value)
            p_addrs = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
            rc = _GetAdaptersAddresses(
                _AF_UNSPEC, flags, None, p_addrs, ctypes.byref(size)
            )
            if rc != _ERROR_SUCCESS:
                logger.debug(
                    "_is_internet_connected: GetAdaptersAddresses failed: %s", rc
                )
                return None

            current = p_addrs
            while current:
                adapter = current.contents
                if (
                    adapter.OperStatus == _IF_OPER_STATUS_UP
                    and adapter.IfType not in (
                        _IF_TYPE_PPP, _IF_TYPE_TUNNEL, _IF_TYPE_SOFTWARE_LOOPBACK,
                    )
                    and adapter.FirstGatewayAddress
                ):
                    return True
                current = adapter.Next
            return False
        except Exception:
            logger.debug(
                "_is_internet_connected (GetAdaptersAddresses) failed", exc_info=True
            )
            return None

    def _adopt_vpn_routes_from_response(self, resp: Dict[str, Any]) -> None:
        """Get the list of installed ones from the response vpn.connect_and_route()
        routes and the current session in _vpn_watch.

        Called from background workers (precheck, reconnect) immediately after
        successful connect_and_route. The answer could have come from an old version
        vpn.py without routes/if_index fields - then the mirror simply remains
        empty, and the route loss detector is silently turned off, and the check
        session identity continues to work."""
        if vpn is None:
            return
        routes = resp.get("routes")
        if_index = resp.get("if_index")
        try:
            self._vpn_watch.set_routes(
                routes,
                if_index_fallback=int(if_index) if if_index is not None else None,
            )
        except Exception:
            logger.debug("Failed to remember our VPN routes", exc_info=True)
            return
        # At the same time, we record the session to which these routes are tied: otherwise
        # The very first tick of the monitor would compare a fresh snapshot with an empty prev.
        try:
            _state, session = vpn.get_vpn_session_state(
                self.scanner.vpn_connection_name
            )
            self._vpn_watch.adopt(session)
        except Exception:
            logger.debug("get_vpn_session_state() after connect_and_route failed", exc_info=True)

    def _poll_vpn_health_tick(self) -> None:
        """One tick of VPN session verification. Only with _vpn_relied_upon and not during
        recovery. Called both when the network is live and when _is_internet_connected() ==
        False (for example, the physical network has disappeared regardless of the VPN state).

        All the logic of “same session or not” is in _VpnSessionWatch: adapter status
        (missing/OperStatus) and its traffic counters via GetIfEntry2, plus control
        that our /32 is still in the routing table (tri-state everywhere).
        IfIndex comparison is not enough for the most common scenario - fast
        manual Disconnect→Connect when RAS raises a new tunnel on the same
        ifIndex, and the routes have already been demolished.
        """
        assert vpn is not None
        if self._rs.vpn_watch_inactive:
            return
        name = self.scanner.vpn_connection_name
        if not name:
            return
        try:
            state, session = vpn.get_vpn_session_state(name)
        except Exception:
            logger.debug("get_vpn_session_state() failed", exc_info=True)
            state, session = vpn.VpnSessionState.UNKNOWN, None

        if state is vpn.VpnSessionState.UP:
            assert session is not None
            reason = self._vpn_watch.check(session)
            if reason:
                self._post_to_gui(self._on_vpn_session_invalidated, reason)
            return

        if state is vpn.VpnSessionState.UNKNOWN:
            # A single iphlpapi failure is not a reason to invalidate the session.
            # The semantics are the same as in _VpnSessionWatch.check(): “I don’t know” ≠
            # “session invalidated.” Especially important for the owned branch below,
            # where there is no PowerShell confirmation (deliberately a race with
            # fast reconnect), and the false owned_interface_down takes away the GUI
            # in full recovery (scan pause, cleanup, dial again) due to
            # single API failure.
            logger.debug(
                "VPN session lookup returned UNKNOWN (GetAdaptersAddresses "
                "unavailable) — treating the tick as inconclusive "
                "(no watch reset, no invalidate)."
            )
            return

        # state is VpnSessionState.DOWN - there is definitely no adapter.
        self._vpn_watch.reset()
        if self._vpn_owned_by_us:
            # Owned: without PowerShell-confirm (race with fast reconnect).
            self._post_to_gui(self._on_vpn_session_invalidated, "owned_interface_down")
            return
        # System: rate-limited confirm via get_vpn_connected.
        now = time.monotonic()
        if now - self._last_system_vpn_confirm_mono < 3.0:
            return
        self._last_system_vpn_confirm_mono = now
        self._post_to_gui(self._confirm_vpn_dropped)

    def _confirm_vpn_dropped(self) -> None:
        """Confirm drop for "System" VPN via get_vpn_connected."""
        epoch = self._net_epoch
        if self._rs.vpn_watch_inactive:
            return
        if self._vpn_owned_by_us:
            self._on_vpn_session_invalidated("owned_interface_down")
            return
        if self._vpn_drop_confirm_pending:
            return
        self._vpn_drop_confirm_pending = True
        threading.Thread(
            target=self._confirm_vpn_dropped_worker,
            args=(epoch,),
            daemon=True,
            name="vpn-drop-confirm",
        ).start()

    def _confirm_vpn_dropped_worker(self, epoch: int) -> None:
        assert vpn is not None
        sc = self.scanner
        try:
            still_up = vpn.get_vpn_connected(
                sc.vpn_connection_name, all_user=sc.vpn_connection_all_user
            )
        except Exception:
            logger.debug("get_vpn_connected (drop confirmation) failed", exc_info=True)
            still_up = None
        # NOT bool(still_up) here: get_vpn_connected() returns three
        # states (True/False/None), and None ("PowerShell did not respond
        # /error/scope is ambiguous") is NOT the same as
        # "VPN has definitely dropped." bool(None) == False would silently turn
        # temporary PowerShell failure due to confirmed VPN failure and
        # would trigger a false recovery/reconnect. We send triple
        # the condition continues as is.
        self._post_to_gui(
            self._on_vpn_drop_confirm_done,
            epoch,
            still_up,
        )

    def _on_vpn_drop_confirm_done(self, epoch: int, still_up: Optional[bool]) -> None:
        # The flag is reset BEFORE checking the epoch: the worker terminated in any case, and
        # The era changes not only in _on_internet_lost (the only place where the flag
        # reset manually), but also when applying VPN settings, in
        # _schedule_resume_after_recovery and _on_vpn_session_invalidated. Otherwise
        # the legacy result would leave the flag cocked forever, and
        # _confirm_vpn_dropped() would silently refuse to fire new confirmations.
        self._vpn_drop_confirm_pending = False
        if epoch != self._net_epoch:
            return
        if still_up is None:
            # State could not be determined (PowerShell timeout/error,
            # or scope is ambiguous) - we do not consider this confirmed
            # VPN crash. Next monitor tick (or next
            # rate-limited confirm) will check again; We don't break anything.
            logger.debug(
                "VPN drop confirmation inconclusive (get_vpn_connected returned "
                "None) — leaving session state as-is, will re-check next tick."
            )
            return
        if still_up:
            logger.debug(
                "VPN drop suspicion was a false positive (fast check vs get_vpn_connected)."
            )
            return
        self._on_vpn_session_invalidated("system_vpn_down")

    def _on_vpn_session_invalidated(self, reason: str) -> None:
        """The VPN session that was relied upon is no longer valid."""
        # Check + “occupation” recovery - atomically relative
        # begin_intentional_reset() worker: otherwise between check and
        # recovery_in_progress=True the worker would have time to start L2-reset over
        # already starting VPN-recovery.
        with self._rs.lock:
            if self._rs.vpn_watch_inactive:
                return
            self._rs.recovery_in_progress = True
        logger.warning("VPN session invalidated (%s).", reason)
        was_owned = self._vpn_owned_by_us
        self._rs.vpn_relied_upon = False
        self._rs.vpn_owned_by_us = False
        self._rs.reset_episode()
        self._vpn_watch.reset()
        # Always VPN status, not “No Internet”.
        self._set_vpn_status("vpn_state_disconnected")
        self._pause_for_connectivity_issue()
        self._rs.bump_epoch()
        epoch = self._net_epoch
        self._check_recovery_invariants("vpn_session_invalidated")
        # First, synchronously (in the background, but BEFORE reconnect-worker) we clear ownership
        # and SplitTunneling - otherwise settle may see Connected on the profile
        # with SplitTunneling=True and take split to be “full system”.
        if was_owned and vpn is not None and vpn.IS_WINDOWS:
            threading.Thread(
                target=self._vpn_invalidate_cleanup_then_reconnect,
                args=(epoch,),
                daemon=True,
            ).start()
        else:
            threading.Thread(
                target=self._vpn_reconnect_retry_worker, args=(epoch,), daemon=True
            ).start()

    def _vpn_invalidate_cleanup_then_reconnect(self, epoch: int) -> None:
        """Owned session: restore SplitTunneling + routes + unregister, then reconnect."""
        self._clear_owned_vpn_routes_worker()
        if epoch != self._net_epoch:
            return
        self._vpn_reconnect_retry_worker(epoch)

    def _clear_owned_vpn_routes_worker(self) -> None:
        """restore_split_tunnel → remove_routes → unregister, without disconnect."""
        assert vpn is not None
        try:
            if not vpn.is_helper_alive(timeout=0.8):
                return
            try:
                resp = vpn.send_command({"cmd": "restore_split_tunnel"}, timeout=4.0)
                logger.info("restore_split_tunnel after invalidate: %s", resp)
            except Exception:
                logger.warning("restore_split_tunnel after VPN invalidate failed", exc_info=True)
            try:
                vpn.send_command({"cmd": "remove_routes"}, timeout=5.0)
            except Exception:
                logger.debug("remove_routes after VPN invalidate failed", exc_info=True)
            try:
                vpn.send_command({"cmd": "unregister_client"}, timeout=10.0)
            except Exception:
                logger.debug("unregister_client after VPN invalidate failed", exc_info=True)
        except Exception:
            logger.debug("clear owned VPN routes worker failed", exc_info=True)

    def _pause_for_connectivity_issue(self) -> None:
        """Single point to pause scanning for any reason of loss
        connectivity. Idempotent and safe for overlapping calls
        several detectors in a row: is_scanning could already be False
        due to another detector that worked a little earlier - so it’s a fact
        "scanning was active" is remembered once every
        _scan_was_running_before_pause and is not overwritten back to False
        subsequent calls to this method."""
        self._set_controls_enabled(False) 
        # Precheck - not yet is_scanning, but the user has already pressed Start /
        # autostart Without this wake/network break during “Network check...”
        # does not set _scan_was_running_before_pause, bump_epoch kills
        # in-flight worker, and _finish_recovery_guard only unlocks
        # buttons with the text “Checking the network...” forever.
        if self._precheck_in_progress:
            self._scan_was_running_before_pause = True
            self._precheck_in_progress = False

        if self.scanner.is_scanning:
            self._scan_was_running_before_pause = True
            self.scanner.request_stop()
            # request_stop() generation does not change - without this, the results
            # already in the Tk queue would be accepted as current.
            self._invalidate_scan_callbacks()
            try:
                self.scanner.close_all_sessions()
            except Exception:
                logger.debug("close_all_sessions on connectivity pause failed", exc_info=True)
            try:
                self.scanner.abort_active_responses()
            except Exception:
                logger.debug("abort_active_responses on connectivity pause failed", exc_info=True)
            self.scan_btn.config(text=self.scanner.s("btn_start"))
            # scan_thread is still alive (we just called request_stop), but
            # is_scanning is already False - refresh itself will take both signs into account.
            self._refresh_vpn_chk_state()
            # We remove “scanning” from all lines of the tree immediately, without
            # waiting for the background scan_loop to reach
            # _reset_scanning_tags: at the moment of pause, its workers can be
            # while still in flight, and the blue backlight will linger on the screen until
            # seconds (and if circumstances are unfortunate, see rollback
            # last_index in scan_loop/_apply_batch_results - not at all
            # will go away until the user starts scanning again). Further
            # scan_loop attempts to remove a tag from a specific index are no-op.
            self._reset_all_scanning_tags()

    def _record_path_quality_from_result(self, res: "ScanResult") -> None:
        """Call from scan_loop (background thread) after future.result().

        A sample is considered "elevated" (suspicious of path degradation) if the
        channel has ANY of two independent signs:

          * cc_err >= path_quality_cc_threshold — loss of TS packets, the classic
            symptom of a "clogged" path;
          * bitrate < error_bitrate_kbps — the channel connected, chunks arrive intact
            and without gaps (otherwise it would have been filtered as CONNECT_FAILED),
            but path throughput fell below the minimum. That is how a "degraded but
            still alive path" looks after a failed Wi-Fi reconnect: the TCP session
            is up, there are no errors, yet the speed is an order of magnitude below normal.

        Both signs feed the same soft-recovery pipeline (path_quality_samples →
        _maybe_start_soft_path_recovery → _path_quality_recovery_worker →
        _network_recovery_aggressive): for the rest of the logic this is a single
        "path to udpxy is misbehaving, try resetting it" event.
        """
        # added/test channels do not participate in path quality assessment: they
        # are obviously unreliable as an indicator (typically non-existent
        # udp-IP), and any contribution to path_quality_samples would distort
        # share elevated in the window.
        if _name_has_prefix(res.channel.name, self.scanner.no_alert_prefixes):
            return
        if self._rs.any_recovery_active:
            return
        if res.status in (Status.CONNECT_FAILED, Status.INTERNAL_ERROR, Status.NOT_TS):
            return
        metrics = res.metrics
        if metrics is None or metrics.total_ts_packets < RUNTIME.path_quality_min_ts_packets:
            return
        continuity_errors = sum(
            metrics.continuity_errors_by_pid.get(pid, 0) for pid in metrics.video_pids
        )
        # Radio channels are excluded from the bitrate branch: they have a low
        # bitrate is the norm (audio only, typically 128-320 kbps), not
        # a symptom of pathway degradation. If they participated here, it would be enough
        # a large playlist with radio stations would be enough to
        # the elevated share exceeded path_quality_elevated_ratio itself
        # yourself, without any network degradation, and soft recovery would start
        # "from scratch."
        elevated = (
            continuity_errors >= RUNTIME.path_quality_cc_threshold
            or (
                res.status != Status.RADIO
                and metrics.bitrate_kbps < self.scanner.thresholds.error_bitrate_kbps
            )
        )
        trigger = False
        with self._path_quality_lock:
            self._path_quality_samples.append(elevated)
            max_n = RUNTIME.path_quality_window
            if len(self._path_quality_samples) > max_n:
                self._path_quality_samples = self._path_quality_samples[-max_n:]
            n = len(self._path_quality_samples)
            if n >= RUNTIME.path_quality_min_samples:
                bad = sum(1 for x in self._path_quality_samples if x)
                if bad / n >= RUNTIME.path_quality_elevated_ratio:
                    trigger = True
                    self._path_quality_samples.clear()
        if trigger:
            self._post_to_gui(
                self._maybe_start_soft_path_recovery, "path_quality_cc_err"
            )

    def _maybe_start_soft_path_recovery(self, reason: str = "path_quality") -> bool:
        """GUI flow: soft recovery (hygiene + force routes).

        General entrance for:
          - elevated cc_err (path_quality) - can be repeated by cooldown;
          - several all-CONNECT_FAILED batches in a row - once per episode;
          - unsuccessful post-probe in precheck - once per episode.

        Returns True if the worker is actually running, False if one of them is triggered
        early exits (closing / recovery already in progress / cooldown / episodic flag).
        The result is needed `_on_precheck_done` so as not to leave it cocked
        `_scan_was_running_before_pause` when nothing was running.
        """
        if self._closing or self._path_recovery_in_progress:
            return False
        if self._rs.network_recovery_active:
            return False

        is_path_quality = reason == "path_quality_cc_err"
        if not is_path_quality and self._soft_recovery_attempted:
            logger.info(
                "Soft path recovery skipped (already attempted this episode), reason=%s",
                reason,
            )
            return False

        now = time.monotonic()
        if now - self._path_recovery_last_mono < RUNTIME.path_quality_recovery_cooldown_sec:
            logger.debug(
                "Soft path recovery suppressed by cooldown (%.0f s left), reason=%s",
                RUNTIME.path_quality_recovery_cooldown_sec
                - (now - self._path_recovery_last_mono),
                reason,
            )
            return False

        self._rs.path_recovery_last_mono = now
        self._rs.path_recovery_in_progress = True
        self._precheck_ok_mono = None
        # The epoch is captured here on the GUI thread, IMMEDIATELY after the checks above
        # (all _net_epoch increments also come from the GUI thread), so between
        # There is no window for the race with the “run” solution and capturing the epoch.
        epoch = self._net_epoch
        self._rs.path_recovery_epoch = epoch
        self._rs.path_recovery_reason = reason
        if not is_path_quality:
            self._rs.soft_recovery_attempted = True
        self._rs.connect_fail_batch_streak = 0
        logger.warning(
            "Soft path recovery starting (reason=%s) — "
            "flush DNS/ARP, refresh VPN routes, then re-precheck",
            reason,
        )
        # We disable controls for the entire recovery time, regardless of whether it was in progress
        # whether the scan was at the time of triggering. Recovery touches physical L2/
        # DNS/ARP/VPN routes; any playlist download started in
        # this window (F5 or click on the playlist button), doomed - HTTP request
        # will either go into disabled Wi-Fi or slip through a narrow window
        # reconnection without ARP/DNS. The user will see a false popup
        # "Failed to load playlist." Real gate for F5 -
        # check `any(btn.instate(["disabled"]))` in _on_f5_reload_playlist;
        # it is this call that switches the buttons to disabled so that gate
        # worked.
        self._set_controls_enabled(False)
        if self.scanner.is_scanning:
            self._scan_was_running_before_pause = True
            self.scanner.request_stop()
            self._invalidate_scan_callbacks()
            self._set_stopping_ui()
            try:
                self.scanner.abort_active_responses()
            except Exception:
                logger.debug("abort_active_responses in soft path recovery failed", exc_info=True)
        else:
            # The scan was not launched, but recovery is still in progress. Label on
            # scan_btn ("⏳ Checking the network...") reflects that something is currently
            # occurs in the background and the scan cannot be started: disabled button
            # above, and _on_path_quality_recovery_done will return it to idle
            # (or in the precheck phase) when recovery is complete.
            self.scan_btn.config(text=self.scanner.s("btn_precheck"))
        threading.Thread(
            target=self._path_quality_recovery_worker,
            args=(epoch, reason),
            daemon=True,
            name="soft-path-recovery",
        ).start()
        return True

    def _network_hygiene_light(self, *, flush_gateway_arp: bool = True) -> None:
        """Easy cache hygiene: flushdns (+ optional ARP+ping of the physical gateway).

          * `ipconfig /flushdns` flushes the DNS cache. Useful for any trigger:
            after sleep/hibernation, network recovery and VPN reconnection
            (split-horizon DNS breaks down when changing DNS servers);
          * ARP flush + ping for GATEWAY physical adapter. Real L2 neighbor of the client
            - gateway, not remote udpxy (traffic to it goes through the gateway, and ARP records
            for the proxy host there is no client table - `arp -d <proxy_ip>` would be
            no-op). Gateway ARP reset and immediate ping force entry
            be re-resolved immediately, and not at the first outgoing packet. After reboot
            router (a common cause of a “dead” path), this sometimes helps without completely
            adapter reset.

        DOES NOT touch interface counters/sessions - there is a tool for that
        _network_recovery_aggressive().

        Parameters:
          flush_gateway_arp=True - ARP+ping the gateway. Disabled when called from
            _on_vpn_reconnected: VPN reconnection does not affect physical L2,
            there is nothing to reset, and the extra ping is just noise on the network.
        """
        if platform.system() != "Windows":
            return

        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True,
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            logger.info("Network hygiene (light): ipconfig /flushdns done")
        except Exception:
            logger.debug("ipconfig /flushdns failed", exc_info=True)

        if not flush_gateway_arp:
            return

        if vpn is None or not vpn.IS_WINDOWS or not vpn.is_helper_alive(timeout=1.0):
            return

        try:
            gateway = vpn.get_physical_gateway_ip()
        except Exception:
            logger.debug("get_physical_gateway_ip failed", exc_info=True)
            gateway = None

        if not gateway:
            logger.debug(
                "Network hygiene (light): physical gateway not determined — "
                "ARP/ping skipped"
            )
            return

        try:
            resp = vpn.send_command(
                {"cmd": "arp_flush", "ips": [gateway]},
                timeout=6.0,
                connect_timeout=1.5,
            )
            if resp.get("ok"):
                logger.info(
                    "Network hygiene (light): ARP flush for gateway %s", gateway
                )
        except Exception:
            logger.debug("arp_flush (gateway) via helper failed", exc_info=True)
            return

        try:
            vpn.send_command(
                {"cmd": "ping_probe", "host": gateway},
                timeout=6.0,
                connect_timeout=1.5,
            )
        except Exception:
            logger.debug("ping_probe (gateway) via helper failed", exc_info=True)

    def _network_recovery_aggressive_lite(
        self, reason: str, epoch: Optional[int]
    ) -> bool:
        """Lite version without vpn.py: only Wi-Fi soft reset.

        The default route is not checked: in the lite build Ethernet-restart
        is impossible (an elevated helper is needed), so distinguishing between "Wi-Fi -
        active default" and "Wi-Fi just connected" make no sense. Restart
        Wi-Fi, even if the traffic goes over Ethernet, is harmless."""
        profile = get_active_wifi_profile_local()
        if not profile:
            logger.warning(
                "Aggressive network recovery (lite): no active Wi-Fi profile — "
                "Ethernet restart needs the elevated helper (unavailable); "
                "skipping reset (reason=%s)", reason,
            )
            return True

        started, resp = self._run_intentional_l2_reset(
            kind="wifi_soft_reset",
            label=f"Wi-Fi soft reset (profile={profile!r}, lite)",
            cmd_fn=functools.partial(_wifi_soft_reset_local, profile),
            cmd_timeout=45.0,
            epoch=epoch,
            reason=reason,
        )
        if not started:
            logger.info(
                "Aggressive network recovery (lite): context is stale "
                "(net_epoch/recovery/closing) — reset cancelled",
            )
            return False
        if resp is None:
            logger.debug("wifi_soft_reset (lite) via netsh failed")
            return True
        if resp.get("ok"):
            logger.info(
                "Wi-Fi soft reset succeeded (profile=%r, lite, reason=%s)",
                profile, reason,
            )
        else:
            logger.warning(
                "Wi-Fi soft reset failed: %s (profile=%r, lite, reason=%s)",
                resp.get("error"), profile, reason,
            )
        return True

    def _network_recovery_aggressive(
        self, reason: str = "unknown", epoch: Optional[int] = None
    ) -> bool:
        """Hard restoration of the L2 state for the case of a cc_err stream.

Empirically:
          * easy hygiene (DNS + gateway ARP) and `ipconfig /renew` from the cc_err flow is not
            help;
          * helps the full 802.11 disconnect-connect cycle (same as
            the user does it manually in the list of networks);
          * there is no analogue on the wire, but re-creation of the interface object in the kernel (netsh
            disable/enable) may help if the problem is in the NIC driver.

Branches according to the type of active physical adapter:
          * wifi -> wifi_soft_reset {profile};
          * ethernet -> helper: adapter_restart {interface_name};
          * other/None -> does nothing, just logs (which adapter is active -
            we're not guessing).

Called only from _path_quality_recovery_worker, that is, after
        stop scanning: Wi-Fi reconnection will not disconnect active
        connections in the middle of work.

Protection from an outdated solution. Between the start of recovery and the helper command
        A noticeable amount of time passes (helper check, adapter detection, netsh request
        profile), during which a new connectivity event can occur. Therefore directly
        Before a destructive command, two checks are performed:
          1) a repeated snapshot of active physical transport must coincide with
             by which strategy was selected (type and ifIndex); otherwise, for example, when
             connecting an Ethernet in the middle of recovery would “treat” Wi-Fi, which is no longer
             the cause of the problem;
          2) atomic RESERVATION of the epoch under reset - RecoveryState.
             begin_intentional_reset(): application does not close, `epoch` does not
             changed, there is no higher priority recovery (_internet_down /
             _recovery_in_progress), and under the same lock is cocked
             intentional_network_reset. Checking and platooning the flag are one indivisible
             operation: _on_internet_lost / _on_vpn_session_invalidated (take the same
             castle) either get there early and the reset is cancelled, or they see the flag and don’t
             react to the expected loss of a link.

Controlled episode. While the flag is cocked, NetworkHealthMonitor does not count
        loss of network by connectivity event (does not call _on_internet_lost, does not bump
        epoch) and VPN watch is paused (vpn_watch_inactive). Flag
        is removed in finally, then post-check is executed (see.
        _run_intentional_l2_reset): physical link → escalation to _on_internet_lost,
        if the link does not return → VPN check (_poll_vpn_health_tick) → normal
        precheck (VPN routes + probe to udpxy) in _on_path_quality_recovery_done.
        The residual window (milliseconds to open a named pipe) cannot be eliminated
        without passing the epoch to the helper itself.

Returns False if reset is CANCELED as obsolete (new event, closing
        windows, transport change) - the caller does not need to continue the pipeline. True - in
        in all other cases (reset completed, failed, or was not required)."""
        if platform.system() != "Windows":
            return True

        # vpn.py is not available (lite assembly by one IPTV_scanner.exe) or we are not
        # on a Windows module. Ethernet restart is not possible without an elevated helper;
        # Wi-Fi soft reset works via netsh wlan connect/connect (not
        # requires administrator rights) and the active profile is determined via
        # WLAN API locally. Let's go to the simplified branch.
        if vpn is None:
            return self._network_recovery_aggressive_lite(reason, epoch)

        try:
            info = vpn.get_active_physical_adapter_info()
        except Exception:
            logger.debug("get_active_physical_adapter_info failed", exc_info=True)
            info = None

        kind = (info or {}).get("kind") if info else None

        def _transport_state() -> Optional[bool]:
            """Three-state: True - the same, False - different, None - I don’t know.

            None from get_active_physical_adapter_info() (or its exception)
            does not mean “the transport has changed”, but “could not read
            adapter table" - single iphlpapi failure. Same principle
            tri-state as in _VpnSessionWatch / _confirm_vpn_dropped:
            “I don’t know” should not turn into “same” or “different”.

            You cannot cancel a destructive reset using “I don’t know”: it is silent
            skips recovery due to a single Win32 API failure,
            when reset is exactly what is needed (the path has degraded, and the definition
            transport simply failed on this beat).
            """
            try:
                now = vpn.get_active_physical_adapter_info()
            except Exception:
                logger.debug(
                    "get_active_physical_adapter_info (re-snapshot) failed",
                    exc_info=True,
                )
                return None
            if not now:
                return None
            return bool(
                now.get("kind") == kind
                and now.get("if_index") == (info or {}).get("if_index")
            )

        def _cancel(why: str) -> bool:
            logger.info(
                "Aggressive network recovery cancelled: %s "
                "(kind=%s, reason=%s, epoch=%s -> %s)",
                why, kind, reason, epoch, self._net_epoch,
            )
            return False

        if kind == "wifi":
            try:
                profile = get_active_wifi_profile_local()
            except Exception:
                logger.debug("get_active_wifi_profile_local failed", exc_info=True)
                profile = None
            if not profile:
                logger.warning(
                    "Aggressive network recovery: active Wi-Fi profile "
                    "not determined — wifi_soft_reset skipped (reason=%s)",
                    reason,
                )
                return True
            state = _transport_state()
            if state is False:
                return _cancel("active physical transport changed")
            if state is None:
                logger.info(
                    "Aggressive network recovery: could not re-read the "
                    "active physical adapter (GetAdaptersAddresses failed) — "
                    "proceeding with the reset as if transport were unchanged "
                    "(reason=%s, kind=%s)", reason, kind,
                )
            # state is True or None → continue
            # 45 s: helper is busy at worst ~30 s (disconnect 5 +
            # pause 1.5 + connect 8 + wait Connected up to 15), plus
            # reserve for slow netsh.
            started, resp = self._run_intentional_l2_reset(
                kind="wifi_soft_reset",
                label=f"Wi-Fi soft reset (profile={profile!r})",
                cmd_fn=functools.partial(_wifi_soft_reset_local, profile),
                cmd_timeout=45.0,
                epoch=epoch,
                reason=reason,
            )
            if not started:
                return _cancel("context is stale (net_epoch/recovery/closing)")
            if resp is None:
                logger.debug("wifi_soft_reset via helper failed")
                return True
            if resp.get("ok"):
                if resp.get("reconciled"):
                    logger.info(
                        "Wi-Fi soft reset: netsh connect failed, but "
                        "the adapter returned to Connected (profile=%r, reason=%s)",
                        profile, reason,
                    )
                else:
                    logger.info(
                        "Wi-Fi soft reset succeeded (profile=%r, reason=%s)",
                        profile, reason,
                    )
            else:
                logger.warning(
                    "Wi-Fi soft reset failed: %s (profile=%r, reason=%s)",
                    resp.get("error"), profile, reason,
                )
            return True

        if kind == "ethernet":
            iface = (info or {}).get("name") or ""
            if not iface:
                logger.warning(
                    "Aggressive network recovery: active Ethernet adapter "
                    "not determined — adapter_restart skipped (reason=%s)",
                    reason,
                )
                return True
            if not vpn.is_helper_alive(timeout=1.0):
                logger.warning(
                    "Aggressive network recovery: elevated helper unavailable — "
                    "Ethernet adapter restart skipped (reason=%s)", reason,
                )
                return True
            state = _transport_state()
            if state is False:
                return _cancel("active physical transport changed")
            if state is None:
                logger.info(
                    "Aggressive network recovery: could not re-read the "
                    "active physical adapter (GetAdaptersAddresses failed) — "
                    "proceeding with the reset as if transport were unchanged "
                    "(reason=%s, kind=%s)", reason, kind,
                )
            # state is True or None → continue
            started, resp = self._run_intentional_l2_reset(
                kind="adapter_restart",
                label=f"Ethernet adapter restart ({iface!r})",
                cmd_fn=functools.partial(
                    vpn.send_command,
                    {"cmd": "adapter_restart", "interface_name": iface},
                    timeout=60.0, connect_timeout=1.5,
                ),
                cmd_timeout=60.0,
                epoch=epoch,
                reason=reason,
            )
            if not started:
                return _cancel("context is stale (net_epoch/recovery/closing)")
            if resp is None:
                logger.debug("adapter_restart via helper failed")
                return True
            if resp.get("ok"):
                logger.info(
                    "Ethernet adapter restart succeeded (%r, reason=%s)",
                    iface, reason,
                )
            else:
                logger.warning(
                    "Ethernet adapter restart failed: %s (iface=%r, reason=%s)",
                    resp.get("error"), iface, reason,
                )
            return True

        logger.warning(
            "Aggressive network recovery: active adapter type not "
            "determined (info=%r, reason=%s) — reset skipped",
            info, reason,
        )
        return True

    def _check_recovery_invariants(self, where: str) -> None:
        """Diagnostics: logs impossible combinations of recovery flags
        (see RecoveryState.invariant_violations). The condition does not change."""
        try:
            bad = self._rs.invariant_violations()
        except Exception:
            logger.debug("invariant_violations failed", exc_info=True)
            return
        if bad:
            logger.error(
                "RecoveryState invariant violated at %s: %s (phase=%s, "
                "epoch=%s)", where, "; ".join(bad), self._rs.phase,
                self._rs.epoch,
            )

    def _force_kill_vpn_before_l2_reset(self, epoch: Optional[int]) -> None:
        """Kill the VPN we rely on BEFORE running the destructive L2 reset.

        See _run_intentional_l2_reset for the rationale. Mirrors the
        post-check force-kill block (same epoch guard, same ownership/routes
        snapshot, same _force_kill_vpn_worker) — the only difference is
        *when* it runs: before cmd_fn(), while the network is still up.
        """
        if vpn is None or not vpn.IS_WINDOWS:
            return
        if not self._rs.vpn_relied_upon:
            return
        if epoch is not None and epoch != self._net_epoch:
            return
        sc = self.scanner
        if not sc.vpn_connection_name:
            return
        # Same snapshot and same reset sequence as in
        # _on_internet_lost before running _force_kill_vpn_worker:
        # order is important because the fuse is inside
        # _force_kill_vpn_worker for the System session is checked
        # exactly with this photo /32.
        owned_snapshot = self._rs.vpn_owned_by_us
        routes_snapshot_list = self._vpn_watch.routes()
        self._vpn_watch.reset()
        self._rs.vpn_relied_upon = False
        self._rs.vpn_owned_by_us = False
        logger.warning(
            "Aggressive network recovery: force-killing VPN %r before the "
            "L2 reset (owned=%s, tracked_routes=%d) — the L2 being reset "
            "carries the tunnel; doing this now avoids a zombie VPN for the "
            "whole outage.",
            sc.vpn_connection_name, owned_snapshot, len(routes_snapshot_list),
        )
        self._force_kill_vpn_worker(
            sc.vpn_connection_name,
            sc.vpn_connection_all_user,
            owned_snapshot,
            epoch if epoch is not None else self._net_epoch,
            routes_snapshot_list,
        )
        self._post_to_gui(self._set_vpn_status, "vpn_state_disconnected")

    def _run_intentional_l2_reset(
        self,
        *,
        kind: str,
        label: str,
        cmd_fn: Callable[[], Optional[Dict[str, Any]]],
        cmd_timeout: float,
        epoch: Optional[int],
        reason: str,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Executes a destructive L2 command to helper as CONTROLLED
        episode: reservation → command → waiting for a link → removing the flag
        (always, in finally) → post-check.

        Returns (started, resp):
          started=False - reservation rejected (context is out of date), command
            NOT sent;
          started=True, resp=None - the command was sent, but send_command failed
            exception (reset may have been partially completed, so waiting
            link and post-check are still executed).
        """
        max_sec = (
            cmd_timeout
            + RUNTIME.l2_reset_link_wait_sec
            + RUNTIME.l2_reset_flag_margin_sec
        )
        if not self._rs.begin_intentional_reset(
            epoch, kind, max_sec, self._closing
        ):
            return False, None
        logger.warning(
            "Aggressive network recovery: %s (reason=%s, epoch=%s, phase=%s)",
            label, reason, epoch, self._rs.phase,
        )
        self._check_recovery_invariants("l2_reset_begin")

        # Kill the VPN we rely on BEFORE the destructive L2 reset.
        #
        # The L2 we're about to reset carries the VPN tunnel, so the tunnel
        # will end up a "zombie" once the link goes down (RAS PPP adapter
        # stays Up for dozens of seconds after the underlying L2 has
        # vanished — see the comment block further below). Killing the VPN
        # now, while the network is still up, is the clean path:
        #   * the disconnect runs against a live link (no hung pipe/
        #     PowerShell calls against a broken network);
        #   * during the whole L2 outage Windows shows the VPN as genuinely
        #     Disconnected instead of a misleading "Connected";
        #   * when the link comes back, there is no zombie to fight with —
        #     the previous behaviour killed the VPN *after* the network had
        #     already come back (in the post-check below), which looked like
        #     "VPN stayed up through the outage, then flickered off and
        #     instantly dialed back in".
        self._force_kill_vpn_before_l2_reset(epoch)

        resp: Optional[Dict[str, Any]] = None
        link_state: Optional[bool] = None
        try:
            try:
                resp = cmd_fn()
            except Exception:
                logger.debug("%s command failed", label, exc_info=True)
            link_state = self._await_physical_link_after_reset(epoch)
        finally:
            # The flag is ALWAYS removed. Debounce network loss starts from scratch:
            # everything that the monitor “accumulated” during reset is irrelevant.
            self._rs.end_intentional_reset()
            self._internet_down_since = None
            self._check_recovery_invariants("l2_reset_end")

        # ── post-check (the flag has already been removed - then the usual mechanisms work) ─
        if link_state is False:
            logger.warning(
                "Post-check after %s: physical connectivity did not recover "
                "within %.0f s — the reset did not help, escalating to the 'network lost' path.",
                kind, RUNTIME.l2_reset_link_wait_sec,
            )
            # Same path as the monitor: pause, epoch++, force-kill VPN.
            # Debounce is not needed - the link has already been missing for the entire waiting window.
            self._post_to_gui(self._on_internet_lost)
            return True, resp
        logger.info(
            "Post-check after %s: physical link %s.", kind,
            "restored" if link_state else "state not confirmed",
        )

        # Update the watch state for the session we are NOT
        # touched (for example, if _force_kill_vpn_worker decided that before
        # We already have a fresh System session, and missed disconnect). If we
        # VPN just turned off, vpn_relied_upon is already False, and tick
        # will come out immediately.
        if vpn is not None and not self._rs.vpn_watch_inactive:
            try:
                self._poll_vpn_health_tick()
            except Exception:
                logger.debug("post-reset VPN health tick failed", exc_info=True)
        # Proxy/udpxy: _on_path_quality_recovery_done → _start_scan_if_idle →
        # precheck (probe).
        return True, resp

    def _await_physical_link_after_reset(self, epoch: Optional[int]) -> Optional[bool]:
        """Waits for physical connectivity to become “up” and hold
        RUNTIME.l2_reset_link_stable_sec continuously (but no longer
        RUNTIME.l2_reset_link_wait_sec).

        True - recovered and stable;
        False — at the time of the timeout, “down” was POSITIVELY observed;
        None - no verdict: the check returned None (API failure), window
                the era is closing / has changed (someone is already leading it), or
                the link was blinking and was not stable at the deadline.
        """
        deadline = time.monotonic() + RUNTIME.l2_reset_link_wait_sec
        stable_need = RUNTIME.l2_reset_link_stable_sec
        up_since: Optional[float] = None
        last: Optional[bool] = None
        while True:
            if self._closing or self._app_stop_event.is_set():
                return None
            if epoch is not None and epoch != self._net_epoch:
                logger.info(
                    "Waiting for the link after L2 reset interrupted: epoch %s -> %s "
                    "(a newer connectivity event owns the situation).",
                    epoch, self._net_epoch,
                )
                return None
            try:
                up = self._is_internet_connected()
            except Exception:
                logger.debug("is_internet_connected() after L2 reset failed", exc_info=True)
                up = None
            now = time.monotonic()
            if up is True:
                last = True
                if up_since is None:
                    up_since = now
                if now - up_since >= stable_need:
                    return True
            elif up is False:
                last = False
                up_since = None
            # up is None - “I don’t know”: we neither reset nor advance the timer.
            if now >= deadline:
                return False if last is False else None
            self._app_stop_event.wait(0.5)

    def _post_to_gui(self, fn, *args) -> bool:
        """Single entry point for callbacks from background threads in the GUI:
        `root.after(0, fn, *args)`, safe when closing - if the window
        closes or Tk is already destroyed, the callback is simply not planned
        (without exception in daemon thread). Returns True if callback
        queued.

        ALL calls from non-GUI threads must go through this method (or
        via _post_to_gui_coalesced) rather than via direct root.after().
        The exception is _close_worker: it puts root.destroy AFTER
        cocking _closing, therefore must bypass this guard."""
        if self._closing:
            return False
        try:
            self.root.after(0, fn, *args)
            return True
        except (RuntimeError, tk.TclError):
            logger.debug("root.after unavailable (shutdown) — callback skipped", exc_info=True)
            return False

    def _post_to_gui_coalesced(self, key: str, fn, *args) -> None:
        """Like _post_to_gui, but with “last one wins” semantics: for now
        the callback with this key has not yet been executed, the repeated call does NOT add
        the second element in the Tk queue, but only replaces fn/args in the already
        standing. For events of the “update status” type - intermediate values
        they would have been immediately erased anyway.

        Do not use for events where every call or order is important
        various events (network loss ↔ restoration, etc.)."""
        with self._gui_coalesced_lock:
            already_pending = key in self._gui_coalesced
            self._gui_coalesced[key] = (fn, args)
        if already_pending:
            return
        if not self._post_to_gui(self._run_coalesced, key):
            with self._gui_coalesced_lock:
                self._gui_coalesced.pop(key, None)

    def _run_coalesced(self, key: str) -> None:
        with self._gui_coalesced_lock:
            entry = self._gui_coalesced.pop(key, None)
        if entry is None:
            return
        fn, args = entry
        fn(*args)

    def _path_quality_recovery_worker(self, epoch: int, reason: str = "unknown") -> None:
        """Background worker soft recovery. `epoch` — the value of _net_epoch at the moment
        recovery decisions (see _maybe_start_soft_path_recovery); if it
        time to change, destructive steps are not carried out."""
        self._rs.path_recovery_deferred = False
        try:
            # 1) Join scan_thread first (timeout: IPTVScanner.thread_join_timeout).
            # Soft recovery must not flush DNS/ARP/routes under a still-running scan
            # (stale sockets vs new routes). If join times out, skip hygiene this run
            # and retry from the GUI when the thread dies (see
            # _on_path_quality_recovery_done / _retry_deferred_path_recovery).
            t = self.scan_thread
            if t is not None and t.is_alive():
                t.join(timeout=self.scanner.thread_join_timeout)
                if t.is_alive():
                    self._rs.path_recovery_deferred = True
                    logger.warning(
                        "Path-quality recovery: scan_thread is still alive "
                        "after thread_join_timeout (%.1f s) — skipping "
                        "hygiene/route-refresh this time so the network is not "
                        "changed under a still-running scan; "
                        "will retry once the thread has actually finished.",
                        self.scanner.thread_join_timeout,
                    )
                    return

            try:
                self.scanner.close_all_sessions()
            except Exception:
                logger.debug("close_all_sessions in path recovery failed", exc_info=True)

            # While this worker was waiting for scan_thread to stop, a more serious problem could begin
            # recovery (Internet/VPN loss, see _on_internet_lost /
            # _on_vpn_session_invalidated). Checks in GUI functions
            # (_maybe_start_path_quality_recovery, etc.) won’t help here: worker
            # launched. Hygiene/force-refresh over the ongoing recovery are not performed - that
            # will do this itself after connectivity is restored.
            #
            # Checking via _net_epoch - the same scheme as in reconnect/force-kill
            # workers: any connectivity event (network loss, VPN invalidation, awakening,
            # closing the window) increments epoch. Flags alone are not enough: an event can
            # come and go (or not set a flag yet) between checking and destructive
            # team. Flags - additional insurance; final check is repeated
            # immediately before the helper command (see _network_recovery_aggressive).
            if self._closing or epoch != self._net_epoch:
                logger.info(
                    "Path-quality recovery: stale (net_epoch %s -> %s, "
                    "closing=%s) — a newer connectivity event owns "
                    "recovery, skipping.",
                    epoch, self._net_epoch, self._closing,
                )
                return
            if self._rs.network_recovery_active:
                logger.debug(
                    "Path-quality recovery: a higher-priority "
                    "recovery (network/VPN) is active — skipping hygiene, deferring to it."
                )
                return

            # 2) Aggressive recovery: light hygiene from cc_err stream
            # useless (see _network_recovery_aggressive); need either
            # Wi-Fi soft reset, or (for wire) reset adapter.
            if not self._network_recovery_aggressive(reason=reason, epoch=epoch):
                return  # canceled as obsolete - no pause needed

            # wait(), not sleep(): we wake up immediately when the window is closed.
            if self._app_stop_event.wait(RUNTIME.path_quality_hygiene_pause_sec):
                return
        except Exception:
            logger.exception("path quality recovery worker failed")
        finally:
            self._post_to_gui(self._on_path_quality_recovery_done)

    def _on_path_quality_recovery_done(self) -> None:
        self._rs.path_recovery_in_progress = False
        if self._closing or self._rs.network_recovery_active:
            # Repetition is no longer needed; reset deferred, otherwise guard
            # (see path_recovery_active) would wait for it forever.
            self._rs.path_recovery_deferred = False
            return
        if self._path_recovery_deferred:
            # The previous scan_thread was still alive - hygiene/route-refresh
            # were not executed (see _path_quality_recovery_worker). UI
            # leave it in “Stops...”/disabled and just wait until
            # the thread will actually die in order to safely retry -
            # without this the user would be left without hygiene/refresh at all,
            # silently.
            # deferred remains True until the second worker starts (his
            # resets _retry_deferred_path_recovery): while it is set,
            # recovery for guard is “still in progress” (path_recovery_active).
            self.root.after(500, self._retry_deferred_path_recovery)
            return
        if self._rs.path_recovery_epoch != self._rs.epoch:
            # While soft recovery was working, a newer event happened
            # connectivity (wake up / restore network / reconnect
            # VPN) - it has already scheduled _finish_recovery_guard or
            # will schedule it upon completion of its chain, and it is guard
            # owns renewal (with post-wake delay). If we
            # resumed the scan here, it would have started before the guard pause, and
            # guard would then turn on the buttons in the middle of precheck.
            logger.info(
                "Path-quality recovery finished but is stale (epoch %s -> %s): "
                "resumption is left to the guard.",
                self._rs.path_recovery_epoch, self._rs.epoch,
            )
            return
        if self._scan_was_running_before_pause:
            self._scan_was_running_before_pause = False
            self._set_controls_enabled(False)
            self.scan_btn.config(text=self.scanner.s("btn_precheck"))
            self._start_scan_if_idle()
        else:
            self._set_controls_enabled(True)
            self._set_idle_ui()

    def _retry_deferred_path_recovery(self) -> None:
        """Repeat after the previous soft recovery run
        delayed because scan_thread has not completed yet (see
        _path_quality_recovery_worker). Polls scan_thread short
        approaches - the same technique as _resume_scan_after_sleep - and how
        only it really died, it restarts the worker directly (this
        continuation of an already started recovery attempt, rather than a new one: not
        should trip over the episodic flag _soft_recovery_attempted or
        cooldown _maybe_start_soft_path_recovery)."""
        if self._closing or self._rs.network_recovery_active:
            self._rs.path_recovery_deferred = False
            return
        if self.scan_thread is not None and self.scan_thread.is_alive():
            self.root.after(500, self._retry_deferred_path_recovery)
            return
        # in_progress is set BEFORE resetting deferred: path_recovery_active neither
        # does not become False momentarily between attempts.
        self._rs.path_recovery_in_progress = True
        self._rs.path_recovery_deferred = False
        # Repetition is a continuation of the same attempt: the era and reason are original.
        # If the epoch has changed during the delay, the worker himself will see this and
        # will not take destructive steps.
        threading.Thread(
            target=self._path_quality_recovery_worker,
            args=(self._path_recovery_epoch, self._path_recovery_reason),
            daemon=True,
            name="soft-path-recovery-retry",
        ).start()

    def _maybe_schedule_recovery_resume(
        self, guard_sec: Optional[float] = None
    ) -> None:
        """Schedules resuming only if there are no active causes for pause.

        guard_sec=None → RUNTIME.post_wake_guard_sec (sleep/network loss).
        After a clean accept system VPN we transmit 0: full-tunnel is already
        ensured, waiting for post_wake is pointless and gives ~8 from “silence”.
        """
        if self._rs.network_recovery_active:
            return
        self._rs.bump_epoch()
        epoch = self._net_epoch
        if guard_sec is None:
            guard_sec = RUNTIME.post_wake_guard_sec
        delay_ms = max(0, int(float(guard_sec) * 1000))
        if delay_ms == 0:
            self.root.after(0, self._finish_recovery_guard, epoch)
        else:
            self.root.after(delay_ms, self._finish_recovery_guard, epoch)

    def _finish_recovery_guard(self, epoch: int) -> None:
        if epoch != self._net_epoch:
            return
        if self._rs.network_recovery_active:
            return
        if self._rs.path_recovery_active:
            self.root.after(500, self._finish_recovery_guard, epoch)
            return
        self._set_controls_enabled(False)
        threading.Thread(
            target=self._finish_recovery_guard_worker,
            args=(epoch,),
            daemon=True,
            name="finish-recovery-guard",
        ).start()

    def _finish_recovery_guard_worker(self, epoch: int) -> None:
        try:
            key = self._query_vpn_status_from_reality()
            if key is not None:
                self._post_to_gui(self._set_vpn_status, key)
        except Exception:
            logger.debug("_query_vpn_status_from_reality failed in worker", exc_info=True)
        self._post_to_gui(self._finish_recovery_guard_resume, epoch)

    def _finish_recovery_guard_resume(self, epoch: int) -> None:
        if epoch != self._net_epoch:
            return
        if self._rs.network_recovery_active or self._rs.path_recovery_active:
            return
        if self._scan_was_running_before_pause:
            self._scan_was_running_before_pause = False
            self._set_controls_enabled(False)
            self.scan_btn.config(text=self.scanner.s("btn_precheck"))
            self._resume_scan_after_sleep()
        else:
            self._set_controls_enabled(True)
            self._set_idle_ui()

    def _set_no_internet_status(self) -> None:
        """Shows "Network: No Internet" in place of the VPN status."""
        if vpn is None or self._closing or not vpn.IS_WINDOWS:
            return
        self.vpn_status_label.config(text=self.scanner.s("label_no_internet"))
        self.vpn_status_label.pack(side="right", anchor="e")

    def _on_internet_lost(self) -> None:
        if self._internet_down:
            return

        # The solution "our own L2-reset or real network loss"
        # is accepted atomically with internet_down set (the same lock as
        # at begin_intentional_reset): either we see the flag and nothing
        # we do, or the worker will see internet_down and will not start the reset.
        with self._rs.lock:
            if self._rs.intentional_reset_active:
                suppressed = True
            else:
                suppressed = False
                was_recovering = self._rs.recovery_in_progress
                self._rs.internet_down = True
                self._rs.recovery_in_progress = False
        if suppressed:
            logger.info(
                "Internet-down ignored: controlled %s in progress (epoch=%s) — "
                "the verdict will come from the worker's post-check.",
                self._rs.intentional_reset_kind or "L2 reset",
                self._rs.intentional_reset_epoch,
            )
            self._internet_down_since = None
            return

        # Do not skip this tick for recovery_in_progress/_vpn_relied_upon — same
        # zombie-VPN force-kill rationale as in the network-loss debounce above.
        if was_recovering:
            logger.info(
                "Internet lost during VPN recovery — cancelling reconnect, "
                "switching to no-internet state."
            )
        if self._vpn_relied_upon:
            logger.info(
                "Internet lost while VPN status still Connected (zombie tunnel) "
                "— force-kill VPN and pause scan."
            )

        self._rs.vpn_relied_upon = False
        # Snapshot of our routes BEFORE reset: for System VPN (owned=False, see below)
        # this is the only signal that allows you to distinguish "same" before disconnect
        # tunnel from a new session that the user could raise manually until
        # The worker has not yet reached rasdial_disconnect (TOCTOU race, see
        # _force_kill_vpn_worker). Comparison by ifIndex/local_ip (vpn.same_session())
        # not suitable for this: RAS almost always saves both fields for any
        # reconnecting the same profile, and they prove nothing.
        routes_snapshot_list = self._vpn_watch.routes()
        self._vpn_watch.reset()
        self._vpn_drop_confirm_pending = False
        self._rs.bump_epoch()  # cancel VPN reconnect-worker/guard
        self._check_recovery_invariants("internet_lost")

        self._set_no_internet_status()
        logger.warning("Internet connectivity lost (physical link check).")
        self._pause_for_connectivity_issue()

        sc = self.scanner

        owned_snapshot = self._vpn_owned_by_us
        self._rs.vpn_owned_by_us = False
        self._rs.reset_episode()
        # epoch is already increased above (self._rs.bump_epoch()) - grab it
        # here and pass it to the worker so that he can detect that the event
        # which spawned it is deprecated (see _force_kill_vpn_worker).
        epoch = self._net_epoch
        if sc.vpn_connection_name and vpn is not None and vpn.IS_WINDOWS:
            threading.Thread(
                target=self._force_kill_vpn_worker,
                args=(sc.vpn_connection_name, sc.vpn_connection_all_user,
                      owned_snapshot, epoch, routes_snapshot_list),
                daemon=True,
            ).start()

    def _force_kill_vpn_worker(
        self, name: str, all_user: Optional[bool], owned: bool, epoch: int,
        routes_snapshot_list: Optional[List[Tuple[str, int]]] = None,
    ) -> None:
        assert vpn is not None
        # Race: the network could recover (and epoch increase again, see
        # _on_internet_restored -> _maybe_schedule_recovery_resume) between launches
        # worker and the moment when it reaches disconnect. Then the user or
        # Windows could have already raised the VPN again, and disconnect_and_unroute() (it
        # determines “whose” VPN it is through ownership on the elevated helper side, and not by
        # picture taken here) risks disconnecting the NEW, legitimate session, and not the one
        # due to the loss of which the worker was launched. Therefore epoch is checked
        # immediately before a destructive action - the same principle as in
        # reconnect/guard-workers.
        # Called in two modes:
        #   * from the GUI thread (_on_internet_lost) - like a daemon thread via
        #     threading.Thread because _on_internet_lost itself cannot
        #     block on pipe/PowerShell;
        #   * from the worker thread (_run_intentional_l2_reset after
        #     successful L2 reset) - synchronously, because there is a need
        #     ensure that by the time you return the VPN is already disabled
        # (otherwise the next precheck in the pipeline will see “connected”
        #     and will go down the wrong branch).
        # Logic and all checks (epoch, verification of routes for System sessions)
        # are the same in both modes and do not depend on who exactly
        # called the method.
        if epoch != self._net_epoch:
            logger.info(
                "Force-kill VPN skipped: net_epoch changed (%s -> %s) — "
                "a newer connectivity event superseded this one, likely "
                "internet came back before the kill ran.",
                epoch, self._net_epoch,
            )
            return
        try:
            if owned:
                # Our session: disconnect_and_unroute()/release_and_disconnect
                # checks ownership atomically on the elevated helper side
                # just before shutdown, so the window for this
                # The specific TOCTOU race is already closed there at the server level.
                vpn.disconnect_and_unroute(base_path, name, all_user=all_user)
            else:
                # System/external VPN: rasdial_disconnect() does not know about ownership and breaks
                # connection by name. If between the epoch check above and this call
                # the user manually raised a NEW connection with the same name, we disabled
                # it would be him, and not the dead session due to which the worker was launched. epoch is not here
                # protects: it describes the internal state of recovery, not identity
                # VPN adapter. Therefore, immediately before disconnect identity session
                # is checked again.
                #
                # Comparison by ifIndex or ifIndex + local_ip proves almost nothing: RAS
                # reuses both index and local IP when reconnecting the same
                # profile. A reliable independent sign - are ours alive /32: Windows is blowing away
                # routes bound to the interface along with it, so if they are in place,
                # the interface has not fallen apart since then.
                #
                # The direction of caution here is the opposite _on_internet_restored: there
                # destructive to TAKE ownership, so positive proof is needed
                # "same session". Here it is destructive to DISCONNECT, but there is a complete refusal to disconnect
                # would leave the zombie tunnel hanging, so disconnect is only passed when
                # clear signs that we have another session ahead of us.
                skip = False
                skip_reason = ""
                cur_session = None
                try:
                    _cur_state, cur_session = vpn.get_vpn_session_state(name)
                except Exception:
                    logger.debug(
                        "get_vpn_session_state() re-check before force-kill failed",
                        exc_info=True,
                    )
                if routes_snapshot_list and cur_session is not None:
                    try:
                        snap = vpn.routes_snapshot()
                        alive, total = vpn.count_alive_routes(routes_snapshot_list, snap)
                    except Exception:
                        logger.debug("routes re-check before force-kill failed", exc_info=True)
                        alive, total = 1, 1  # we don’t know - we don’t interfere with kill
                    if total > 0 and alive == 0:
                        skip = True
                        skip_reason = (
                            f"all {total} of our routes are gone while the adapter is up — "
                            f"the tunnel was re-established since recovery started"
                        )
                if skip:
                    logger.warning(
                        "Force-kill (system VPN) skipped: %s — looks like a "
                        "fresh user-initiated session, not the one that "
                        "triggered recovery.",
                        skip_reason,
                    )
                if not skip:
                    vpn.rasdial_disconnect(name, all_user=all_user)
        except Exception:
            logger.exception(
                "Failed to force-disconnect VPN after internet loss"
            )

    def _on_internet_restored(self) -> None:
        if not self._internet_down:
            return
        self._rs.internet_down = False
        
                # Fast network flap: force-kill may not have disconnected our VPN yet
        # while epoch already advanced. Do NOT reclaim ownership here — session
        # identity is not reliable (RAS ifIndex/local_ip survive reconnects).
        # Losing ownership is safe (session becomes "System"); taking a foreign
        # one is not (later invalidate would restore_split_tunnel /
        # release_and_disconnect on a user-raised tunnel). Ownership is only
        # taken when we dial ourselves (see _vpn_reconnect_retry_worker).
        logger.info(
            "Internet connectivity restored. Waiting %.0f s guard period before resuming.",
            RUNTIME.post_wake_guard_sec,
        )
        
        threading.Thread(
            target=self._network_hygiene_light,
            daemon=True, name="hygiene-after-net",
        ).start()
        
        self._update_vpn_status_visibility()
        self._set_vpn_status_from_reality_async()   # return "Disabled"/"System" instead of "No Internet"
        self._maybe_schedule_recovery_resume()

    def _apply_connect_and_route_result(
        self,
        resp: Dict[str, Any],
        *,
        already_up_before: bool,
        status_key: str = "vpn_status",
    ) -> Optional[str]:
        """Parse vpn.connect_and_route() and update GUI state.

        When already_up_before=True the tunnel was up before this call, so
        resp["we_connected"] is always False and must not drive ownership —
        use self._rs.vpn_owned_by_us instead. Treating we_connected as truth
        would drop ownership on every route-refresh precheck of our own
        session (label → "System", helper still owner_pid=us, later
        invalidate skips restore_split_tunnel/remove_routes/unregister_client).
        """
        if not resp.get("ok"):
            return "failed"

        if already_up_before:
            we = self._rs.vpn_owned_by_us
        else:
            we = bool(resp.get("we_connected"))
        self._rs.vpn_owned_by_us = we
        self._adopt_vpn_routes_from_response(resp)

        state_key = "vpn_state_connected" if we else "vpn_state_system"
        self._post_to_gui_coalesced(status_key, self._set_vpn_status, state_key)
        return "owned" if we else "system"

    def _vpn_reconnect_retry_worker(self, epoch: int) -> None:
        """After invalidate: settle → if the user is already Connected - System
        without dial; otherwise dial our tunnel (Connection → Connected).

        Before dialing, check get_vpn_connected again. SplitTunneling
        The profile should already have been restored by cleanup by this time.

        The result of ensure is checked. If ok=False - short repetitions
        (ensure he retraits inside). After several failures
        Connected we still accept “System” so that the scan comes to life.
        If you've ever seen Connected, never dial/prepare_split
        over a custom VPN (ultra-fast toggle race).
        """
        assert vpn is not None
        sc = self.scanner

        def _accept_as_system(where: str, *, full_tunnel_ok: bool) -> None:
            """Mark System and uncheck recovery. full_tunnel_ok is for log only."""
            if full_tunnel_ok:
                logger.info("Accepting system VPN (%s) with full-tunnel ensured", where)
            else:
                logger.warning(
                    "Accepting system VPN (%s) WITHOUT confirmed full-tunnel — "
                    "scan resumes; corporate traffic may still miss the tunnel",
                    where,
                )
            self._rs.vpn_owned_by_us = False
            # We take the current session as the starting point of observation.
            # The routes do not go here yet.
            # When VpnSessionState.UNKNOWN/DOWN session == None - this is normal:
            # _VpnSessionWatch.adopt(None) means “there is nothing to watch yet,
            # We will establish a session at the next successful tick."
            try:
                _state, session = vpn.get_vpn_session_state(sc.vpn_connection_name)
                self._vpn_watch.adopt(session)
            except Exception:
                logger.debug("get_vpn_session_state() in _accept_as_system failed", exc_info=True)
            self._post_to_gui_coalesced("vpn_status", self._set_vpn_status, "vpn_state_system")
            self._post_to_gui(
                functools.partial(self._on_vpn_reconnected, epoch, run_hygiene=False),
            )

        def _try_accept_system_vpn(where: str) -> bool:
            # We accept the system VPN as is: we don’t touch the profile
            # (SplitTunneling), no routes (no ensure_default_route -
            # see comment in _precheck_worker). If after accepted
            # system-VPN will find that proxy hosts are unavailable, this
            # will be corrected by the next precheck (cache is invalidated via
            # bump_epoch in _on_vpn_reconnected) - vpn.connect_and_route
            # will add /32 routes without affecting the profile.
            _accept_as_system(where, full_tunnel_ok=True)
            return True

        # True, if Connected was seen at least once in this worker - after
        # this CANNOT be called connect_and_route/prepare_split: otherwise we break it
        # system VPN just installed by the user (typical race
        # superfast toggle when get_vpn_connected flashes False).
        saw_connected = False
        ensure_fail_streak = 0
        # How many times in a row ensure failed with Connected before
        # accept the System “as is” (the scan should come to life; full-tunnel
        # ensure has already made several internal attempts).
        ENSURE_FAIL_ACCEPT_AFTER = 3
        # Short backoff between ensure when Connected (not 18 s - otherwise
        # The scan is “silent” for too long, and with a false down it also goes to dial).
        ENSURE_RETRY_SEC = 1.2

        settle_deadline = time.monotonic() + RUNTIME.vpn_reconnect_grace_sec
        while time.monotonic() < settle_deadline:
            if self._rs.superseded_or_offline(epoch):
                return
            # A quick sign of “the user has already connected a VPN”:
            # FriendlyName of adapter + IPv4 (ctypes), without PowerShell.
            # “VPN connected” = adapter found AND IPv4 assigned:
            # adapter without IPv4 (FOUND with local_ip=None) - this is either
            # a rising tunnel, or already descending; for this thread
            # settle needs a ready-to-use VPN, so we require
            # local_ip.
            try:
                lookup_state, session = vpn.get_vpn_session_state(
                    sc.vpn_connection_name
                )
            except Exception:
                logger.debug("get_vpn_session_state (settle) failed", exc_info=True)
                lookup_state, session = vpn.VpnSessionState.UNKNOWN, None
            if (
                lookup_state is vpn.VpnSessionState.UP
                and session is not None
                and session.local_ip
            ):
                saw_connected = True
                logger.info(
                    "VPN adapter up during %.1f s settle after invalidate "
                    "(ifIndex=%s) — trying system full-tunnel (no dial).",
                    RUNTIME.vpn_reconnect_grace_sec, session.if_index,
                )
                if _try_accept_system_vpn("settle"):
                    return
                ensure_fail_streak += 1
                if self._app_stop_event.wait(0.25):
                    return
                continue
            if self._app_stop_event.wait(0.2):
                return

        if self._rs.superseded_or_offline(epoch):
            return

        fail_times: List[float] = []
        warned = False
        while True:
            if self._rs.superseded_or_offline(epoch):
                return

            connected_now = None
            try:
                connected_now = vpn.get_vpn_connected(
                    sc.vpn_connection_name,
                    all_user=sc.vpn_connection_all_user,
                )
            except Exception:
                logger.debug("get_vpn_connected before connect_and_route failed", exc_info=True)
                connected_now = None

            if connected_now is None:
                # The VPN state is unknown: we do not consider it disabled.
                # Otherwise, a temporary PowerShell error may result in an unnecessary dial.
                logger.warning(
                    "get_vpn_connected returned None before connect_and_route "
                    "— VPN state is unknown; retrying without dial."
                )
                if self._app_stop_event.wait(0.5):
                    return
                continue

            if connected_now:
                saw_connected = True
                if _try_accept_system_vpn("retry-loop"):
                    return
                ensure_fail_streak += 1
                if ensure_fail_streak >= ENSURE_FAIL_ACCEPT_AFTER:
                    # ensure exhausted internal + external attempts but VPN
                    # Connected. We accept System so that the scan does not remain
                    # dead; full-tunnel could already finish off Windows itself.
                    _accept_as_system("retry-loop-fallback", full_tunnel_ok=False)
                    return
                self._post_to_gui_coalesced("vpn_status", self._set_vpn_status, "vpn_state_connecting")
                deadline = time.monotonic() + ENSURE_RETRY_SEC
                while time.monotonic() < deadline:
                    if self._rs.superseded_or_offline(epoch):
                        return
                    if self._app_stop_event.wait(0.2):
                        return
                continue

            # Not Connected. If you were recently Connected - NOT dial: this
            # false down in race toggle. Looking forward to seeing Connected again.
            if saw_connected:
                logger.info(
                    "VPN not Connected after earlier Connected — waiting "
                    "(skip dial to avoid prepare_split over system VPN)"
                )
                self._post_to_gui_coalesced("vpn_status", self._set_vpn_status, "vpn_state_connecting")
                deadline = time.monotonic() + ENSURE_RETRY_SEC
                while time.monotonic() < deadline:
                    if self._rs.superseded_or_offline(epoch):
                        return
                    if self._app_stop_event.wait(0.2):
                        return
                continue

            self._post_to_gui_coalesced("vpn_status", self._set_vpn_status, "vpn_state_connecting")
            hosts = self._extract_proxy_hosts()
            try:
                resp = vpn.connect_and_route(
                    base_path, sc.vpn_connection_name, hosts,
                    all_user=sc.vpn_connection_all_user,
                )
            except Exception:
                logger.exception("VPN reconnect: connect_and_route raised an exception")
                resp = {"ok": False, "error": "exception", "we_connected": False}

            if self._rs.superseded_or_offline(epoch):
                return

            outcome = self._apply_connect_and_route_result(
                resp, already_up_before=False,
            )
            if outcome != "failed":
                self._post_to_gui(self._on_vpn_reconnected, epoch)
                return

            now = time.monotonic()
            fail_times.append(now)
            fail_times[:] = [
                t for t in fail_times if now - t <= RUNTIME.vpn_reconnect_fail_window_sec
            ]
            logger.warning(
                "VPN reconnect attempt failed (%d in last %.0f s): %s",
                len(fail_times), RUNTIME.vpn_reconnect_fail_window_sec, resp.get("error"),
            )
            if len(fail_times) >= RUNTIME.vpn_reconnect_fail_threshold and not warned:
                warned = True
                self._post_to_gui(self._show_vpn_reconnect_failed_warning, len(fail_times))

            deadline = time.monotonic() + RUNTIME.vpn_reconnect_retry_sec
            while time.monotonic() < deadline:
                if self._rs.superseded_or_offline(epoch):
                    return
                if self._app_stop_event.wait(0.2):
                    return

    def _on_vpn_reconnected(self, epoch: int, *, run_hygiene: bool = True) -> None:
        """Remove recovery after restoring the VPN.

        run_hygiene=True - after our dial / tunnel loss (DNS/ARP
        may have gone rotten). False - the user made a clean one himself
        Disconnect→Connect (system full-tunnel in settle/retry): hygiene
        is not needed there and only interferes with what has just been exposed
        full-tunnel/routes.
        """
        if epoch != self._net_epoch:
            return

        if run_hygiene:
            # VPN reconnection does not affect the physical L2, so
            # We skip the ARP part of light hygiene: there is nothing to reset,
            # and the extra ping of the gateway is just noise.
            threading.Thread(
                target=functools.partial(
                    self._network_hygiene_light, flush_gateway_arp=False
                ),
                daemon=True, name="hygiene-after-vpn",
            ).start()

        self._rs.recovery_in_progress = False
        # Accept system VPN: VPN already Connected + full-tunnel; guard is not needed.
        # Our dial/break recovery: a short settle is enough
        # (post_wake 8 s is redundant here - it is for sleep/uplinking).
        guard = 0.0 if not run_hygiene else 1.0
        self._maybe_schedule_recovery_resume(guard_sec=guard)

    def _show_vpn_reconnect_failed_warning(self, count: int) -> None:
        if self._closing:
            return
        messagebox.showwarning(
            self.scanner.s("msg_vpn_reconnect_failed_title"),
            self.scanner.s("msg_vpn_reconnect_failed", attempts=count),
            parent=self.root,
        )

    def apply_tree_colors(self) -> None:
        """Applies tag_configure to all tree tags based on the current one
        self.scanner.color_saturation. Called at startup and again -
        live - when dragging the saturation slider in the settings."""
        for tag, colors in self.scanner.effective_tree_colors().items():
            try:
                # mypy can't check **dict against keyword-only overloads
                # tag_configure() from typeshed; the dict itself is always
                # {"background": str, "foreground": str} by construction.
                self.tree.tag_configure(tag, **colors)  # type: ignore[call-overload]
            except tk.TclError:
                logger.warning("Invalid color for tree tag %r in config, skipping", tag)

    def _set_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for btn in self.playlist_buttons:
            btn.config(state=state)
        self.scan_btn.config(state=state)

    def _refresh_vpn_chk_state(self) -> None:
        """Blocks the “Use VPN” checkbox in the open settings window,
        while scanning is in progress (or its stream is still alive). Changing this
        On-the-fly states are applied immediately when closing settings - see.
        close_settings → _sett_finish_vpn_and_close: disconnect/routes
        are executed without waiting for the scan to stop, which is what gives “strange
        results." During the scan, the checkbox should be unavailable.

        The method is safe to call at any time: if the settings window is not
        open (settings_window is None) or there is no VPN section in this build
        (sett_vpn_chk not created) - simply does nothing.
        """
        chk = getattr(self, "sett_vpn_chk", None)
        combo = getattr(self, "sett_vpn_combo", None)
        if chk is None:
            return
        win = self.settings_window
        if win is None:
            return
        try:
            if not win.winfo_exists():
                return
        except tk.TclError:
            return
        busy = self.scanner.is_scanning or (
            self.scan_thread is not None and self.scan_thread.is_alive()
        )
        try:
            chk.config(state="disabled" if busy else "normal")
            # combo may not yet exist if the method was called in the
            # at the beginning of open_settings (or the settings window is not in VPN mode).
            if combo is not None:
                combo.config(state="disabled" if busy else "readonly")
        except tk.TclError:
            logger.debug("Failed to refresh VPN checkbox state", exc_info=True)

    def _init_vpn_status_label(self) -> None:
        """Shows/hides the "VPN: ..." indicator in the window header and
        sets the initial text - called once from __init__,
        right after setup_ui().

        The label is visible only if VPN fallback is generally available in this build
        (the vpn.py module was imported and we are on Windows) And the checkbox is enabled
        "Use VPN" in Settings - if the VPN user is not
        uses, showing "VPN: Disabled" all the time makes no sense: this
        carries no information and simply takes up space. Visibility further
        updated in _update_vpn_status_visibility() on every change
        this checkbox in Settings.
        """
        if vpn is None or not vpn.IS_WINDOWS:
            self.vpn_status_label.pack_forget()
            self._rs.vpn_relied_upon = False
            return
        # The real rasdial (see _precheck_worker) only happens on
        # at the start of the scan, and not here - at the __init__ stage there is a maximum start
        # elevated helper (UAC), the VPN itself is not yet up, regardless of
        # Is the "Use VPN" checkbox checked? That's why it's always here
        # honestly “Disconnected” - the label will go to “Connection” itself, like
        # only the first scan will actually begin (see _start_scan_if_idle).
        self._set_vpn_status("vpn_state_disconnected")
        self._update_vpn_status_visibility()

    def _update_vpn_status_visibility(self) -> None:
        """Shows the "VPN: ..." label if the VPN fallback is available in principle
        (module/platform) And now the “Use VPN” checkbox is enabled in Settings.
        Called from _init_vpn_status_label() and from _sett_apply_vpn_result(), i.e.
        exactly when the state of the checkbox could change.

        While there is no network (_internet_down), the label remains visible regardless of
        checkbox (see _set_no_internet_status()): there should be no Internet
        visible even if VPN is not used."""
        if vpn is None or not vpn.IS_WINDOWS:
            return
        if self._internet_down:
            self.vpn_status_label.pack(side="right", anchor="e")
            return
        if self.scanner.vpn_enabled:
            self.vpn_status_label.pack(side="right", anchor="e")
        else:
            self.vpn_status_label.pack_forget()

    def _set_vpn_status(self, state_key: str) -> None:
        """Updates the text of the "VPN: <status>" label. Like any call to widgets
        Tk, called only from the GUI thread (deciding the state in the background thread
        delivered via _post_to_gui).

        At the same time, it centrally supports _vpn_relied_upon - the only flag
        which NetworkHealthMonitor decides whether to monitor the VPN adapter (see
        _network_health_loop): "rely on the tunnel" exactly when the label
        shows "Connected" or "System"."""
        if vpn is None or not vpn.IS_WINDOWS:
            return
        self.vpn_status_label.config(
            text=self.scanner.s("label_vpn_status", state=self.scanner.s(state_key))
        )
        relied = state_key in ("vpn_state_connected", "vpn_state_system")
        self._rs.vpn_relied_upon = relied
        if not relied:
            # The session is no longer relevant - we reset the entire observation
            # (both session snapshot and route mirror) so that next time
            # Connected does not accept the new tunnel as the “same” and does not compare
            # fresh routes with the old list.
            self._vpn_watch.reset()

    def _query_vpn_status_from_reality(self) -> Optional[str]:
        """Worker-secure polling of the real VPN state.

        DOES NOT touch Tk widgets - can be called from a background thread. Returns
        status key for _set_vpn_status() or None if status
        could not be determined (in this case the caller should NOT change
        status).

        The only side effect is resetting self._rs.vpn_owned_by_us to False when
        confirmed “disabled” (need NetworkHealthMonitor
        stopped monitoring the disappeared session). Assignment of a single
        bool under GIL is atomic, no lock required.
        """
        sc = self.scanner
        if not (sc.vpn_enabled and sc.vpn_connection_name
                and vpn is not None and vpn.IS_WINDOWS):
            return "vpn_state_disconnected"

        try:
            connected = vpn.get_vpn_connected(
                sc.vpn_connection_name, all_user=sc.vpn_connection_all_user
            )
        except Exception:
            logger.exception("Failed to poll the VPN state")
            connected = None

        if connected is None:
            # Unknown (PowerShell timeout/error, scope ambiguous) is NOT
            # "definitely disabled." The else branch would have set vpn_state_disconnected, which means
            # _set_vpn_status() resets _vpn_relied_upon and the monitor would stop monitoring
            # behind the VPN adapter due to one unanswered PowerShell call (for example,
            # immediately after wake/reconnect). The status remains as is; next call or
            # The tick of the monitor will clarify it.
            logger.debug(
                "_query_vpn_status_from_reality: get_vpn_connected returned None — "
                "leaving status and _vpn_relied_upon unchanged."
            )
            return None

        if connected:
            return "vpn_state_connected" if self._vpn_owned_by_us else "vpn_state_system"
        self._rs.vpn_owned_by_us = False
        return "vpn_state_disconnected"

    def _set_vpn_status_from_reality_async(self) -> None:
        """Asynchronous version for GUI thread: starts a worker that does
        PowerShell poll (~1 sec) in the background and posts the result back to the GUI via
        _post_to_gui → _set_vpn_status.

        Concurrent calls within a second collapse: while the previous one
        polling is not completed, restart is ignored - intermediate
        the result would still be immediately overwritten by the next one, and the extra
        No one needs the PowerShell process at this moment.

        The result does NOT apply if the connectivity epoch is
        changed: newer event (network loss, invalidate VPN) itself
        will set the current status, and the outdated “System/Connected” from
        of the previous era could visually blink and return for a moment
        _vpn_relied_upon=True, forcing the monitor to monitor the already invalid
        session.
        """
        if self._closing:
            return
        epoch = self._net_epoch
        with self._vpn_status_from_reality_lock:
            if self._vpn_status_from_reality_in_progress:
                return
            self._vpn_status_from_reality_in_progress = True
        threading.Thread(
            target=self._set_vpn_status_from_reality_worker,
            args=(epoch,),
            daemon=True,
            name="vpn-status-reality",
        ).start()

    def _set_vpn_status_from_reality_worker(self, epoch: int) -> None:
        """Background worker _set_vpn_status_from_reality_async: does polling,
        checks the relevance of the epoch, posts the result to the GUI stream and removes
        in_progress flag."""
        try:
            key = self._query_vpn_status_from_reality()
            if key is None:
                return
            if epoch != self._net_epoch:
                logger.debug(
                    "_set_vpn_status_from_reality_worker: epoch changed "
                    "(%s -> %s) — dropping stale status update %r",
                    epoch, self._net_epoch, key,
                )
                return
            self._post_to_gui(self._set_vpn_status, key)
        except Exception:
            logger.debug(
                "_set_vpn_status_from_reality_worker failed", exc_info=True
            )
        finally:
            with self._vpn_status_from_reality_lock:
                self._vpn_status_from_reality_in_progress = False

    def _on_tree_configure(self, event) -> None:
        # event.widget is the tree_container, not the Treeview itself
        total = self.tree.winfo_width()
        if total < 50:
            return
        status_w = self.scanner.column_widths["status"]["width"]
        rest = max(total - status_w - 4, 100)
        name_w = int(rest * 0.50)
        bitrate_w = rest - name_w
        self.tree.column("status", width=status_w)
        self.tree.column("name", width=name_w)
        self.tree.column("bitrate", width=bitrate_w)

    def _on_tree_self_configure(self, event) -> None:
        """Recalculates the line height each time the dimensions are changed
        the tree itself (window resize, change font/DPI, show/hide
        scrollbar) - see _fit_tree_row_height."""
        self._fit_tree_row_height()

    def _tree_rows_area_height(self) -> int:
        """Height of the Treeview row area (without header), in pixels."""
        try:
            tree_h = self.tree.winfo_height()
            tree_w = self.tree.winfo_width()
        except tk.TclError:
            return 0
        if tree_h <= 1 or tree_w <= 1:
            return 0
        # Binary search for header → row boundary: for y inside header
        # identify_region() returns "heading", below - "tree"/"cell"/
        # "nothing". This is how the height of the cap is obtained without knowing the specific
        # theme and current font.
        x = max(1, min(5, tree_w - 1))
        lo, hi = 0, tree_h
        while lo < hi:
            mid = (lo + hi) // 2
            try:
                region = self.tree.identify_region(x, mid)
            except tk.TclError:
                return 0
            if region == "heading":
                lo = mid + 1
            else:
                hi = mid
        return tree_h - lo

    def _fit_tree_row_height(self) -> None:
        """Adjusts the height of the Treeview row so that the height of the area
        rows was divided by it without a remainder (or with a minimum remainder).

        ttk.Treeview when scrolling to the bottom aligns the lines according to
        the top edge of the row area. If its height is not a multiple of rowheight,
        there is an empty stripe under the last line
        (fieldbackground, white by default). When scaling
        Windows / large font absolute balance (up to rowheight
        pixels) is multiplied by the scale factor and becomes
        especially noticeable under the color line of the last channel.

        The hook hangs on the <Configure> of the tree itself (see.
        _on_tree_self_configure), therefore it is also called when manually
        resize the window, and when changing the font/DPI, and when appearing/hiding
        vertical scrollbar."""
        if not self.tree.get_children():
            return
        rows_h = self._tree_rows_area_height()
        if rows_h <= 0:
            return
        style = ttk.Style()
        # The base line height is fixed once (before the first adjustment):
        # Then we correct it and take the current value from
        # style as a “base” is impossible - the fit would begin to “float”.
        if self._base_rowheight is None:
            try:
                self._base_rowheight = int(style.lookup("Treeview", "rowheight"))
            except (TypeError, ValueError):
                self._base_rowheight = 26
            if self._base_rowheight <= 0:
                self._base_rowheight = 26
        base_h = self._base_rowheight
        # We are looking for a height in the window ±4 px from the base, giving the minimum remainder.
        # The window constraint prevents lines from visually jumping: even when
        # In a continuous resize, the height changes by a maximum of a couple of pixels.
        best_h = base_h
        best_rem = rows_h % base_h
        for h in range(max(1, base_h - 4), base_h + 5):
            rem = rows_h % h
            if rem < best_rem:
                best_rem = rem
                best_h = h
        try:
            cur = int(style.lookup("Treeview", "rowheight"))
        except (TypeError, ValueError):
            cur = base_h
        if best_h != cur:
            try:
                style.configure("Treeview", rowheight=best_h)
            except tk.TclError:
                logger.debug(
                    "Failed to adjust Treeview rowheight", exc_info=True
                )

    def on_double_click(self, event) -> None:
        item = self.tree.selection()
        if not item:
            return
        tree_idx = self.tree.index(item[0])
        with self.scanner._channels_lock:
            if not (0 <= tree_idx < len(self.scanner.channels)):
                return
            ch = self.scanner.channels[tree_idx]
        if _name_has_prefix(ch.name, self.scanner.known_scrambled_prefixes):
            messagebox.showinfo(
                self.scanner.s("msg_attention"),
                self.scanner.s("msg_scrambled_channel"),
            )
            return
        self.scanner.launch_vlc(ch.url)
        
    def _on_tree_right_click(self, event) -> None:
        """Context menu: Copy URL or result details."""
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        tree_idx = self.tree.index(item)

        with self.scanner._channels_lock:
            if not (0 <= tree_idx < len(self.scanner.channels)):
                return
            ch = self.scanner.channels[tree_idx]

        # Current values from wood
        status = self.tree.set(item, "status")
        details = self.tree.set(item, "bitrate")

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(
            label=self.scanner.s("menu_copy_url"),
            command=lambda: self._copy_to_clipboard(ch.url),
        )
        menu.add_command(
            label=self.scanner.s("menu_copy_name"),
            command=lambda: self._copy_to_clipboard(ch.display_name),
        )
        menu.add_command(
            label=self.scanner.s("menu_copy_result"),
            command=lambda: self._copy_to_clipboard(f"{status} | {details}"),
        )
        menu.add_separator()
        menu.add_command(
            label=self.scanner.s("menu_copy_all"),
            command=lambda: self._copy_to_clipboard(
                f"{ch.display_name}\n{ch.url}\n{status} | {details}"
            ),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_to_clipboard(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()          # so that the buffer is not cleared when closing

    def _start_scan_if_idle(self) -> None:
        if self.scanner.is_scanning:
            return
        if self.scan_thread is not None and self.scan_thread.is_alive():
            return
        if not self.scanner.channels:
            return
        # No point (and unsafe in terms of racing with VPN-reconnect-
        # cycle) start the scan while NetworkHealthMonitor is counting
        # connectivity is broken - as soon as the reason for the pause is removed,
        # the renewal will occur automatically through _finish_recovery_guard.
        if self._rs.any_recovery_active:
            return

        # Precheck cache: if the same network episode (epoch has not changed) and
        # successful precheck was less than RUNTIME.precheck_cache_ttl_sec ago —
        # We start the scan immediately, without blinking the disabled button for 2–5 s.
        if (
            self._precheck_ok_mono is not None
            and self._precheck_epoch == self._net_epoch
            and (time.monotonic() - self._precheck_ok_mono) < RUNTIME.precheck_cache_ttl_sec
        ):
            self._start_scan_now()
            return

        sc = self.scanner
        if sc.vpn_enabled and sc.vpn_connection_name and vpn is not None and vpn.IS_WINDOWS:
            # Checking the availability of the proxy and, if necessary, raising the VPN are performed alone
            # times before starting the scan, and not for each channel. The work runs in a background thread:
            # The TCP probe and operations with the elevated helper may take a noticeable amount of time, and the
            # the start of scans is delayed until they are completed.
            self._set_controls_enabled(False)
            # Text indication instead of a “silent” gray button - see.
            # below in _on_precheck_done,
            # where the text is returned to btn_start via _set_idle_ui().
            self.scan_btn.config(text=self.scanner.s("btn_precheck"))
            self._precheck_in_progress = True
            threading.Thread(
                target=self._precheck_worker,
                args=(PrecheckMode.VPN,),
                daemon=True, name="precheck-vpn",
            ).start()
        else:
            # VPN fallback is disabled/not configured/unavailable - but playlist hosts
            # may still not be directly accessible. Without scanning scan
            # I would start blindly and go through channels with “connection error”
            # without a single informative message. probe lives in the scanner
            # (_local_probe_hosts) and does not require a VPN or vpn.exe.
            self._set_controls_enabled(False)
            self.scan_btn.config(text=self.scanner.s("btn_precheck"))
            self._precheck_in_progress = True
            threading.Thread(
                target=self._precheck_worker,
                args=(PrecheckMode.DIRECT,),
                daemon=True, name="precheck-direct",
            ).start()

    def _start_scan_now(self) -> None:
        self.controller.start_scan_thread(self.scan_loop)
        self.scan_btn.config(text=self.scanner.s("btn_stop"))
        self._refresh_vpn_chk_state()

    def _extract_proxy_hosts(self) -> List[Tuple[str, int, str]]:
        """Unique (host, port, scheme) from the URLs of all current channels - that
        really need to check/route (playlists on Google Drive
        are always available, but the problem is access to the http proxy that distributes the streams).
        scheme is needed in vpn.connect_and_route/_local_probe_hosts, which support and
        (host, port), and (host, port, scheme) - see their docstrings.

        IPv6 LITERALS (URL like http://[2001:db8::1]:8080/...) do not result in
        get in. This is deliberate - precheck by nature cannot with them
        do nothing meaningful, and his reaction to them would be false:

          * _local_http_probe() builds the URL as f"{scheme}://{host}:{port}/".
            urlsplit().hostname returns a literal WITHOUT parentheses, so for
            IPv6 turns out to be invalid http://2001:db8::1:8080/ - TCP probe
            passes, the HTTP probe always fails. The host is classified as
            inaccessible and entails VPN-recovery for a non-existent
            reason.
          * Even if the HTTP probe were corrected, IPv6 cannot be "passed through"
            VPN" using current means: connect_and_route()/resolve_host_ips()
            resolve only A-records (getaddrinfo AF_INET) and add
            IPv4/32 routes only (see connect_and_route: "IPv6 for now"
            do not add"). The IPv6 literal cannot be found in A-records, and
            connect_and_route will return “does not resolve” - again false
            diagnostics, only now in the form of a popup “VPN did not help.”

        The subject of the precheck is “is a VPN fallback necessary”, and for IPv6 the answer is always
        “no, it won’t help.” Therefore, the correct behavior is not to touch IPv6-
        hosts in general. The IPv6 channels themselves do not break down: if the IPv6 network
        works, StreamFetcher.open_stream() will open the URL with brackets
        regularly; if the address is unreachable, the channel will receive CONNECT_FAILED in general
        OK (without false VPN recovery).
        """
        hosts: List[Tuple[str, int, str]] = []
        seen = set()
        for ch in self.scanner.channels:
            try:
                parts = urlsplit(ch.url)
            except Exception:
                continue
            host = parts.hostname
            if not host:
                continue
            # IPv6 literal? ipaddress.ip_address() distinguishes between versions; ordinary
            # hostnames throw a ValueError and move on as is.
            # Symmetric check for IPv4 is not needed here - IPv4 literal
            # passes both TCP and HTTP tests normally.
            try:
                if ipaddress.ip_address(host).version == 6:
                    continue
            except ValueError:
                pass
            scheme = (parts.scheme or "http").lower()
            try:
                port = parts.port or (443 if scheme == "https" else 80)
            except ValueError:
                continue
            key = (host, port, scheme)
            if key not in seen:
                seen.add(key)
                hosts.append(key)
        return hosts

    def _on_warmup_success(self, epoch: int) -> None:
        """GUI flow: fill precheck-cache after a successful warm-up."""
        if epoch != self._net_epoch:
            return
        if self._closing or self.scanner.is_scanning:
            return
        if self._rs.any_recovery_active:
            return
        self._precheck_ok_mono = time.monotonic()
        self._precheck_epoch = self._net_epoch
        logger.debug("Precheck warm-up: cache filled, next Start will be instant")

    def _reset_path_quality_state(self) -> None:
        """Resets the accumulated path quality state (soft recovery
        by cc_err / connect-fail streak) at the beginning of a new network episode.

        Called when the playlist changes: old _path_quality_samples/
        _connect_fail_batch_streak refer to a different set of channels and
        to another point in time, and should not be combined with new ones -
        otherwise a false cross-playlist soft recovery trigger is possible (few
        samples from the old playlist + few samples from the new one together
        exceed the threshold, although individually not a single episode
        would have achieved)."""
        with self._path_quality_lock:
            self._path_quality_samples.clear()
        self._rs.reset_episode()
        self._rs.path_recovery_last_mono = 0.0

    def _precheck_worker(self, mode: PrecheckMode) -> None:
        """Background check of proxy-host reachability (see PrecheckMode).

        VPN: probe, then connect_and_route for unreachable hosts.
        DIRECT: probe only; popup on failure.
        WARMUP: probe only; fill precheck cache if all reachable.

        Snapshots _net_epoch at start; _on_precheck_done ignores stale epochs.
        """
        sc = self.scanner
        epoch = self._net_epoch

        # Local variable, not self.*: the worker lives in a background thread,
        # the result is read in the GUI stream (_on_precheck_done). Sign up for
        # self.* and subsequent reading from another thread do not formally have
        # happens-before relationships - in practice it works due to GIL/Tk,
        # but this masks the race. We send failure_message via
        # _post_to_gui: root.after() transfers arguments to the GUI thread
        # in the standard way for Tk, there is no more race.
        failure_message: Optional[str] = None

        try:
            hosts = self._extract_proxy_hosts()
            if not hosts:
                # There is nothing to check - straight to the finals.
                self._post_to_gui(self._on_precheck_done, mode, epoch, failure_message)
                return

            # --- WARMUP: if the cache is already fresh, exit without a network ---
            if mode == PrecheckMode.WARMUP:
                if (
                    self._precheck_ok_mono is not None
                    and self._precheck_epoch == self._net_epoch
                    and (time.monotonic() - self._precheck_ok_mono)
                        < RUNTIME.precheck_cache_ttl_sec
                ):
                    return

            # WARMUP mode can “degrade” into a full-fledged VPN path,
            # if the playlist hosts are not directly accessible and the VPN is a fallback
            # enabled in settings. Without this warmup on a typical IPTV
            # playlist (proxies are only available via VPN) would leave
            # the cache is empty, and the first Start would still launch the full one
            # precheck with the blocking button “Check network...” - that is
            # the meaning of warmup would be lost. The decision is made in advance
            # (need to know whether to treat WARMUP as a VPN path) but
            # the actual delegation occurs only AFTER the probe,
            # when it is clear that the hosts are truly unreachable: if
            # probe will show that they are directly accessible, no VPN
            # not required.
            warmup_can_use_vpn = (
                mode == PrecheckMode.WARMUP
                and sc.vpn_enabled
                and bool(sc.vpn_connection_name)
                and vpn is not None and vpn.IS_WINDOWS
            )

            # --- VPN: find out the real state of the VPN BEFORE the probe ---
            #
            # get_vpn_connected() — tri-state:
            #   True - exactly connected;
            #   False - definitely disabled;
            # None—state could not be determined (PowerShell timeout/
            #           error, or scope is ambiguous).
            #
            # None is NOT "definitely disabled". bool(None) would silently turn
            # temporary failure of diagnostic API in confirmed "VPN not
            # raised", and then:
            #   * in the branch below, ownership would be reset to the already raised one
            #     our session (_rs.vpn_owned_by_us = False) - and further
            #     invalidate/cleanup/disconnect would follow the branch was_owned=False
            #     without restore_split_tunnel/remove_routes/unregister_client;
            #   * connect_and_route would follow the "re-raise" path
            #     over a live session.
            #
            # Therefore, None behaves like “I don’t know”: we don’t touch ownership,
            # pipeline to probe continues (probe is still useful -
            # if the hosts are available, VPN is not needed now), but if after
            # probe it will turn out that the hosts are unreachable, and the VPN status is still
            # still undetermined - we are not trying to blindly raise VPN over
            # perhaps a live session, but we report uncertainty.
            vpn_state: Optional[bool]
            if mode == PrecheckMode.VPN or warmup_can_use_vpn:
                assert vpn is not None
                try:
                    vpn_state = vpn.get_vpn_connected(
                        sc.vpn_connection_name,
                        all_user=sc.vpn_connection_all_user,
                    )
                except Exception:
                    logger.debug(
                        "get_vpn_connected() in precheck failed", exc_info=True,
                    )
                    vpn_state = None
                already_up = bool(vpn_state)  # only for the True branch below
                if vpn_state is True:
                    if not self._vpn_owned_by_us:
                        self._post_to_gui_coalesced(
                            "vpn_status", self._set_vpn_status, "vpn_state_system"
                        )
                elif vpn_state is False:
                    # Definitely disabled - we can reset ownership if it was
                    # set by mistake/left over from the last session.
                    self._rs.vpn_owned_by_us = False
                else:
                    # None: State unknown. We DO NOT touch Ownership -
                    # a temporary PowerShell glitch should not force the scanner
                    # forget that this is his own session.
                    logger.warning(
                        "Precheck: get_vpn_connected(%r) returned None — VPN "
                        "state is unknown, leaving ownership untouched "
                        "(owned_by_us=%s)",
                        sc.vpn_connection_name, self._rs.vpn_owned_by_us,
                    )
            else:
                already_up = False
                vpn_state = False

            # --- probe ---
            results = _local_probe_hosts(hosts)
            unreachable = [hp for hp, ok in results.items() if not ok]

            # --- reaction to the result ---
            if mode == PrecheckMode.WARMUP:
                if not unreachable:
                    # Everything is available directly - we fill the cache as is.
                    self._post_to_gui(self._on_warmup_success, epoch)
                    return
                if not warmup_can_use_vpn:
                    logger.debug(
                        "Precheck warm-up: %d host(s) unreachable directly, "
                        "VPN is not configured — leaving the cache empty so "
                        "the full precheck handles the popup on Start",
                        len(unreachable),
                    )
                    return
                # Hosts are not directly accessible, VPN is enabled - we degrade into
                # VPN path. This is a background task after loading the playlist,
                # That’s why we don’t show popups in case of failure (see.
                # the final block is below), and if successful, fill the cache like this
                # same as normal warmup.
                logger.info(
                    "Precheck warm-up: %d host(s) unreachable directly, "
                    "VPN is enabled — warming up via the VPN path",
                    len(unreachable),
                )
                # Continue below as in mode == PrecheckMode.VPN.

            if mode == PrecheckMode.DIRECT:
                if unreachable:
                    failure_message = sc.s(
                        "msg_hosts_unreachable_no_vpn",
                        hosts=", ".join(f"{h}:{p}" for h, p, *_ in unreachable),
                    )
                self._post_to_gui(self._on_precheck_done, mode, epoch, failure_message)
                return

            # mode == PrecheckMode.VPN
            route_targets = list(unreachable)
            if route_targets:
                # If we could not determine the VPN state and at the same time
                # there are unreachable hosts - DO NOT run connect_and_route
                # blindly: he can follow the “VPN is not connected” branch and
                # either make rasdial over the live session, or (if
                # already_up_before=False in _apply_connect_and_route_result)
                # reset ownership. Instead, we communicate uncertainty.
                # through the same _vpn_postcheck_failure - the user will see
                # clear popup, next precheck will try again.
                if vpn_state is None:
                    failure_message = sc.s(
                        "msg_vpn_route_failed",
                        hosts=", ".join(f"{h}:{p}" for h, p, *_ in route_targets),
                        details="Could not determine the VPN state (PowerShell did not respond)",
                    )
                    logger.warning(
                        "Precheck: not calling connect_and_route — VPN state is "
                        "unknown (get_vpn_connected=None), so dialing/ownership "
                        "changes would be unsafe; deferring to the next precheck"
                    )
                else:
                    if not already_up:
                        self._post_to_gui_coalesced(
                            "vpn_status", self._set_vpn_status, "vpn_state_connecting"
                        )

                    assert vpn is not None  # the branch is reachable only with an available VPN (see checks above)
                    resp = vpn.connect_and_route(
                        base_path, sc.vpn_connection_name, route_targets,
                        all_user=sc.vpn_connection_all_user,
                    )
                    outcome = self._apply_connect_and_route_result(
                        resp, already_up_before=already_up,
                    )
                    if outcome == "failed":
                        logger.warning("VPN connect_and_route: %s", resp.get("error"))
                        fail_hosts = unreachable or route_targets
                        failure_message = sc.s(
                            "msg_vpn_route_failed",
                            hosts=", ".join(f"{h}:{p}" for h, p, *_ in fail_hosts),
                            details=resp.get("error") or "Failed to configure VPN",
                        )
                    elif unreachable:
                        post = _local_probe_hosts(unreachable)
                        still_unreachable = [
                            f"{h}:{p}" for (h, p, *_rest) , ok in post.items() if not ok
                        ]
                        if still_unreachable:
                            failure_message = sc.s(
                                "msg_vpn_route_failed",
                                hosts=", ".join(still_unreachable),
                                details=resp.get("error") or "Access was not restored after VPN",
                            )
                            logger.warning(
                                "VPN post-probe failed: %s", failure_message
                            )

            if mode == PrecheckMode.VPN and not failure_message:
                self._rs.reset_episode()

        except Exception:
            logger.exception("Precheck worker failed (mode=%s)", mode.value)
            if failure_message is None:
                failure_message = sc.s(
                    "msg_hosts_unreachable_no_vpn",
                    hosts=", ".join(f"{h}:{p}" for h, p, *_ in hosts),
                )

        # WARMUP mode, which has degraded to the VPN path (see above), ends
        # HERE: _on_precheck_done is not suitable - it is for full
        # precheck (scan start, popups if unsuccessful), and warmup -
        # background task after downloading the playlist, the user
        # nothing is blocking. Therefore:
        #   * success of the VPN path → fill the precheck cache via
        #     _on_warmup_success (the first Start starts instantly);
        #   * failure → silently leaving the cache empty (the first Start itself
        # will run a full precheck and show a popup if necessary).
        if mode == PrecheckMode.WARMUP:
            if failure_message:
                logger.debug(
                    "Precheck warm-up (VPN path) failed: %s — leaving the "
                    "cache empty; the full precheck will run on Start",
                    failure_message,
                )
                return
            self._post_to_gui(self._on_warmup_success, epoch)
            return

        self._post_to_gui(self._on_precheck_done, mode, epoch, failure_message)

    def _on_precheck_done(
        self, mode: PrecheckMode, epoch: int,
        failure_message: Optional[str] = None,
    ) -> None:
        if epoch != self._net_epoch:
            logger.debug(
                "Precheck (%s) done, but epoch is stale (%d != %d) — "
                "ignoring the result (a current precheck/recovery is already "
                "in progress).",
                mode.value, epoch, self._net_epoch,
            )
            return
        self._precheck_in_progress = False

        # WARMUP - background task after loading the playlist, should not
        # neither run a scan nor show popups. Full-time successful
        # WARMUP comes here only when the host list is empty
        # (_extract_proxy_hosts returned []); in this case just
        # Let's go out. All other WARMUP outcomes are completed within
        # _on_warmup_success (see _precheck_worker).
        if mode == PrecheckMode.WARMUP:
            return

        # --- DIRECT: only popup for unreachable hosts ---
        if mode == PrecheckMode.DIRECT:
            if failure_message:
                messagebox.showerror(
                    self.scanner.s("msg_hosts_unreachable_no_vpn_title"),
                    failure_message,
                    parent=self.root,
                )
                self._set_controls_enabled(True)
                self._set_idle_ui()
                return
            if self._rs.any_recovery_active:
                return
            self._rs.reset_episode()
            self._precheck_ok_mono = time.monotonic()
            self._precheck_epoch = self._net_epoch
            self._set_controls_enabled(True)
            self._start_scan_now()
            return

        # --- VPN: soft path recovery, popup or start ---
        if failure_message:
            # Reset cooldown: recovery attempt did not help (hosts are unavailable
            # and then reset). A 10-minute cooldown exists to prevent
            # blink the network after SUCCESSFUL recovery; upon failure
            # the situation is different - the user can repair the network and
            # try again, and should not run into a rancid cooldown.
            self._rs.path_recovery_last_mono = 0.0
            # Local alias - to further access the short name within the function.
            message = failure_message
            self._vpn_postcheck_failure = None

            iface_race = (
                vpn is not None
                and vpn.IFACE_UNDETERMINED_MARKER in message.lower()
            )
            if (
                not iface_race
                and not self._soft_recovery_attempted
                and not self._rs.any_recovery_active
                and not self._closing
            ):
                if self._maybe_start_soft_path_recovery("post_probe_failed"):
                    self._scan_was_running_before_pause = True
                    return

            messagebox.showerror(
                self.scanner.s("msg_vpn_route_failed_title"),
                message,
                parent=self.root,
            )
            self._set_vpn_status_from_reality_async()
            self._set_controls_enabled(True)
            self._set_idle_ui()
            return

        if self._rs.network_recovery_active:
            return

        self._set_vpn_status_from_reality_async()
        self._precheck_ok_mono = time.monotonic()
        self._precheck_epoch = self._net_epoch
        self._set_controls_enabled(True)
        self._start_scan_now()

    def _clear_tree_selection(self) -> None:
        """Deselects the channel row in the table.

        Called each time you click "Stop/Start scanning"
        (see toggle_scan). Without this the "start from the selected channel" effect
        (_apply_selected_start_index) would not be a one-off: selection in Treeview
        lasts until the user clicks another row, so the loop
        Stop → Start would start scanning over and over again with the same
        line instead of the expected continuation from where it stopped."""
        sel = self.tree.selection()
        if sel:
            self.tree.selection_remove(sel)

    def toggle_scan(self) -> None:
        now = time.monotonic()
        if now < self._toggle_lock_until:
            return

        if self.scanner.is_scanning:
            self.scanner.request_stop()
            self._invalidate_scan_callbacks()
            self._set_stopping_ui()
            self._clear_tree_selection()
            # An explicit “Stop” overrides the intent to “resume scanning after
            # recovery": the user just said that the scan was not for him
            # needed. If not reset - _finish_recovery_guard after
            # When the current recovery episode ends, it will start the scan again.
            self._scan_was_running_before_pause = False
            try:
                self.scanner.abort_active_responses()
            except Exception:
                logger.debug("abort_active_responses on Stop failed", exc_info=True)
            self._toggle_lock_until = now + self._TOGGLE_COOLDOWN_SEC
            self.root.after(200, self._wait_scan_thread_finished)
            return

        if not self.scanner.channels:
            messagebox.showwarning(
                self.scanner.s("msg_attention"),
                self.scanner.s("msg_load_playlist_first")
            )
            return

        # An explicit “Start” also overrides a possible outdated intent:
        # the user now decides what to scan and restore
        # “what happened before the pause” should not be interjected.
        self._scan_was_running_before_pause = False
        self._apply_selected_start_index()
        self._clear_tree_selection()
        self._toggle_lock_until = now + self._TOGGLE_COOLDOWN_SEC
        self._start_scan_if_idle()
        
    def _wait_scan_thread_finished(self) -> None:
        """Pollits scan_thread and returns the button to idle when it dies."""
        if self.scan_thread is not None and self.scan_thread.is_alive():
            self.root.after(200, self._wait_scan_thread_finished)
            return
        # Between the Stop click and the actual death of the scan_thread user
        # could have time to start loading the playlist (F5 during scanning,
        # or click on the playlist button - it is still active in this window).
        # The buttons in this script are _on_playlist_loaded /
        # _on_playlist_load_failed; _set_idle_ui() would include here
        # scan_btn in the middle of a download still in progress. "Loading in progress" sign -
        # exactly the same as in _on_f5_reload_playlist: playlist buttons
        # disabled (set synchronously in load_selected_playlist).
        if any(btn.instate(["disabled"]) for btn in self.playlist_buttons):
            return
        self._set_idle_ui()
        fatal = self.scanner.consume_fatal_scan_error()
        if fatal and not self._closing:
            messagebox.showerror(
                self.scanner.s("msg_hanging_limit_title"),
                self.scanner.s("msg_hanging_limit") + "\n\n" + fatal,
                parent=self.root,
            )

    def _apply_selected_start_index(self) -> None:
        """Manual scanning starts from the channel selected in the table (and further
        in a circle), if there is a selection. If there is no selection, last_index is NOT touched:
        it already points to either 0 (after loading the playlist - see below).
        _load_playlist_worker / _on_reset_complete), or to the last stop point
        scan (see scan_loop), and it is from this that the scan should continue. Reset
        last_index if not allocated would reset progress every loop
        Stop → Start (the selection is cleared, see _clear_tree_selection).

        Called only from toggle_scan() (the "Run" button), and not from auto-start
        after preload_playlist: it always starts from the beginning of the list, regardless
        what was allocated before loading."""
        sel = self.tree.selection()
        if not sel:
            return
        try:
            tree_idx = self.tree.index(sel[0])
        except tk.TclError:
            return
        if 0 <= tree_idx < len(self.scanner.channels):
            with self.scanner._channels_lock:
                self.scanner.last_index = tree_idx

    def _reset_scanning_tags(self, indices: List[int]) -> None:
        """Removes the temporary "scanning" tag (blue highlight "currently being scanned") from
        lines that did not get the real result before stopping the scan in the middle
        batcha.

        Without this, the highlighting “freezes” on lines like this forever:
        update_channel_row() will no longer be called for them (see earlier return in
        scan_loop at Stop), and the next time you start them, backlighting is added
        new batch, and there are more blue lines with each cycle
        Stop → Start. Lines that have already received a real status (the tag is different from
        "scanning"), do not move - only stuck ones."""
        for idx in indices:
            item = self.tree_items.get(idx)
            if item is None:
                continue
            try:
                if self.tree.item(item, "tags") == ("scanning",):
                    self.tree.item(item, tags=())
            except tk.TclError:
                pass

    def _reset_all_scanning_tags(self) -> None:
        """Removes the “scanning” tag from ALL rows in the tree.

        Called from _pause_for_connectivity_issue when there is an emergency pause
        (hibernation, network loss, VPN interruption, L2-reset): scan stops
        right now, and the background scan_loop may not reach the
        its standard backlight reset.
        """
        for item in self.tree.get_children():
            try:
                if self.tree.item(item, "tags") == ("scanning",):
                    self.tree.item(item, tags=())
            except tk.TclError:
                return

    @staticmethod
    def _select_batch_retry_candidates(
        batch_results: Dict[int, ScanResult],
    ) -> List[int]:
        """Batch channel indexes that make sense to rerun.

        Returns a non-empty list for the transient signature only
        network blip: in the batch >= 2 channels, ALL returned CONNECT_FAILED,
        and for ALL the reason is a real network one (NETWORK/TIMEOUT/NO_DATA).
        Single channel, COOLDOWN, CANCELLED, HANGING_LIMIT, and
        any non-CONNECT_FAILED status is not a reason for retrying: retry them
        will either instantly fail for the same reason, or interfere with
        someone else's logic (for example, cooldown was deliberately set)."""
        if len(batch_results) < 2:
            return []
        retryable = {
            ConnectFailReason.NETWORK,
            ConnectFailReason.TIMEOUT,
            ConnectFailReason.NO_DATA,
        }
        for res in batch_results.values():
            if res.status != Status.CONNECT_FAILED:
                return []
            if res.connect_reason not in retryable:
                return []
        return list(batch_results.keys())

    def scan_loop(self) -> None:
        generation = self.scan_generation
        # executor is recreated when scanner.parallel changes (for example,
        # the user changed "Parallel" in the settings right during
        # scanning), and not only at the next scan start - otherwise
        # batch_size (which reads scanner.parallel "live") might have gone wrong
        # with the actual size of the worker pool.
        #
        # Track every pool created during this scan in all_executors and join
        # them all in finally (not only the current one). Makes the invariant
        # "no live network workers after scan_loop returns" explicit — needed
        # for thread_join_timeout, path-quality recovery join, and hanging accounting.
        current_parallel = self.scanner.parallel
        all_executors: List[ThreadPoolExecutor] = []
        executor = ThreadPoolExecutor(max_workers=current_parallel)
        all_executors.append(executor)
        try:
            while self.scanner.is_scanning:
                if self.scanner.parallel != current_parallel:
                    old_executor = executor
                    current_parallel = self.scanner.parallel
                    executor = ThreadPoolExecutor(max_workers=current_parallel)
                    all_executors.append(executor)
                    # wait=False: do not block the scan cycle - old pool
                    # drained as_completed of the previous iteration, it
                    # thread workers exit immediately after receiving
                    # sentinel'a. Final (wait=True) guarantee - in
                    # finally below where ALL pools of this scan are expected.
                    old_executor.shutdown(wait=False)

                # Photo below. The batch itself and check_channel are already running
                # without a lock - Channel objects remain valid.
                with self.scanner._channels_lock:
                    channels = list(self.scanner.channels)
                    i = self.scanner.last_index
                    if i >= len(channels):
                        i = 0
                        self.scanner.last_index = 0

                if not channels:
                    time.sleep(1.0)
                    continue

                batch_size = min(current_parallel, len(channels) - i)
                if batch_size <= 0:
                    time.sleep(0.3)
                    continue

                # A copy of the slice - even if the original list is cleared/replaced,
                # Channel objects in the batch will remain valid for already running tasks.
                batch = channels[i : i + batch_size]

                # The “now scanning” highlight is placed here, BEFORE
                # by launching a batch, and not by relaying from _apply_batch_results
                # previous one. This relay race relied on the fact that EVERYONE
                # previous _apply_batch_results will reach the highlighting stage
                # the next one,” and was torn on the last incomplete batch
                # (when len(channels) is not a multiple of parallel). In addition,
                # strict FIFO between root.after-lighting and callbacks
                # tkinter does not guarantee results (also from the scan stream),
                # and on quick emergency batches they could be executed in
                # reverse order - then both groups would be blue.
                batch_start = i
                batch_committed = False
                try:
                    # --- highlighting the current batch as “currently being checked” ---
                    if len(channels) > self.scanner.parallel:
                        for offset in range(batch_size):
                            _idx = batch_start + offset
                            _item = self.tree_items.get(_idx)
                            if _item is None:
                                continue
                            self._post_to_gui(
                                functools.partial(self.tree.item, _item, tags=("scanning",)),
                            )

                    batch_start_mono = time.monotonic()

                    futures = {
                        executor.submit(self.scanner.check_channel, ch): batch_start + offset
                        for offset, ch in enumerate(batch)
                    }

                    batch_results: Dict[int, ScanResult] = {}
                    batch_any_result = False
                    batch_all_failed = True

                    for future in as_completed(futures):
                        if not self.scanner.is_scanning:
                            # Stop came in the middle of the batch: cancel
                            # the remaining futures and we leave. last_index is not
                            # touch - i is incremented only on commit
                            # (see batch_committed below) that's why it's like this
                            # indicates the beginning of the batch. Removing scanning tags
                            # from the entire range will finally make a batch block -
                            # not only from those channels that managed to reach.
                            for f in futures:
                                f.cancel()
                            return

                        if future.cancelled():
                            continue

                        if generation != self.scan_generation:
                        # We return to the soft pass: the result is not
                        # apply, but let the cycle finish -
                        # post-cycle checks below will still not work
                        # post _apply_batch_results for deprecated
                        # generation, and resetting the tags will finally make the block
                        # batcha.
                            continue

                        idx = futures[future]
                        try:
                            res = future.result()
                        except Exception:
                            logger.exception(
                                "Unexpected error in check_channel result (idx=%s)", idx
                            )
                            continue

                        batch_results[idx] = res
                        batch_any_result = True
                        if res.status != Status.CONNECT_FAILED:
                            batch_all_failed = False

                        self._record_path_quality_from_result(res)

                    retry_candidates = self._select_batch_retry_candidates(batch_results)

                    # ── Rhythm of emergency batches ────────────────────────────────
                    batch_elapsed = time.monotonic() - batch_start_mono
                    is_fast_batch = (
                        batch_elapsed < self.scanner.scan_timeout
                        * RUNTIME.batch_fast_fail_max_ratio
                    )

                    will_retry = (
                        bool(retry_candidates)
                        and self.scanner.is_scanning
                        and generation == self.scan_generation
                        and is_fast_batch
                    )

                    if (
                        batch_any_result
                        and batch_all_failed
                        and is_fast_batch
                        and self.scanner.is_scanning
                        and generation == self.scan_generation
                    ):
                        if will_retry:
                            pause = max(
                                self.scanner.scan_timeout - 2.0 * batch_elapsed - RUNTIME.retry_pause_sec,
                                RUNTIME.batch_retry_settle_min_sec,
                            )
                        else:
                            pause = self.scanner.scan_timeout - batch_elapsed
                        if self.scanner._stop_event.wait(pause):
                            # Exit in stop mode in an “emergency” rhythm. This used to be
                            # the place lost scanning tags of the current batch;
                            # Now any exit from the block goes through
                            # finally, but this particular return is the most
                            # probable in reality, and it is useful to remember that
                            # correctness depends on finally.
                            return

                    batch_is_all_no_alert = all(
                        _name_has_prefix(ch.name, self.scanner.no_alert_prefixes)
                        for ch in batch
                    )

                    if will_retry:
                        if not batch_is_all_no_alert:
                            logger.info(
                                "Retrying %d channel(s) from the batch: the whole "
                                "group failed with connect errors at the same "
                                "moment, which usually means a transient network "
                                "blip (Wi-Fi roam / brief packet loss), not a "
                                "per-channel problem",
                                len(retry_candidates),
                            )
                        retry_futures = {
                            executor.submit(
                                self.scanner.check_channel,
                                batch_results[idx].channel,
                                bypass_cooldown=True,
                            ): idx
                            for idx in retry_candidates
                        }
                        retry_success = False
                        for future in as_completed(retry_futures):
                            if not self.scanner.is_scanning:
                                for f in retry_futures:
                                    f.cancel()
                                break
                            if future.cancelled():
                                continue
                            if generation != self.scan_generation:
                                # Symmetrical to the main loop: the result is not
                                # We apply, but do not come out harshly. Tags will be removed
                                # finally batch block.
                                continue
                            idx = retry_futures[future]
                            try:
                                res = future.result()
                            except Exception:
                                logger.exception(
                                    "Unexpected error in check_channel "
                                    "(retry) result (idx=%s)", idx,
                                )
                                continue
                            batch_results[idx] = res
                            if res.status != Status.CONNECT_FAILED:
                                retry_success = True
                            self._record_path_quality_from_result(res)
                        if retry_success:
                            batch_all_failed = False

                        # Pause after the retray: we give the network
                        # “take a breather” before the next group. Interruptible -
                        # “Stop” during it is triggered instantly, and not
                        # waits 300 ms for completion.
                        if self.scanner._stop_event.wait(RUNTIME.retry_pause_sec):
                            return

                    if generation == self.scan_generation:
                        self._post_to_gui(
                            self._apply_batch_results,
                            generation,
                            list(batch_results.items()),
                        )

                    # Soft recovery on consecutive all-CONNECT_FAILED batches
                    # (see RUNTIME.connect_fail_batch_trigger).
                    if batch_is_all_no_alert:
                        pass
                    elif batch_any_result and batch_all_failed:
                        self._rs.connect_fail_batch_streak += 1
                        self._precheck_ok_mono = None
                        if (
                            self._connect_fail_batch_streak
                            >= RUNTIME.connect_fail_batch_trigger
                            and self.scanner.is_scanning
                        ):
                            self._rs.connect_fail_batch_streak = 0
                            self._post_to_gui(
                                self._maybe_start_soft_path_recovery,
                                "connect_failed_batches",
                            )
                    else:
                        self._rs.connect_fail_batch_streak = 0

                    # The batch is “committed” (and last_index is promoted), only
                    # if its results actually end up in the UI: scan more
                    # active and the generation has not changed. Otherwise the last one
                    # the committed last_index remains pointing to the beginning
                    # this batch - the scan on the resume will start with it.
                    if generation == self.scan_generation and self.scanner.is_scanning:
                        i = batch_start + batch_size
                        with self.scanner._channels_lock:
                            self.scanner.last_index = i
                        batch_committed = True
                finally:
                    # Single point of cleaning "scanning" tags for everything
                    # batch range. Triggers on ANY output from the block:
                    # early return (stop, cancel), exception from future.result,
                    # errors _post_to_gui, new iteration while, etc.
                    # Idempotent with respect to _apply_batch_results: that to
                    # at the moment of the call I already put real tags, and _reset
                    # they will not be affected (see _reset_scanning_tags).
                    #
                    # If the batch is committed, we don’t remove the tags: they are already
                    # overwritten by real statuses via _apply_batch_results.
                    if not batch_committed:
                        self._post_to_gui(
                            self._reset_scanning_tags,
                            [batch_start + k for k in range(batch_size)],
                        )
        finally:
            # wait=True: scan_loop must not return while workers still run
            # (see IPTVScanner.thread_join_timeout and all_executors note above).
            # Shutdown every pool from this scan; repeated shutdown() is safe.
            for ex in all_executors:
                ex.shutdown(wait=True)

    def _apply_batch_results(
        self,
        generation: GenerationToken,
        results: List[Tuple[int, ScanResult]],
    ) -> None:
        """Applies the results of one batch commit to the UI.

        Responsible only for placing real statuses/tags on
        channels. All cleaning of “scanning” highlighting in anomalous branches
        (stop in the middle of a batch, generation change, exception from future.result)
        executes finally the batch block in scan_loop - this method in cleanup
        does not participate.
        """
        if self._closing:
            return
        if generation != self.scan_generation:
            # The batch is stale between scheduling the callback and executing it
            # (pause/change playlist): we do not apply the results so as not to
            # Add the statuses of an irrelevant batch to the tree. Scanning-
            # tags at this point have already been removed finally in scan_loop - here
            # there is nothing to do.
            return
        try:
            for idx, res in results:
                self._apply_channel_status(idx, res.channel, res.status, res.details)
            try:
                self.root.update_idletasks()
            except tk.TclError:
                return
        except tk.TclError:
            logger.debug(
                "_apply_batch_results: widget already destroyed "
                "(application closing)", exc_info=True,
            )

    def _apply_channel_status(
        self,
        idx: int,
        channel: Channel,
        status: Status,
        details: str,
    ) -> None:
        """Applies one result: tag in tree + alerts. Without batch-
        pending logic - it is no longer needed, the entire batch is applied
        in _apply_batch_results."""
        if idx in self.tree_items:
            item = self.tree_items[idx]
            label = self.scanner.s(status)
            self.tree.set(item, "status", label)
            self.tree.set(item, "bitrate", details)
            tag = STATUS_TAGS.get(status, DEFAULT_STATUS_TAG)
            self.tree.item(item, tags=(tag,))

        key = channel.alert_key
        removed = False
        need_refresh = False
        play_sound = False

        with self.scanner._alerts_lock:
            if (
                status in OK_STATUSES
                or _name_has_prefix(channel.name, self.scanner.no_alert_prefixes)
            ):
                if key in self.scanner.alerts:
                    del self.scanner.alerts[key]
                    removed = True
            else:
                is_new = key not in self.scanner.alerts
                label = self.scanner.s(status)
                if is_new:
                    self.scanner.alerts[key] = {
                        "status": label,
                        "details": details,
                        "first_seen": time.strftime("%H:%M"),
                        "first_seen_ts": time.monotonic(),
                        "display_name": channel.display_name,
                    }
                    play_sound = True
                else:
                    self.scanner.alerts[key].update({
                        "status": label,
                        "details": details,
                        "display_name": channel.display_name,
                    })
                if len(self.scanner.alerts) > RUNTIME.max_alerts:
                    sorted_keys = sorted(
                        self.scanner.alerts.keys(),
                        key=lambda k: self.scanner.alerts[k].get("first_seen_ts", 0.0),
                    )
                    for old_key in sorted_keys[: len(self.scanner.alerts) - RUNTIME.max_alerts]:
                        del self.scanner.alerts[old_key]
                need_refresh = True

        if play_sound and self.sound_enabled:
            self._play_beeps_async([(900, 350), (1100, 280)], gap=0.08)

        if removed or need_refresh:
            self._schedule_alert_refresh()

    # Pause between redraws of the alert panel. During this time everything is new
    # the scan results collapse into ONE complete restructuring of the Text widget:
    # rebuilding for each result with an error would be O(results × alerts)
    # in the GUI thread. Was lost during one of the refactorings; without him
    # _schedule_alert_refresh() crashes with AttributeError on
    # self._ALERT_REFRESH_DELAY_MS, the _alert_refresh_scheduled flag remains
    # cocked - and the alert panel stops updating altogether.
    _ALERT_REFRESH_DELAY_MS = 150


    def _schedule_alert_refresh(self) -> None:
        """GUI thread. Schedules _refresh_alerts() if it is not already scheduled."""
        if self._alert_refresh_scheduled or self._closing:
            return
        self._alert_refresh_scheduled = True
        try:
            self.root.after(self._ALERT_REFRESH_DELAY_MS, self._alert_refresh_tick)
        except Exception:
            # Any error in planning (including AttributeError when
            # missing attribute) - reset the flag so that the next
            # the update attempt did not remain permanently blocked.
            self._alert_refresh_scheduled = False
            logger.exception("Failed to schedule alert refresh — will retry on the next alert")

    def _alert_refresh_tick(self) -> None:
        # We remove the flag BEFORE redrawing: the result that came during it is
        # will schedule the next refresh and not get lost.
        self._alert_refresh_scheduled = False
        if self._closing:
            return
        try:
            self._refresh_alerts()
        except tk.TclError:
            logger.debug("_refresh_alerts: widget already destroyed", exc_info=True)

    def _refresh_alerts(self) -> None:
        with self.scanner._alerts_lock:
            items = list(self.scanner.alerts.items())
        lines = []
        for key, info in items:
            name = info.get("display_name") or (key[0] if isinstance(key, tuple) else str(key))
            lines.append(self.scanner.s("alert_line", status=info['status'], name=name, details=info['details'], since=info['first_seen']) + "\n")
        # One delete + one insert instead of N insertions along the line.
        self.alert_text.delete("1.0", tk.END)
        if lines:
            self.alert_text.insert("end", "".join(lines))
            
    def _maybe_preload_playlist(self) -> None:
        name = (self.scanner.preload_playlist or "").strip()
        if not name:
            return
        for idx, pl_name, _url in self.scanner.get_active_playlists():
            if pl_name == name:
                self._pending_auto_scan = True
                self.load_selected_playlist(idx, is_preload=True)
                return
        logger.warning(
            "preload_playlist %r not found among configured playlists — start without preload",
            name,
        )

    def load_selected_playlist(self, idx: int, is_preload: bool = False,
                                force: bool = False) -> None:
        sc = self.scanner
        # Snapshot under _config_lock: close_settings() maybe at the same
        # moment on the GUI stream replace sc.playlist_urls/playlist_names
        # entirely new lists (see close_settings), and reading two
        # individual indexes without a lock could, in theory, see the name from
        # one list and a url from another in the middle of this replacement.
        with sc._config_lock:
            url = (sc.playlist_urls[idx] or "").strip()
            name = (sc.playlist_names[idx] or "").strip()
        if not url or not name:
            self._pending_auto_scan = False
            messagebox.showwarning(
                sc.s("msg_attention"),
                sc.s("msg_playlist_not_configured")
            )
            return

        if not force and sc.current_playlist_idx == idx and len(sc.channels) > 0:
            return

        # Changing the playlist cancels the “resume scan after recovery”:
        # the renewal item (the previous set of channels) no longer exists.
        self._scan_was_running_before_pause = False
        # We reset the precheck cache only if the set of hosts changes.
        # When F5 reloading the same playlist (force=True with the same idx)
        # The URL is the same, which means the hosts are the same - there is nothing to heat again, and Start
        # can start instantly if the cache is still fresh.
        with sc._config_lock:
            old_idx = sc.current_playlist_idx
            old_url = ""
            if 0 <= old_idx < MAX_PLAYLISTS:
                old_url = (sc.playlist_urls[old_idx] or "").strip()
        if old_idx != idx or old_url != url:
            self._precheck_ok_mono = None

        self.scan_generation = self.scan_generation.bump()
        self.load_generation = self.load_generation.bump()
        gen = self.load_generation

        sc.request_stop()
        self.scan_btn.config(text=sc.s("btn_start"))   # or self._set_idle_ui() / _set_stopping_ui()
        self._set_controls_enabled(False)
        self.current_playlist_label.config(text=sc.s("label_loading", name=name))
        threading.Thread(
            target=self._load_playlist_worker,
            args=(idx, url, name, gen, is_preload),
            daemon=True,
        ).start()

    # Retrays are only for auto-loading (preload) when the application starts. Immediately after
    # startup (especially from startup), the network stack/DNS may not be ready yet,
    # or the antivirus has not yet “warmed up” the interception of the first connection, and the first
    # The HTTP request fails with a ConnectionError/timeout. This is a race at the OS level, not
    # order of calls inside Tkinter, so rearranging commands does not
    # to fix it, you just need to try again.
    # Manual loading with a button (is_preload=False) occurs when the network is already
    # ready: retrays are not needed there and would only delay the display of the real error
    # playlist.
    _PRELOAD_RETRY_DELAYS: Tuple[float, ...] = (0.7, 1.5, 3.0)

    def _load_playlist_worker(
        self, idx: int, url: str, name: str, gen: GenerationToken, is_preload: bool = False
    ) -> None:
        # 1. Wait for the previous scan_thread to complete
        if not self._join_scan_thread():
            if gen == self.load_generation:
                self._post_to_gui(lambda: messagebox.showwarning(
                    self.scanner.s("msg_stop_title"),
                    self.scanner.s("msg_stop_timeout")
                ))
                self._post_to_gui(self._on_playlist_load_failed, gen)
            return
            
        self.scanner.close_all_sessions()

        # 2. Already outdated even before the network?
        if gen != self.load_generation:
            return

        # 3. Network + parsing (without changing the Scanner state)
        delays = self._PRELOAD_RETRY_DELAYS if is_preload else ()
        new_channels: List[Channel] = []
        for attempt, delay in enumerate((0.0,) + delays, start=1):
            if delay:
                time.sleep(delay)
                if gen != self.load_generation:
                    return
            new_channels = self.scanner.fetch_playlist_channels(url)
            if new_channels:
                break
            logger.info(
                "preload fetch attempt %d/%d for %r returned 0 channels",
                attempt, len(delays) + 1, name,
            )
        count = len(new_channels)

        if not new_channels:
            # fetch_playlist_channels() returns [] on ANY network error/DNS failure −
            # this does not mean "the playlist is now empty." A commit of such a result would have already been erased
            # loaded working playlist into self.scanner.channels before
            # _on_playlist_load_failed() will have time to show an error. Therefore this path behaves
            # same as _join_scan_thread() failure (thread above): nothing is committed,
            # sc.channels/last_index/current_playlist_idx do not change, the user
            # an error is shown.
            if gen == self.load_generation:
                self._post_to_gui(lambda: messagebox.showerror(
                    self.scanner.s("msg_error"), self.scanner.s("msg_playlist_load_error")
                ))
                self._post_to_gui(self._on_playlist_load_failed, gen)
            return

        # 4. Commit under lock + final generation check
        with self.scanner._channels_lock:
            if gen != self.load_generation or self._closing:
                # While downloading/parsing, a newer download had already started
                # or the user closed the window. channels/last_index is not
                # we touch.
                return
            self.scanner.channels = new_channels
            self.scanner.last_index = 0
            self.scanner.current_playlist_idx = idx
        # playlist_urls is mutated here (in the worker thread), and close_settings() on
        # The GUI thread can at the same time assign a completely new sc.playlist_urls
        # list. Without a separate lock, it's a race between "change an element of an existing
        # list" and "replace the entire list". _config_lock is already in use
        # close_settings()/save_config() for these fields.
        #
        # Rule: _channels_lock and _config_lock are never held at the same time
        # (to avoid deadlocks): _config_lock is captured AFTER exiting
        # block with _channels_lock above, not nested. gen checked internally
        # _channels_lock, so they only get here after a commit has taken place.
        with self.scanner._config_lock:
            self.scanner.playlist_urls[idx] = url

        # 5. Config and GUI (only if the commit has passed)
        if self._closing:
            return
        self.scanner.save_config()
        self._post_to_gui(self._on_playlist_loaded, idx, name, count, gen)

    def _on_playlist_loaded(self, idx: int, name: str, count: int, gen: GenerationToken) -> None:
        if gen != self.load_generation:
            return
        auto = self._pending_auto_scan
        self._pending_auto_scan = False

        sc = self.scanner
        self._set_controls_enabled(True)
        self._set_idle_ui()
        # count == 0 is not possible here: _load_playlist_worker() when new_channels is empty
        # goes through _on_playlist_load_failed() even before committing. This callback
        # called only after a successful commit of a non-empty playlist.

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tree_items.clear()
        seen_names: Counter = Counter()
        waiting = sc.s("status_waiting")
        for i, ch in enumerate(sc.channels):
            seen_names[ch.name] += 1
            ch.display_name = (
                ch.name if seen_names[ch.name] == 1
                else f"{ch.name} [{seen_names[ch.name]}]"
            )
            item = self.tree.insert("", "end", values=(waiting, ch.display_name, ""))
            self.tree_items[i] = item
        self.tree.yview_moveto(0)  # channel list slider - to the very top
        # The tree is full - adjust the row height to the current size
        # row areas (see _fit_tree_row_height). We put it aside for idle,
        # so that by the time of the call Tk has time to recalculate the widget geometry.
        self.root.after_idle(self._fit_tree_row_height)
        self.current_playlist_label.config(
            text=sc.s("label_current", name=name, count=count)
        )
        self._play_beeps_async([(380, 480)])
        with sc._alerts_lock:
            sc.alerts.clear()
        # New playlist - old alert_key ((url, name) no longer existing
        # channels) in _fail_cooldowns/_internal_error_seen/_last_issue_status
        # will not coincide with anything else, so they do not interfere with work, but also not
        # are released on their own (see reset_issue_tracking_state).
        sc.reset_issue_tracking_state()
        self.alert_text.delete("1.0", tk.END)
        # New playlist = new online episode: path-quality/connect-fail
        # state from the old playlist should not influence decisions on the new one
        # (see _reset_path_quality_state).
        self._reset_path_quality_state()

        if auto:
            self._start_scan_if_idle()
        else:
            # Warming up the precheck cache so that the first Start is instantaneous.
            # We launch only when there is a VPN module (otherwise _local_probe_hosts
            # unavailable) and we are not in the middle of recovery. We do not touch the UI and VPN:
            # worker only does TCP/HTTP probing.
            if not self._rs.any_recovery_active:
                threading.Thread(
                    target=self._precheck_worker,
                    args=(PrecheckMode.WARMUP,),
                    daemon=True, name="precheck-warmup",
                ).start()
        
    def _on_playlist_load_failed(self, gen: GenerationToken) -> None:
        if gen != self.load_generation:
            return
        self._pending_auto_scan = False
        self._set_controls_enabled(True)
        self._set_idle_ui()
        sc = self.scanner
        if sc.channels and 0 <= sc.current_playlist_idx < MAX_PLAYLISTS:
            old_name = sc.playlist_names[sc.current_playlist_idx]
            self.current_playlist_label.config(
                text=sc.s("label_current", name=old_name, count=len(sc.channels))
            )
        else:
            self.current_playlist_label.config(text=sc.s("label_playlist_none"))

    def _startup_vpn_helper_worker(self) -> None:
        """Background thread, called once at program start, if
        VPN fallback is enabled in the config. It just raises the helper in advance -
        the specific use of VPN for the desired hosts is all the same
        occurs only before the start of the scan, see _precheck_worker."""
        assert vpn is not None  # called only from the vpn_pending branch (see calling code)
        try:
            vpn.launch_helper(base_path)
        except Exception:
            logger.exception("Failed to start the VPN helper at program startup")

    def _startup_recovery_then_helper_worker(self) -> None:
        """Sequential startup recovery + launching helper.

        Recovery is a barrier, not an independent flow. If self_heal_client_on_
        startup() and launch_helper() were running in parallel, the new helper could have time
        get up and register before self_heal reads it
        vpn_client_state.json: self_heal would see "helper is alive, but owner is not yet
        registered" and deleted the state file, which may describe another, not yet
        disconnected VPN session from an abnormally terminated startup. The old VPN remains
        would hang, and the fallback marker for it would disappear.

        Three steps are executed sequentially in one thread:
          1) self_heal_client_on_startup() - checks the old helper and state.json,
             completes recovery of the old session (if necessary);
          2) launch_helper() (see _startup_vpn_helper_worker) - raises OUR new
             helper (and, accordingly, the UAC dialog);
          3) continuation (see _on_startup_vpn_wait_done): unlocking controls /
             playlist preload.
        """
        assert vpn is not None  # called only from the vpn_pending branch (see calling code)
        try:
            vpn.self_heal_client_on_startup()
        except Exception:
            logger.exception("self_heal_client_on_startup() failed at program startup")
        self._startup_vpn_helper_worker()
        self._post_to_gui(self._on_startup_vpn_wait_done)

    def _on_startup_vpn_wait_done(self) -> None:
        # The UAC decision has already been made (accepted, rejected, timeout or file
        # helper was not found - it doesn’t matter which one) - now you can
        # show the main program window (see root.withdraw() in __main__
        # and a comment in __init__).
        self.root.deiconify()
        self.root.lift()
        name = (self.scanner.preload_playlist or "").strip()
        if name:
            self._maybe_preload_playlist()
        else:
            self._set_controls_enabled(True)
            self.current_playlist_label.config(text=self.scanner.s("label_playlist_none"))

    def _perform_vpn_cleanup(self) -> None:
        with self._vpn_cleanup_lock:
            if self._vpn_cleanup_done:
                return
            self._vpn_cleanup_done = True
        if vpn is None or not vpn.IS_WINDOWS:
            return
        try:
            vpn.disconnect_and_unroute(
                base_path, self.scanner.vpn_connection_name,
                all_user=self.scanner.vpn_connection_all_user,
            )
        except Exception:
            logger.exception("Failed to disconnect VPN on close")
        try:
            if vpn.is_helper_alive(timeout=1.0):
                vpn.stop_helper(timeout=15.0)
        except Exception:
            logger.exception("Failed to stop the VPN helper on close")

    def _vpn_atexit_cleanup(self) -> None:
        """Fallback cleanup when the interpreter exits."""
        self._perform_vpn_cleanup()

    def _close_worker(self) -> None:
        try:
            self._perform_vpn_cleanup()
        finally:
            try:
                self.root.after(0, self.root.destroy)
            except Exception:
                logger.debug("Failed to schedule root.destroy() on close", exc_info=True)

    def _on_main_window_close(self) -> None:
        if self._closing:
            return
        self._closing = True
        # We disable BOTH generations before everything else: those already standing in
        # Tk queue scan results and playlist loading still in progress
        # (its worker after the HTTP request would otherwise still be “relevant” and would have time
        # change scanner.channels/playlist_urls, call save_config()
        # and root.after() on the window being destroyed).
        self.controller.invalidate_scan_generation()
        self.controller.invalidate_load_generation()
        _SOUND_PLAYER.shutdown()
        # The application closes - any deferred guards no longer have
        # meaning, and the flag could (theoretically) revive the scan if closing
        # For some reason it didn’t reach the end and the window somehow remained.
        self._scan_was_running_before_pause = False
        # Bump epoch BEFORE set() app_stop_event: all background recovery/
        # reconnect workers (see _vpn_reconnect_retry_worker, etc.) check
        # `epoch != self._net_epoch` on each iteration and should be seen
        # mismatch as soon as they wake up from wait() below - otherwise
        # the worker may have time to raise the VPN again AFTER
        # _close_worker disabled it (the race “closed - but the VPN still hangs”).
        self._rs.bump_epoch()
        self._app_stop_event.set()
        try:
            self.scanner.request_stop()
            self.scanner.abort_active_responses()
        except Exception:
            logger.exception("request_stop()/abort_active_responses() failed while closing the window")
        try:
            self.scanner.close_all_sessions()
        except Exception:
            logger.debug("close_all_sessions() raised an exception while closing the window", exc_info=True)
        try:
            self._set_controls_enabled(False)
            self.scan_btn.config(state="disabled", text=self.scanner.s("btn_stopping"))
        except Exception:
            logger.debug("Failed to update control state while closing", exc_info=True)
        threading.Thread(
            target=self._close_worker, daemon=True, name="vpn-close-cleanup"
        ).start()


if __name__ == "__main__":
    # +++ We install exception handlers and faulthandler IMMEDIATELY, before
    # creating ScannerGUI: if a crash occurs in its __init__ (request
    # UAC, first render, etc.), we also want to see traceback, not
    # pythonw.exe silently disappears.
    _install_exception_hooks()
    _enable_faulthandler()

    if not _try_acquire_single_instance():
        # Minimum Tk only for messagebox (we do not create the main window).
        _root = tk.Tk()
        _root.withdraw()
        try:
            messagebox.showwarning(
                DEFAULT_UI_STRINGS["msg_already_running_title"],
                DEFAULT_UI_STRINGS["msg_already_running"],
            )
        finally:
            _root.destroy()
        sys.exit(0)
    root = tk.Tk()
    # We hide the window IMMEDIATELY, before any rendering. If enabled in settings
    # VPN fallback, ScannerGUI.__init__ will ask for administrator rights (UAC)
    # and will show the main window only after the user responds
    # to this system request - see the comment there and in
    # _on_startup_vpn_wait_done. So the user first sees the UAC dialog,
    # and not a program window with a waiting message.
    root.withdraw()
    style = ttk.Style()
    style.configure("Treeview", rowheight=26)
    app = ScannerGUI(root)
    app.apply_tree_colors()
    # +++ Process life cycle markers. Needed for the next
    # suspicious window disappearance could be distinguished by "mainloop
    # really completed normally" from "the process died from the outside": when
    # native crash/external TerminateProcess next line in the log
    # it just won't appear.
    logger.info("Entering Tk mainloop (PID=%s)", os.getpid())
    try:
        root.mainloop()
    except BaseException:
        logger.exception("Tk mainloop exited with an exception")
        raise
    finally:
        logger.info("Tk mainloop exited")