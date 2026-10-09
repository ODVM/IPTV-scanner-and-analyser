"""
vpn.py
======
Building to .exe:
Manually:
pyinstaller --noconfirm --clean --onefile --name vpn --windowed vpn.py
vpn.exe is built first.
Then compute the hash of this vpn.exe file:
python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('vpn.exe').read_bytes()).hexdigest())"
Then write the resulting hex (lowercase) into EXPECTED_VPN_HELPER_SHA256 in the vpn.py source.
After that, the main scanner exe is built.
Automated: use python build.py
======
The entire VPN subsystem of the scanner lives in a single file to avoid
proliferating companion scripts. The file plays two different roles depending
on how it is used:

  1) IMPORTED by the main (ordinary, NON-elevated) scanner GUI process —
     then only the functions from the "CLIENT" section below are used:
     start/stop of the elevated helper via UAC, command exchange with it over
     a named pipe, the list of VPN connections, TCP probe of proxy
     reachability. Administrator rights are not needed for this part at all.

  2) LAUNCHES ITSELF as a separate process (`python vpn.py --parent-pid
     <PID>`) via ShellExecute with verb="runas" — then the
     "SERVER (ELEVATED HELPER)" section below is executed (see
     `if __name__ == "__main__"` at the very end of the file) and THIS
     process, with administrator rights, performs route add/delete, removal
     of the default route (split-tunnel), and emergency VPN disconnect if
     the GUI process is killed.

In other words: where the code runs is determined not by which file it was
imported from (there is only one file), but by how the process was started —
ordinarily (client role) or via `--base-path` (server role).

The communication protocol between the two roles is a local Windows named pipe.
IMPORTANT: the pipe is created manually via the raw Win32 API (CreateNamedPipeW
through ctypes), not via multiprocessing.connection — because a pipe created
by an elevated process (High integrity level) by default gets the same
integrity label, and an ordinary (Medium) GUI process cannot open it for
writing (Windows "No-Write-Up" rule) — multiprocessing does not allow
overriding the pipe security descriptor, so we explicitly lower the
integrity level required for writing when creating the pipe (see PIPE_SDDL /
_pipe_sddl below). Messages are JSON, with a 4-byte length prefix
(little-endian) before each message.

Commands (the "cmd" field in the incoming JSON) are handled by the server.
IMPORTANT: the elevated server is responsible for operations that need
administrator rights (routes, All-User SplitTunneling, emergency rasdial
/DISCONNECT). VPN connection via the Windows RAS API is performed in the
unprivileged client process (see connect_and_route()), because the elevated
process does not see the saved credentials of "modern" VPN connections:
  ping                          -> {"ok": true}
  add_routes {routes: [[ip, if_index, gateway], ...]}
                                 -> {"ok": bool, "error": str|None, "added": [ip,...]}
  remove_routes                 -> {"ok": bool, "error": str|None}
  prepare_split_tunnel {connection_name, all_user?}
                                 -> {"ok": bool, "already": bool?, "previous": bool|None}
                                 (before rasdial: enables SplitTunneling in the profile,
                                  saving the previous value for restore)
  restore_split_tunnel          -> {"ok": bool, "restored": bool}
  remove_default_route {if_index: int,
                          pre_defaults_v4?: [{if_index, gateway, metric}, ...],
                          pre_defaults_v6?: [...]}
                                 -> {"ok": bool, "removed": int, "removed_v6": int,
                                     "restored_v4": int, "restored_v6": int,
                                     "has_other_default": bool, "metric_set": bool,
                                     "postcondition_ok": bool, ...}
                                 (always removes the VPN default; if needed
                                  restores the physical default from the snapshot;
                                  raises the VPN adapter InterfaceMetric)
  register_client {pid, connection_name, all_user?}
                                 -> {"ok": bool}
  unregister_client             -> {"ok": true}
  release_and_disconnect        -> {"ok": bool, "owned": bool, "routes_removed": bool,
                                     "vpn_disconnected": bool}
                                 (releases ownership, routes, restores
                                  SplitTunneling and immediately disconnects the VPN
                                  in the elevated process — without a race window
                                  with the client-side disconnect)
  status                        -> {"ok": true, "routes": [ip, ...], "owner_pid": ...}
  arp_flush {ips: [str, ...]}   -> {"ok": true, "attempted": [ip, ...]}
                                 (best-effort `arp -d` for valid IPv4 from
                                  ips; network command — available only to
                                  owner_pid/parent_pid, see _NETWORK_OPS_COMMANDS;
                                  uses the helper's administrator rights
                                  for an operation that is normally unavailable
                                  to the unprivileged GUI process; see
                                  _network_hygiene_light() in IPTV_scanner.pyw)
  ping_probe {host}             -> {"ok": bool, "host": str, "error": str|None}
                                 (`ping -n 1`; used after arp_flush of the
                                  gateway so the ARP entry is re-resolved
                                  immediately, not on the first outgoing
                                  packet by chance; see _network_hygiene_light())
  adapter_restart {interface_name}
                                 -> {"ok": bool, "interface": str, "error": str|None}
                                 (`netsh interface set interface <name>
                                  admin=disable`; 3 s; `admin=enable`).
                                 Escalation for wired, when Wi-Fi reset
                                 is not applicable; requires admin (hence via
                                 the helper).
  shutdown                      -> {"ok": true} then the server process exits

If the client connection drops abnormally (GUI crashed without sending
shutdown), this is NOT treated as a signal to "remove routes" by itself
(otherwise they would be removed every time simply on short GUI
reconnections between individual commands — see send_command(): one command =
one connection). A crash of the elevated process itself does not require
separate recovery on the next start: routes are bound to the VPN adapter
ifIndex and Windows removes them from the table automatically when the
adapter disappears (on VPN disconnect) — unlike the VPN tunnel itself, whose
correct closure on abnormal program termination is the responsibility of the
client side (see self_heal_client_on_startup()) and the PID monitor in the
helper. If the GUI is killed via Task Manager, the monitor not only
disconnects the VPN but also terminates the elevated helper itself —
otherwise a orphaned python.exe process remains in Task Manager (often
shown simply as "Python", separate from the original Python(32) GUI).

Blocking calls (rasdial_connect / connect_and_route / send_command /
launch_helper) must not be called from the GUI thread — only from a worker.
"""

from __future__ import annotations

import argparse
import ctypes
import functools
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Tuple, cast

PIPE_NAME = r"\\.\pipe\iptv_scanner_vpn_helper"

# Substring of "VPN interface could not be determined" messages. The GUI uses
# it to distinguish a brief RAS/IP race after connect from real path
# degradation (see iface_race in IPTV_scanner.pyw), so error texts in this
# module and the GUI check must use the same constant.
IFACE_UNDETERMINED_MARKER: str = "interface could not be determined"

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Elevated helper integrity (protection against vpn.exe / vpn.py substitution)
# ---------------------------------------------------------------------------
# At release build time, fill EXPECTED_VPN_HELPER_SHA256 with the SHA-256 hash
# of the vpn.exe file (hex, lowercase) that sits next to IPTV_Scanner.exe:
#
#   python -c "import hashlib,pathlib; p=pathlib.Path('vpn.exe');
#   print(hashlib.sha256(p.read_bytes()).hexdigest())"
#
# Empty string = check disabled (development / debug mode).
# Substituting only vpn.exe when the hash is set blocks launch_helper().
# Substituting both scanner and vpn.exe simultaneously bypasses this protection —
# full protection requires Authenticode signing / OS-level code integrity.
EXPECTED_VPN_HELPER_SHA256: str = ""

# Resolve absolute paths to Windows system utilities
windir = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
_SYSTEM_ROOT = Path(windir)

if os.path.exists(_SYSTEM_ROOT / "Sysnative"):
    _SYSTEM32 = _SYSTEM_ROOT / "Sysnative"
else:
    _SYSTEM32 = _SYSTEM_ROOT / "System32"

ROUTE_EXE   = str(_SYSTEM32 / "route.exe")
RASDIAL_EXE = str(_SYSTEM32 / "rasdial.exe")
NETSH_EXE   = str(_SYSTEM32 / "netsh.exe")
PING_EXE    = str(_SYSTEM32 / "ping.exe")
ARP_EXE     = str(_SYSTEM32 / "arp.exe")

POWERSHELL_EXE = str(
    _SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
)

# Hard ceiling on the size of a single JSON message over the pipe (DoS/OOM).
MAX_PIPE_MESSAGE = 1_000_000

# add_routes is not the place for hundreds of thousands of entries in one
# request; the fewer semantic assumptions the elevated helper makes about
# request content, the more predictable its behaviour. An explicit ceiling
# and reject is better than an implicit hope that the client is "reasonable".
MAX_ROUTES_PER_REQUEST = 256

# Maximum number of simultaneously "hung" (not returned within timeout)
# RasDialW calls that are allowed to leave behind a daemon observer thread
# (_late_hangup, see rasdial_connect). One genuinely hung RasDialW is a
# normal, documented trade-off (the Win32 RAS API provides no way to
# forcibly cancel it). But with systematic RAS timeouts such threads would
# accumulate without bound on every new scan -> connect call. This ceiling
# does not fix hung RAS; it only limits the growth of waiting threads and
# explicitly refuses new attempts when the limit is reached.
#
# Limit semantics — a STRICT circuit breaker on the number of REALLY ALIVE
# hung calls. An entry is removed from _hung_rasdial_timestamps EXCLUSIVELY
# when the corresponding worker.join() has actually returned (see
# _late_hangup/_late_hangup_retry), not on age expiry. Previously, age-
# "stale" entries were excluded from the count — but hang age does not mean
# the hang has cleared: worker.join() is called there WITHOUT a timeout, and
# the thread (and with it the Win32 RasDialW call and the connection it
# holds) may live until process end. Result — the counter reflected
# "recently discovered hangs", not "alive hung calls", and after 15 minutes
# silently allowed a new call on top of already accumulated zombies.
#
# While the limit is reached, new RasDialW calls are not started. That is
# the circuit breaker: recovery must go through restarting RasMan, a reboot,
# or restarting the scanner process — not through accumulating ever more
# hung calls. There is deliberately no automatic "age-out".
MAX_HUNG_RASDIAL = 2
_hung_rasdial_lock = threading.Lock()
_hung_rasdial_count = 0
# Monotonic timestamps of when each "hung" call was recorded (one per
# increment of _hung_rasdial_count). Needed only for DIAGNOSTICS — so that
# the refusal message and the log can show the age of the oldest hung call
# (whether this is a fresh incident or the system degraded long ago).
# They do not affect the circuit-breaker decision. Invariant:
# len(_hung_rasdial_timestamps) == _hung_rasdial_count.
_hung_rasdial_timestamps: List[float] = []

# ---------------------------------------------------------------------------
# RAS API — working with saved credentials without passing the password
# ---------------------------------------------------------------------------

RASCM_UserName = 0x00000001
RASCM_Password = 0x00000002
RASCM_Domain = 0x00000004

RAS_MaxEntryName = 256
RAS_MaxPhoneNumber = 128
RAS_MaxCallbackNumber = 128

# RasDial code for which a single recovery cycle (disconnect + retry) makes
# sense: ERROR_AUTHENTICATION_FAILURE. In practice 691 arrives not only on
# wrong credentials but also on a "zombie" handle from a previous session
# (see rasdial_connect): RasGetCredentialsW succeeds, but RasDialW fails.
# No other RasDial codes are added here — for them /DISCONNECT is useless
# and sometimes harmful (see the retry condition below).
RAS_ERROR_AUTHENTICATION_FAILURE = 691

UNLEN = 256
PWLEN = 256
DNLEN = 15

ERROR_INVALID_HANDLE = 6


if IS_WINDOWS:
    class _RASCREDENTIALS(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("dwMask", wintypes.DWORD),
            ("szUserName", wintypes.WCHAR * (UNLEN + 1)),
            ("szPassword", wintypes.WCHAR * (PWLEN + 1)),
            ("szDomain", wintypes.WCHAR * (DNLEN + 1)),
        ]


    class _RASDIALPARAMS(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("szEntryName", wintypes.WCHAR * (RAS_MaxEntryName + 1)),
            ("szPhoneNumber", wintypes.WCHAR * (RAS_MaxPhoneNumber + 1)),
            ("szCallbackNumber", wintypes.WCHAR * (RAS_MaxCallbackNumber + 1)),
            ("szUserName", wintypes.WCHAR * (UNLEN + 1)),
            ("szPassword", wintypes.WCHAR * (PWLEN + 1)),
            ("szDomain", wintypes.WCHAR * (DNLEN + 1)),
        ]


    _rasapi32 = ctypes.WinDLL("rasapi32", use_last_error=True)

    _RasGetCredentialsW = _rasapi32.RasGetCredentialsW
    _RasGetCredentialsW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(_RASCREDENTIALS),
    ]
    _RasGetCredentialsW.restype = wintypes.DWORD

    _RasDialW = _rasapi32.RasDialW
    _RasDialW.argtypes = [
        ctypes.c_void_p,                    # lpRasDialExtensions
        wintypes.LPCWSTR,                   # lpszPhonebook
        ctypes.POINTER(_RASDIALPARAMS),     # lpRasDialParams
        wintypes.DWORD,                     # dwNotifierType
        ctypes.c_void_p,                    # lpvNotifier (RasDialFunc1 pointer)
        ctypes.POINTER(ctypes.c_void_p),    # lphRasConn
    ]
    _RasDialW.restype = wintypes.DWORD

    # RasHangUpW takes HRASCONN — the same handle that RasDial returns.
    # RASCONNW / RasEnumConnections are not needed here.
    _RasHangUpW = _rasapi32.RasHangUpW
    _RasHangUpW.argtypes = [ctypes.c_void_p]
    _RasHangUpW.restype = wintypes.DWORD
    
    # ---------------------------------------------------------------------------
    # IP Helper (for get_interface_info without PowerShell)
    # ---------------------------------------------------------------------------
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

    GAA_FLAG_INCLUDE_PREFIX   = 0x0010
    GAA_FLAG_SKIP_ANYCAST     = 0x0002
    GAA_FLAG_SKIP_MULTICAST   = 0x0004
    GAA_FLAG_SKIP_DNS_SERVER  = 0x0008
    GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    AF_INET  = 2
    AF_UNSPEC = 0

    # Interface types (RFC 2863 / ipifcons.h) and link status — needed
    # to distinguish a physical
    # uplink from a VPN adapter (PPP — L2TP/PPTP/SSTP client, Tunnel —
    # most modern VPN tunnels) and from loopback.
    IF_TYPE_PPP = 23
    IF_TYPE_TUNNEL = 131
    IF_TYPE_SOFTWARE_LOOPBACK = 24
    # IfType for physical adapters — needed by get_active_physical_adapter_info()
    # (wifi vs ethernet) so that _network_recovery_aggressive() in IPTV_scanner.pyw
    # picks the right strategy (kind): "wifi_soft_reset" for Wi-Fi,
    # "adapter_restart" for wired. The Wi-Fi reset implementation itself now lives
    # in IPTV_scanner.pyw (_wifi_soft_reset_local) and this module is not involved.
    IF_TYPE_ETHERNET_CSMACD = 6
    IF_TYPE_IEEE80211 = 71
    IF_OPER_STATUS_UP = 1
    # For MIB_IF_ROW2 (GetIfEntry2, see below) — field sizes for Alias/
    # Description/PhysicalAddress from netioapi.h/ifdef.h.
    IF_MAX_STRING_SIZE = 256
    IF_MAX_PHYS_ADDRESS_LENGTH = 32

    class _SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [
            ("lpSockaddr", ctypes.POINTER(ctypes.c_byte)),
            ("iSockaddrLength", ctypes.c_int),
        ]

    class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass
    _IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", _SOCKET_ADDRESS),
        # remaining fields are not needed
    ]
    
    # IP_ADAPTER_DNS_SERVER_ADDRESS repeats the first four fields of
    # _IP_ADAPTER_UNICAST_ADDRESS (Length/Reserved/Next/Address), but in the unicast
    # structure Flags follows Length, while in the DNS structure it is Reserved. For our
    # purposes there is no difference, but a separate definition is semantically more
    # accurate and will not break if we later need to read DNS-server-specific fields.
    class _IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
        pass
    _IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ("Address", _SOCKET_ADDRESS),
    ]

    # IP_ADAPTER_GATEWAY_ADDRESS repeats the first four fields of
    # _IP_ADAPTER_DNS_SERVER_ADDRESS (Length/Reserved/Next/Address). Defined
    # separately for the same reason: each list gets its own semantically correct
    # type, and adding specific fields to one will not affect the other.
    class _IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
        pass
    _IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
        ("Address", _SOCKET_ADDRESS),
    ]

    class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass
    _IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS)),
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
        # FirstGatewayAddress is used only as a "does the adapter have a
        # gateway" flag — we do not walk the gateway list itself, so it does
        # not need the full IP_ADAPTER_GATEWAY_ADDRESS structure; c_void_p is
        # enough: NULL/non-NULL is checked the same way in both cases.
        ("FirstGatewayAddress", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
        # further fields need not be described — Length protects us
    ]

    _GetAdaptersAddresses = _iphlpapi.GetAdaptersAddresses
    _GetAdaptersAddresses.argtypes = [
        wintypes.ULONG,                          # Family
        wintypes.ULONG,                          # Flags
        ctypes.c_void_p,                         # Reserved
        ctypes.POINTER(_IP_ADAPTER_ADDRESSES),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _GetAdaptersAddresses.restype = wintypes.ULONG

    # GetIfEntry2 (MIB_IF_ROW2) — 64-bit interface traffic counters, see
    # get_interface_counters() below. Structure copy from netioapi.h. On VPN
    # reconnect InOctets/OutOctets are zeroed even when ifIndex is reused
    # (verified on a live connection). Two places need explicit padding because
    # ctypes, unlike a C compiler, does not add it automatically before the next
    # field:
    #   * InterfaceAndOperStatusFlags — in C these are 8 single-bit fields; we do
    #     not need the values, we need to preserve the offset of subsequent fields
    #     — c_uint8 + 3 bytes of padding;
    #   * ConnectionType (uint32) before TransmitLinkSpeed (uint64) — explicit
    #     c_uint32 padding to an 8-byte boundary.
    class _MIB_IF_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_uint32),
            ("InterfaceGuid", ctypes.c_byte * 16),
            ("Alias", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
            ("Description", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
            ("PhysicalAddressLength", ctypes.c_uint32),
            ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
            ("PermanentPhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
            ("Mtu", ctypes.c_uint32),
            ("Type", ctypes.c_uint32),
            ("TunnelType", ctypes.c_uint32),
            ("MediaType", ctypes.c_uint32),
            ("PhysicalMediumType", ctypes.c_uint32),
            ("AccessType", ctypes.c_uint32),
            ("DirectionType", ctypes.c_uint32),
            ("InterfaceAndOperStatusFlags", ctypes.c_uint8),
            ("_flags_padding", ctypes.c_uint8 * 3),
            ("OperStatus", ctypes.c_uint32),
            ("AdminStatus", ctypes.c_uint32),
            ("MediaConnectState", ctypes.c_uint32),
            ("NetworkGuid", ctypes.c_byte * 16),
            ("ConnectionType", ctypes.c_uint32),
            ("_conn_padding", ctypes.c_uint32),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
            ("InOctets", ctypes.c_uint64),
            ("InUcastPkts", ctypes.c_uint64),
            ("InNUcastPkts", ctypes.c_uint64),
            ("InDiscards", ctypes.c_uint64),
            ("InErrors", ctypes.c_uint64),
            ("InUnknownProtos", ctypes.c_uint64),
            ("InUcastOctets", ctypes.c_uint64),
            ("InMulticastOctets", ctypes.c_uint64),
            ("InBroadcastOctets", ctypes.c_uint64),
            ("OutOctets", ctypes.c_uint64),
            ("OutUcastPkts", ctypes.c_uint64),
            ("OutNUcastPkts", ctypes.c_uint64),
            ("OutDiscards", ctypes.c_uint64),
            ("OutErrors", ctypes.c_uint64),
            ("OutUcastOctets", ctypes.c_uint64),
            ("OutMulticastOctets", ctypes.c_uint64),
            ("OutBroadcastOctets", ctypes.c_uint64),
            ("OutQLen", ctypes.c_uint64),
        ]

    # Exported starting with Windows Vista; if for some reason the symbol is
    # missing (a very old system or a stripped-down build of iphlpapi.dll),
    # get_interface_counters() quietly returns None — same as on any other
    # iphlpapi error.
    _GetIfEntry2: Optional[Any]
    try:
        _GetIfEntry2 = _iphlpapi.GetIfEntry2
        _GetIfEntry2.argtypes = [ctypes.POINTER(_MIB_IF_ROW2)]
        _GetIfEntry2.restype = wintypes.ULONG
    except (AttributeError, OSError):
        _GetIfEntry2 = None



# ═══════════════════════════════════════════════════════════════════════
# PART 0. Low-level transport: Windows named pipe via raw Win32 API
# (ctypes), with an explicit security descriptor. Used by both the client
# and server roles — see the explanation in the module docstring above on
# why we cannot simply use multiprocessing.connection.
# ═══════════════════════════════════════════════════════════════════════

if IS_WINDOWS:
    # use_last_error=True is required so that ctypes.get_last_error() below
    # returns the real Win32 API error code (without this flag ctypes does not
    # capture GetLastError() immediately after the call, and the error code in
    # diagnostic messages would be meaningless/zero).
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    PIPE_ACCESS_DUPLEX = 0x00000003
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    ERROR_PIPE_CONNECTED = 535
    ERROR_PIPE_BUSY = 231
    ERROR_FILE_NOT_FOUND = 2
    ERROR_BROKEN_PIPE = 109
    ERROR_NO_DATA = 232
    ERROR_PIPE_NOT_CONNECTED = 233
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    TOKEN_QUERY = 0x0008
    TokenUser = 1
    STILL_ACTIVE = 259
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR),
    ]

    _kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    _kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    _kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    _kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    _kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    _kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    _kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
    ]
    # Process creation time — together with the PID gives a PID-reuse-resistant
    # identifier of a specific process instance (see _process_start_time).
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
    ]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    _kernel32.GetNamedPipeClientProcessId.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
    ]

    class PipeError(OSError):
        pass

    _SID_RE = re.compile(r"^S-\d+(-\d+)+$")

    def _sid_from_token(token: int) -> Optional[str]:
        needed = wintypes.DWORD(0)
        _advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not _advapi32.GetTokenInformation(
            token, TokenUser, buf, needed.value, ctypes.byref(needed)
        ):
            return None
        # TOKEN_USER starts with a PSID (pointer).
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents.value
        sid_str = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_str)):
            return None
        try:
            return sid_str.value
        finally:
            _kernel32.LocalFree(sid_str)

    # Cache of the current user SID. The SID is an invariant of the vpn.exe
    # process: it does not change during its lifetime. _process_same_user() is
    # called in _handle_client on EVERY client command (per protocol — one
    # command = one connection, see send_command), and without a cache every
    # call would re-open the token of its own process.
    #
    # Only a SUCCESSFUL result is cached: a transient OpenProcessToken/
    # GetTokenInformation failure must not stick in the cache, otherwise
    # _process_same_user() would start permanently rejecting legitimate
    # clients until the helper is restarted (in _handle_client that would
    # lead to "access denied" on every command).
    #
    # The lock is not strictly required (in the server role clients are
    # handled sequentially by a single thread, and a race of two threads
    # would only cause a repeated computation, not data corruption), but it
    # is cheap and removes the thread-safety question for any future change
    # of the handling model.
    _current_user_sid_cache: Optional[str] = None
    _current_user_sid_cache_lock = threading.Lock()

    def _current_user_sid() -> Optional[str]:
        global _current_user_sid_cache
        cached = _current_user_sid_cache
        if cached is not None:
            return cached
        with _current_user_sid_cache_lock:
            cached = _current_user_sid_cache
            if cached is not None:
                return cached
            token = wintypes.HANDLE()
            if not _advapi32.OpenProcessToken(
                _kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
            ):
                return None
            try:
                sid = _sid_from_token(token.value)  # type: ignore[arg-type]
            finally:
                _kernel32.CloseHandle(token)
            if sid:
                _current_user_sid_cache = sid
            return sid

    def _process_user_sid(pid: int) -> Optional[str]:
        handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            token = wintypes.HANDLE()
            if not _advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
                return None
            try:
                return _sid_from_token(token.value)  # type: ignore[arg-type]
            finally:
                _kernel32.CloseHandle(token)
        finally:
            _kernel32.CloseHandle(handle)

    def _process_same_user(pid: int) -> bool:
        mine = _current_user_sid()
        theirs = _process_user_sid(pid)
        return bool(mine and theirs and mine == theirs)

    def _pipe_sddl() -> str:
        """DACL only for the current user (+ SYSTEM), IL lowered to Medium.

        Authenticated Users (AU) is intentionally absent: otherwise any user
        on the machine could send remove_default_route/add_routes to the
        elevated helper.

        The named pipe is created by the elevated process and by default gets
        a High integrity label, so an ordinary (Medium IL) GUI client would
        not be able to open it for writing — therefore the label must be
        lowered explicitly. We lower it exactly to Medium (the level at which
        the client GUI process already runs), not to Low: Low IL in Windows is
        reserved for truly untrusted code (sandboxed processes such as
        Protected Mode IE or browser-extension sandboxes). The DACL itself
        checks only the SID, not the integrity level — so with a Low label
        the pipe would theoretically be writable by low-trust processes of
        the same user as well, expanding the attack surface without need.
        """
        sid = _current_user_sid()
        if sid and _SID_RE.match(sid):
            owner_ace = f"(A;;GRGW;;;{sid})"
        else:
            # IU = Interactive User — narrower than AU if the SID could not be obtained.
            owner_ace = "(A;;GRGW;;;IU)"
        return f"D:{owner_ace}(A;;GRGW;;;SY)S:(ML;;NW;;;ME)"

    def _build_pipe_security_attributes() -> Tuple[_SECURITY_ATTRIBUTES, Any]:
        psd = wintypes.LPVOID()
        ok = _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _pipe_sddl(), 1, ctypes.byref(psd), None
        )
        if not ok:
            raise PipeError(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: "
                f"WinError {ctypes.get_last_error()}"
            )
        sa = _SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = psd
        sa.bInheritHandle = False
        return sa, psd

    def _server_create_pipe_handle(first: bool) -> int:
        sa, psd = _build_pipe_security_attributes()
        flags = PIPE_ACCESS_DUPLEX
        if first:
            flags |= FILE_FLAG_FIRST_PIPE_INSTANCE
        try:
            handle = _kernel32.CreateNamedPipeW(
                PIPE_NAME, flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,          # nMaxInstances — one client at a time sequentially
                65536, 65536, 0, ctypes.byref(sa),
            )
        finally:
            # SD is copied into the pipe object; LocalFree is safe right after create.
            try:
                _kernel32.LocalFree(psd)
            except Exception:
                logger.debug("LocalFree(psd) failed in _server_create_pipe_handle", exc_info=True)
        if handle == INVALID_HANDLE_VALUE:
            raise PipeError(f"CreateNamedPipeW failed: WinError {ctypes.get_last_error()}")
        return int(handle)

    def _server_wait_for_client(handle: int) -> None:
        ok = _kernel32.ConnectNamedPipe(handle, None)
        if not ok:
            err = ctypes.get_last_error()
            if err != ERROR_PIPE_CONNECTED:
                raise PipeError(f"ConnectNamedPipe failed: WinError {err}")

    def _pipe_client_pid(handle: int) -> Optional[int]:
        pid = wintypes.DWORD(0)
        if not _kernel32.GetNamedPipeClientProcessId(handle, ctypes.byref(pid)):
            return None
        return int(pid.value) or None

    def _client_open_pipe(timeout_ms: int = 3000) -> int:
        """Opens the client end of the pipe.

        We retry not only ERROR_PIPE_BUSY but also ERROR_FILE_NOT_FOUND:
        between DisconnectNamedPipe and the next ConnectNamedPipe the pipe
        name briefly "does not exist".
        """
        deadline = time.monotonic() + max(int(timeout_ms), 1) / 1000.0
        last_err = 0
        while True:
            handle = _kernel32.CreateFileW(
                PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, None,
                OPEN_EXISTING, 0, None,
            )
            if handle != INVALID_HANDLE_VALUE:
                return int(handle)
            last_err = ctypes.get_last_error()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PipeError(f"CreateFileW failed: WinError {last_err}")
            if last_err == ERROR_PIPE_BUSY:
                wait_ms = max(1, min(int(remaining * 1000), 500))
                if not _kernel32.WaitNamedPipeW(PIPE_NAME, wait_ms):
                    time.sleep(0.05)
            elif last_err in (ERROR_FILE_NOT_FOUND, ERROR_PIPE_NOT_CONNECTED):
                time.sleep(0.05)
            else:
                raise PipeError(f"CreateFileW failed: WinError {last_err}")

    def _write_all(handle: int, data: bytes) -> None:
        buf = ctypes.create_string_buffer(data, len(data))
        total = 0
        written = wintypes.DWORD(0)
        while total < len(data):
            ok = _kernel32.WriteFile(
                handle, ctypes.byref(buf, total), len(data) - total,
                ctypes.byref(written), None,
            )
            if not ok:
                err = ctypes.get_last_error()
                if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
                    # The remote side has already closed the pipe (e.g. the client
                    # received the reply to the previous command and disconnected,
                    # as the protocol provides — see the send_command docstring).
                    # This is a normal session end, not an error.
                    raise EOFError("Pipe closed by the remote side")
                raise PipeError(f"WriteFile failed: WinError {err}")
            total += written.value

    def _read_exact(handle: int, n: int) -> bytes:
        buf = ctypes.create_string_buffer(n)
        total = 0
        read = wintypes.DWORD(0)
        while total < n:
            ok = _kernel32.ReadFile(
                handle, ctypes.byref(buf, total), n - total,
                ctypes.byref(read), None,
            )
            if not ok:
                err = ctypes.get_last_error()
                if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
                    raise EOFError("Pipe closed by the remote side")
                raise PipeError(f"ReadFile failed: WinError {err}")
            if read.value == 0:
                raise EOFError("Pipe closed by the remote side")
            total += read.value
        return buf.raw[:n]

    def pipe_write_message(handle: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(data) > MAX_PIPE_MESSAGE:
            raise PipeError(f"Message too large: {len(data)} bytes")
        _write_all(handle, len(data).to_bytes(4, "little") + data)

    def pipe_read_message(handle: int) -> dict:
        header = _read_exact(handle, 4)
        length = int.from_bytes(header, "little")
        if length > MAX_PIPE_MESSAGE:
            raise PipeError(f"Message too large: {length} bytes")
        raw = _read_exact(handle, length) if length else b""
        parsed = json.loads(raw.decode("utf-8"))
        # json.loads() can return anything (list/str/int/...), not only a
        # dict — e.g. if something that does not match our protocol arrived
        # on the pipe. Explicit check instead of a blind `return parsed`
        # (that would be Any disguised as dict) — it is a private named pipe,
        # but extra protection against garbage on input does not hurt.
        if not isinstance(parsed, dict):
            raise PipeError(f"Expected a JSON object, got {type(parsed).__name__}")
        return parsed

    def pipe_close(handle: int) -> None:
        try:
            _kernel32.CloseHandle(handle)
        except Exception:
            logger.debug("CloseHandle failed in pipe_close", exc_info=True)

    def _read_message_with_timeout(
        handle: int,
        timeout: float,
        *,
        abort: Optional[Callable[[], None]] = None,
    ) -> dict:
        """ReadFile in this synchronous (non-overlapped) mode has no built-in
        timeout — we wrap the read in a separate thread and wait via a queue.

        abort() is called when the deadline expires, to unblock a hung
        ReadFile:
          * client (abort=None) — closes the handle (it is no longer needed);
          * server — DisconnectNamedPipe, NOT CloseHandle: otherwise the only
            pipe instance is destroyed and the elevated helper dies.
        The reader thread is a daemon, so it does not prevent process exit.

        TRADE-OFF: abort() does not guarantee and does not instantly unblock
        a blocking ReadFile. If the reader thread receives data after
        TimeoutError, it does put_nowait — when the queue is full it simply
        drops the result and exits, without hanging forever on put.
        Full overlapped I/O + CancelIoEx would be more reliable, but would
        noticeably complicate the code for a rare edge case.
        """
        q: "queue.Queue" = queue.Queue(maxsize=1)

        def _reader() -> None:
            payload: Tuple[str, Any]
            try:
                payload = ("ok", pipe_read_message(handle))
            except Exception as e:  # noqa: BLE001
                payload = ("error", e)
            try:
                q.put_nowait(payload)
            except queue.Full:
                # Reader is late: the main thread has already left on timeout.
                pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        try:
            kind, value = q.get(timeout=timeout)
        except queue.Empty:
            try:
                if abort is not None:
                    abort()
                else:
                    pipe_close(handle)
            except Exception:
                logger.debug(
                    "abort()/pipe_close failed before raising TimeoutError",
                    exc_info=True,
                )
            raise TimeoutError("Timed out waiting for a reply on the pipe")
        if kind == "error":
            raise value
        return cast(dict, value)


# ═══════════════════════════════════════════════════════════════════════
# PART 0.5. Shared helpers (PowerShell / RAS / routes / processes).
# Used by both the client and the elevated server.
# ═══════════════════════════════════════════════════════════════════════

logger = logging.getLogger("iptv_scanner.vpn")

CONNECT_POLL_TIMEOUT = 20.0
CONNECT_POLL_INTERVAL = 0.25
DEFAULT_CMD_TIMEOUT = 45.0

# After RasDial the adapter/IP often appears in 1–3 s; after UAC/cold start
# it can take longer. 2.25 s (15×0.15) produced false
# "network interface could not be determined" and a cascade of soft recovery.
IF_INDEX_POLL_ATTEMPTS = 40      # 40×0.2 = 8 s
IF_INDEX_RETRY_EXTRA_ATTEMPTS = 50
IF_INDEX_POLL_INTERVAL = 0.20

# Short window for a "late" default route after connect. The loop exits
# early if there is no VPN default or it has already been removed.
# Windows/RAS usually adds the default within 1–2 s; 3.5 s with early
# exit (see remove_default_route) is enough without an extra UI pause.
DEFAULT_ROUTE_WATCH_SECONDS = 3.5
DEFAULT_ROUTE_WATCH_INTERVAL = 0.3

# VPN interface metric after force-split: if RAS still returns
# 0.0.0.0/0 via the tunnel, the physical default with the ordinary metric (~25)
# will remain preferred.
VPN_INTERFACE_METRIC_HIGH = 9000

# PowerShell 5.1 often emits UTF-16 LE when stdout is redirected. We force
# UTF-8 and additionally detect UTF-16 just in case.
_PS_UTF8_PREFIX = (
    "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
    "$OutputEncoding = [Console]::OutputEncoding; "
    "$ProgressPreference = 'SilentlyContinue'; "
)


def _warn_if_main_thread(op: str) -> None:
    try:
        if threading.current_thread() is threading.main_thread():
            logger.warning(
                "%s is called from the main thread and will block the GUI — "
                "call it from a worker thread",
                op,
            )
    except Exception:
        pass


def _no_window_kwargs() -> dict:
    if not IS_WINDOWS:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {"creationflags": subprocess.CREATE_NO_WINDOW, "startupinfo": si}


def _run(args: List[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout, **_no_window_kwargs())


def _decode_ps_output(raw: bytes) -> str:
    if not raw:
        return ""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace").strip()
    # UTF-16 LE without BOM: zeros on odd positions.
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        return raw.decode("utf-16-le", errors="replace").strip()
    return raw.decode("utf-8", errors="replace").strip()


def _validate_vpn_name(name: str) -> str:
    """Validates a VPN/interface name without an artificial Unicode restriction.

    The name is then safely inserted into PowerShell only via _ps_quote().
    """
    if not isinstance(name, str):
        raise ValueError(f"Invalid VPN/interface name: {name!r}")

    text = name.strip()

    if not text or len(text) > 256:
        raise ValueError(f"Invalid VPN/interface name: {name!r}")

    # Control characters in the name are not wanted. In particular, CR/LF
    # must not end up in the constructed PowerShell command.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError(f"Invalid VPN/interface name: {name!r}")

    return text


# PowerShell treats as a single-quote not only ASCII ' but also the
# typographic U+2018, U+2019, U+201A, U+201B. A VPN name may contain any
# Unicode, so all four plus ASCII must be escaped (doubled).
_PS_SINGLE_QUOTE_CHARS = frozenset("'\u2018\u2019\u201a\u201b")


def _ps_quote(value: str) -> str:
    """Safe single-quoted string literal for PowerShell."""
    return "'" + "".join(
        ch * 2 if ch in _PS_SINGLE_QUOTE_CHARS else ch for ch in value
    ) + "'"


def _is_valid_route_ip(value: Any) -> bool:
    """True if value is a valid ordinary unicast IPv4 address, suitable
    as a destination or gateway for a route added by the elevated helper.

    Besides the semantic check (multicast/broadcast/loopback/link-local/
    reserved must not appear here), this is also protection against command
    injection: `ip`/`gateway` from add_routes/remove_routes are substituted
    into a PowerShell command as an f-string in _unicast_route_exists().
    Without a strict format check, an arbitrary string like
    "1'; Remove-Item C:\\; '" would go straight into powershell.exe -Command.
    If value is not a valid IPv4 literal, ipaddress.IPv4Address raises and we
    return False without reaching any command substitution.
    """
    if not isinstance(value, str):
        return False
    try:
        addr = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return False
    if addr.is_multicast or addr.is_loopback or addr.is_link_local or \
            addr.is_reserved or addr.is_unspecified:
        return False
    if value == "255.255.255.255":
        return False
    # str(addr) canonicalizes the representation (e.g. strips leading zeros
    # of octets like "010", which some parsers treat as octal) — we use that
    # form, not the original string, further down the call chain.
    return True


def _is_valid_if_index(value: Any) -> bool:
    """True if value is a positive integer within reasonable bounds for a
    Windows InterfaceIndex. Rejects negative/zero/garbage string values
    before if_index reaches route.exe / PowerShell commands."""
    try:
        idx = int(value)
    except (TypeError, ValueError):
        return False
    return 0 < idx <= 0x7FFFFFFF


# ---------------------------------------------------------------------------
# VPN profile scope resolution cache.
#
# get_vpn_connected/... are called from the hot path (precheck, reconnect-retry),
# and with all_user=None each call currently runs powershell.exe TWICE
# (~1 s each): first checks the All-User profile, then User. For legacy
# configs without all_user this is a noticeable delay for no good reason.
#
# We cache only an UNAMBIGUOUS resolution: the profile exists in exactly one
# scope. Negative cache (profile not found / found in both) is deliberately
# not kept:
#   * "not found" can become "found" if the user creates a profile mid-scanner
#     session — a negative cache would force waiting for TTL expiry, and the
#     GUI would show "VPN state unknown" for no reason;
#   * "found in both" is a clear anomaly, where a TTL cache would only mask
#     a name conflict.
#
# Thread safety: dict operations (.get/.popitem/[]) are atomic under the GIL,
# and a race "two threads both miss and both write" is harmless — both write
# the same correct value. No lock needed.
#
# TTL is short (120 s): if the profile is nevertheless moved between scopes
# manually, detection delay is minutes, not "until restart".
# ---------------------------------------------------------------------------
_scope_cache: Dict[str, Tuple[float, bool]] = {}
_SCOPE_CACHE_TTL = 120.0


def _get_cached_scope(name: str) -> Optional[bool]:
    """Scope from the cache (True=All-User, False=User) or None if there is
    no entry or it has expired. None here means specifically "no cache" —
    the value None is never written into the cache (see the comment above)."""
    entry = _scope_cache.get(name)
    if entry is None:
        return None
    ts, scope = entry
    if time.monotonic() - ts >= _SCOPE_CACHE_TTL:
        return None
    return scope


def _set_cached_scope(name: str, scope: bool) -> None:
    _scope_cache[name] = (time.monotonic(), scope)


def _query_vpn_field_per_scope(
    name: str,
    all_user: Optional[bool],
    ps_expr: str,
    parse_value: Callable[[Any], Optional[Any]],
    *,
    timeout: float,
    field_name: str,
) -> Optional[Any]:
    """Shared wrapper for get_vpn_connected/get_vpn_split_tunneling.

    ps_expr — PowerShell expression after Get-VpnConnection<scope> -Name '<name>',
    returning the JSON value of the field (e.g.
    "Select-Object -ExpandProperty ConnectionStatus | ConvertTo-Json -Compress").

    parse_value(raw) -> Optional[Any]: None if raw is not recognized.

    all_user=None: first look at the resolved-scope cache (_get_cached_scope).
    If it has True/False — query only that scope; on a miss — both, as before.
    On an unambiguous answer (value obtained in exactly one scope) we cache
    the scope for subsequent calls. The field value is returned, or None on
    error / scope collision.
    """
    try:
        validated = _validate_vpn_name(name)
    except ValueError:
        logger.warning(
            "_query_vpn_field_per_scope(%s): invalid VPN name %r", field_name, name,
        )
        return None
    safe_name = _ps_quote(validated)

    cached_scope: Optional[bool] = None
    scopes: List[Tuple[str, bool]]
    if all_user is None:
        cached_scope = _get_cached_scope(validated)
        if cached_scope is not None:
            # One scope from the cache — save the second powershell.exe.
            scopes = [(" -AllUserConnection" if cached_scope else "", cached_scope)]
        else:
            scopes = [(" -AllUserConnection", True), ("", False)]
    else:
        scopes = [(" -AllUserConnection" if all_user else "", all_user)]

    def _try_scope(extra: str, scope: bool) -> Optional[Any]:
        cmd = (
            f"Get-VpnConnection{extra} -Name {safe_name} -ErrorAction SilentlyContinue | "
            f"{ps_expr}"
        )
        try:
            raw = run_powershell_json(cmd, timeout=timeout)
        except Exception:
            raw = None
        return parse_value(raw)

    found: List[Tuple[Any, bool]] = []
    for extra, scope in scopes:
        parsed = _try_scope(extra, scope)
        if parsed is not None:
            found.append((parsed, scope))

    # Fallback: if we relied on the cache and the "hinted" scope has nothing —
    # the profile may have been moved between scopes after the cache was
    # filled (rare but not impossible). Try the other scope once so we do not
    # report a false "state unknown".
    if all_user is None and cached_scope is not None and not found:
        other_scope = not cached_scope
        other_extra = " -AllUserConnection" if other_scope else ""
        parsed = _try_scope(other_extra, other_scope)
        if parsed is not None:
            found.append((parsed, other_scope))

    # Unambiguous answer with all_user=None — cache the scope for the future.
    # Do not cache when all_user is given explicitly: resolution is not needed.
    if all_user is None and len(found) == 1:
        _set_cached_scope(validated, found[0][1])

    if not found:
        return None
    if len(found) > 1:
        logger.warning(
            "_query_vpn_field_per_scope(%s): profile %r found as both "
            "AllUser and User — scope is ambiguous, value undetermined "
            "(pass all_user explicitly)",
            field_name, name,
        )
        return None
    return found[0][0]


def run_powershell_json(command: str, timeout: float = 10.0) -> Any:
    """Runs powershell.exe and parses stdout as JSON. Works from both the
    unelevated GUI and the elevated helper (visible VPN profiles depend on
    the process token)."""
    proc = _run(
        [
            POWERSHELL_EXE,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _PS_UTF8_PREFIX + command,
        ],
        timeout=timeout,
    )
    text = _decode_ps_output(proc.stdout)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Single logger call: the module `logger` ("iptv_scanner.vpn") propagates
        # the record up the hierarchy both on the client (into "iptv_scanner") and
        # on the server (into "vpn_helper" — see _setup_server_logging, where the
        # handler is attached to both loggers). An extra direct call to
        # logging.getLogger("vpn_helper") would duplicate the line in vpn_helper.log
        # in the elevated process.
        logger.warning("Failed to parse JSON from PowerShell: %r", text[:500])
        return None


def _secure_zero(obj: Any) -> None:
    try:
        ctypes.memset(ctypes.addressof(obj), 0, ctypes.sizeof(obj))
    except Exception:
        logger.debug(
            "Failed to zero the in-memory credentials buffer (_secure_zero)",
            exc_info=True,
        )


def _hangup_and_drain(hrasconn: Any, wait: float = 3.0) -> None:
    """RasHangUp + a short pause so RAS has time to tear down the port.

    MSDN: after an unsuccessful RasDial the handle must still be closed via
    RasHangUp, otherwise the port/connection hangs in Connecting.
    """
    if not IS_WINDOWS:
        return
    value = getattr(hrasconn, "value", None)
    if not value:
        return
    try:
        _RasHangUpW(hrasconn)
    except Exception:
        logger.exception("RasHangUpW")
    deadline = time.monotonic() + max(wait, 0.0)
    while time.monotonic() < deadline:
        try:
            rc = _RasHangUpW(hrasconn)
            if rc == ERROR_INVALID_HANDLE:
                return
        except Exception:
            return
        time.sleep(0.25)


def _ras_phonebook_path(all_user: Optional[bool]) -> Optional[str]:
    """Explicit phonebook for the selected scope. None = system default."""
    if all_user is None:
        return None
    if all_user:
        base = os.environ.get("ProgramData")
    else:
        base = os.environ.get("APPDATA")
    if not base:
        return None
    path = Path(base) / "Microsoft" / "Network" / "Connections" / "Pbk" / "rasphone.pbk"
    return str(path) if path.exists() else None


def _release_hung_rasdial_slot(hang_ts: float) -> None:
    """The only way to decrease _hung_rasdial_count.

    Called from _late_hangup/_late_hangup_retry EXACTLY ONCE, when
    worker.join() for the hung RasDialW has actually returned — i.e.
    the Win32 call no longer holds the PPP port and does not block RasMan. No
    other path for removing the entry (in particular, by age) exists: that
    is the essence of the circuit breaker — the refusal holds until the actual return
    of the call, not until an arbitrary timer expires.
    """
    global _hung_rasdial_count
    with _hung_rasdial_lock:
        _hung_rasdial_count = max(0, _hung_rasdial_count - 1)
        remaining = _hung_rasdial_count
        try:
            _hung_rasdial_timestamps.remove(hang_ts)
        except ValueError:
            # Should not happen (each hang_ts is removed exactly once), but
            # we do not treat this as an error — what matters is that the counter is already decremented.
            pass
    logger.info(
        "A previously hung RasDialW call returned — %d hung call(s) remain",
        remaining,
    )


def rasdial_connect(name: str, timeout: float = 40.0, all_user: Optional[bool] = None) -> Tuple[bool, str]:
    """Connects RAS/VPN via RasGetCredentials + asynchronous RasDial.

    The password is not extracted in cleartext: Windows returns a password
    handle (usually 16 asterisks) that RasDial knows how to use.

    IMPORTANT: the call blocks the current thread until success/failure/timeout —
    do not call from the GUI thread. The timeout is real: on expiry
    RasHangUp is performed to unblock a hung IKE/PPP.
    """
    global _hung_rasdial_count
    _warn_if_main_thread("rasdial_connect")
    if not IS_WINDOWS:
        return False, "VPN functionality is available only on Windows"
    try:
        name = _validate_vpn_name(name)
    except ValueError as e:
        return False, str(e)

    credentials = _RASCREDENTIALS()
    params = _RASDIALPARAMS()
    phonebook = _ras_phonebook_path(all_user)
    if all_user is not None and phonebook is None:
        return False, "Phonebook of the selected VPN profile not found"
        
    try:
        credentials.dwSize = ctypes.sizeof(_RASCREDENTIALS)
        credentials.dwMask = RASCM_UserName | RASCM_Password | RASCM_Domain

        rc = _RasGetCredentialsW(phonebook, name, ctypes.byref(credentials))
        if rc != 0:
            logger.error("RasGetCredentialsW(%r) failed: code=%s", name, rc)
            return False, f"RasGetCredentials returned code {rc}"

        if not (credentials.dwMask & RASCM_Password):
            logger.error(
                "No saved password for VPN %r (dwMask=0x%08X)",
                name, credentials.dwMask,
            )
            return False, "No saved password found for the VPN"

        username = credentials.szUserName
        password_handle = credentials.szPassword
        domain = credentials.szDomain

        logger.info(
            "Retrieved saved RAS credentials for %r: user=%r, "
            "domain=%r, password_handle=%s",
            name, username, domain,
            "present" if password_handle else "absent",
        )

        if not username:
            return False, "RasGetCredentials did not return a user name"
        if not password_handle:
            return False, "RasGetCredentials did not return a password handle"

        params.dwSize = ctypes.sizeof(_RASDIALPARAMS)
        params.szEntryName = name
        params.szUserName = username
        params.szPassword = password_handle
        params.szDomain = domain

        # Synchronous RasDial (lpvNotifier=NULL) — without extra callback delay.
        # Runs in a thread to honour the timeout: if RAS hangs the GUI is not
        # blocked forever. The handle for HangUp appears only when RasDial
        # returns, so on timeout the deferred hangup is attached to the same
        # thread.
        # Protection against accumulation of daemon threads on systematic RAS API timeouts
        # (see the docstring below about the "known trade-off"): if already MAX_HUNG_RASDIAL
        # previous calls have hung and their observer threads are still waiting for
        # RasDialW to complete, a new call is not started — an explicit error is better than another
        # potentially eternal thread.
        with _hung_rasdial_lock:
            if _hung_rasdial_count >= MAX_HUNG_RASDIAL:
                # Age of the oldest hung call — only for
                # diagnostics (to distinguish a fresh incident from prolonged
                # degradation). It does not affect the refusal itself and does not
                # participate in the limit: there is no more "age-out", the entry is removed
                # only on the actual return of worker.join() — see
                # _release_hung_rasdial_slot.
                oldest_age = (
                    time.monotonic() - min(_hung_rasdial_timestamps)
                    if _hung_rasdial_timestamps else 0.0
                )
                logger.error(
                    "RasDialW(%r): refusing to start — %d earlier hung "
                    "calls are still alive (limit %d, oldest hang %.0f s ago); "
                    "the RAS API appears to be persistently unresponsive",
                    name, _hung_rasdial_count, MAX_HUNG_RASDIAL, oldest_age,
                )
                return False, (
                    f"Too many hung previous connection attempts "
                    f"({_hung_rasdial_count}); the RAS service appears unresponsive — "
                    "try restarting the 'Remote Access Connection Manager' "
                    "service (RasMan) or rebooting the computer"
                )

        hrasconn = ctypes.c_void_p()
        box: Dict[str, int] = {}

        def _dial() -> None:
            try:
                box["rc"] = int(_RasDialW(
                    None, phonebook, ctypes.byref(params),
                    0, None, ctypes.byref(hrasconn),
                ))
            except Exception:
                logger.exception("RasDialW(%r) raised an exception", name)
                box["rc"] = -1

        worker = threading.Thread(target=_dial, daemon=True, name="rasdial-connect")
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            logger.error("RasDialW(%r): timeout %.1fs", name, timeout)

            # KNOWN TRADE-OFF: worker.join() here has no timeout —
            # deliberately. hrasconn is valid only after RasDialW
            # returns, so HangUp cannot be called earlier. If RasDialW
            # has genuinely hung solid (and is not merely responding slowly),
            # this observer thread will remain alive until process end —
            # a daemon thread, does not leak handles/memory beyond the stack, simply
            # waits forever. Full protection would require forcibly
            # cancelling RasDialW itself, which the Win32 RAS API does not provide
            # natively; on repeated timeouts (not single ones) one should
            # look toward restarting the RAS subsystem/rebooting, rather
            # than complicating this thread.
            hang_ts = time.monotonic()
            with _hung_rasdial_lock:
                _hung_rasdial_count += 1
                _hung_rasdial_timestamps.append(hang_ts)

            def _late_hangup() -> None:
                try:
                    worker.join()
                    _hangup_and_drain(hrasconn)
                finally:
                    _release_hung_rasdial_slot(hang_ts)

            threading.Thread(target=_late_hangup, daemon=True, name="rasdial-hangup").start()
            return False, f"VPN connection timed out ({timeout:.0f} s)"

        rc = int(box.get("rc", -1))
        if rc != 0:
            logger.error("RasDialW(%r) failed: code=%s", name, rc)
            _hangup_and_drain(hrasconn)

            # RasDialW can fail not because of credentials but because of a
            # "zombie" handle from a previous session: RasGetCredentialsW
            # succeeds (password_handle=present), but RasDialW returns 691.
            # One recovery cycle (check → /DISCONNECT → retry RasDial) fixes
            # this case.
            #
            # IMPORTANT (unlike the old preventive /DISCONNECT at the start
            # of the function): here we take the destructive step ONLY if
            # RasDialW has already failed with a specific code, and ONLY after
            # confirming that the VPN is still not connected. This eliminates
            # the TOCTOU race with a user who may have manually brought the
            # VPN up between the decision to "connect" and our disconnect.
            #
            # Between this final get_vpn_connected() check and the /DISCONNECT
            # call a small window remains (a few tens of ms) that cannot be
            # closed without an atomic Win32 API. It is orders of magnitude
            # narrower than the original (where preventive /DISCONNECT ran
            # before RasDial, i.e. seconds before any check).
            if rc == RAS_ERROR_AUTHENTICATION_FAILURE:
                recovered = _recover_stale_ras_entry(name, phonebook, all_user)
                if recovered:
                    logger.info(
                        "RasDialW(%r): retrying after recovering the stale "
                        "RAS entry", name,
                    )
                    # Retry RasDial. hrasconn was already closed via
                    # _hangup_and_drain above — create a new one.
                    hrasconn = ctypes.c_void_p()
                    box.clear()

                    worker = threading.Thread(
                        target=_dial, daemon=True, name="rasdial-connect-retry",
                    )
                    worker.start()
                    worker.join(timeout)
                    if worker.is_alive():
                        # Same "hanging RasDialW" contract as the first
                        # call: increment the shared counter and attach
                        # a late hangup.
                        logger.error(
                            "RasDialW(%r, retry): timeout %.1fs", name, timeout,
                        )
                        hang_ts = time.monotonic()
                        with _hung_rasdial_lock:
                            _hung_rasdial_count += 1
                            _hung_rasdial_timestamps.append(hang_ts)

                        def _late_hangup_retry() -> None:
                            try:
                                worker.join()
                                _hangup_and_drain(hrasconn)
                            finally:
                                _release_hung_rasdial_slot(hang_ts)

                        threading.Thread(
                            target=_late_hangup_retry,
                            daemon=True, name="rasdial-hangup-retry",
                        ).start()
                        return False, f"VPN connection timed out ({timeout:.0f} s)"

                    rc = int(box.get("rc", -1))
                    if rc != 0:
                        logger.error(
                            "RasDialW(%r, retry) failed: code=%s", name, rc,
                        )
                        _hangup_and_drain(hrasconn)
                        return False, f"RasDial returned code {rc} (after RAS recovery)"
                    logger.info(
                        "VPN %r connected via RasDialW after RAS recovery "
                        "(handle=%s)", name, hrasconn.value,
                    )
                    return True, ""
                # recovery failed (VPN is still connected by someone else,
                # or state is unknown) — do not take destructive actions,
                # return the original error.
                logger.info(
                    "RasDialW(%r): no recovery attempted for code %s — "
                    "another VPN session is (possibly) active, not touching it",
                    name, rc,
                )

            return False, f"RasDial returned code {rc}"

        logger.info(
            "VPN %r connected successfully via RasDialW (handle=%s)",
            name, hrasconn.value,
        )
        return True, ""
    finally:
        _secure_zero(credentials)
        _secure_zero(params)


def _recover_stale_ras_entry(
    name: str,
    phonebook: Optional[str],
    all_user: Optional[bool],
) -> bool:
    """Recovers a "stuck" RAS entry after RasDialW with code 691.

    Does exactly what the preventive /DISCONNECT at the start of
    rasdial_connect() used to do, but:
      * only AFTER RasDialW has failed with a specific code;
      * only after a fresh check that the VPN is still not connected.

    Returns True if /DISCONNECT was performed (or is no longer needed —
    see below), and the caller may try RasDialW again.

    Returns False if there is nothing to recover: the VPN is already
    connected (or its state is unknown) — in that case the destructive
    step would interfere with someone else's/an unknown session.

    Between the final get_vpn_connected() check and the rasdial
    /DISCONNECT call a small window remains (tens of ms) that cannot be
    closed without an atomic Win32 API. In practice it is orders of
    magnitude narrower than the original.
    """
    if not IS_WINDOWS:
        return False

    # Fresh check BEFORE the destructive step. Any outcome other than
    # "definitely not connected" cancels /DISCONNECT:
    #   True — the user brought the VPN up between our decision and now;
    #   None — state unknown (PowerShell did not respond), we do not risk it.
    try:
        still_connected = get_vpn_connected(name, all_user=all_user, timeout=5.0)
    except Exception:
        logger.debug(
            "_recover_stale_ras_entry: get_vpn_connected(%r) failed", name,
            exc_info=True,
        )
        still_connected = None

    if still_connected is not False:
        logger.info(
            "_recover_stale_ras_entry(%r): connection state is %s, not False — "
            "skipping /DISCONNECT (would interfere with an active/unknown session)",
            name, still_connected,
        )
        return False

    args = [RASDIAL_EXE, name, "/DISCONNECT"]
    if phonebook:
        args.insert(1, f"/PHONEBOOK:{phonebook}")
    try:
        _run(args, timeout=8.0)
    except Exception:
        logger.debug(
            "_recover_stale_ras_entry: rasdial /DISCONNECT failed", exc_info=True,
        )
    # Short pause so RAS has time to actually finish teardown: rasdial
    # /DISCONNECT returns 0 before the RAS service releases the entry.
    time.sleep(0.8)
    return True


def rasdial_disconnect(name: str, timeout: float = 20.0, all_user: Optional[bool] = None) -> bool:
    """Disconnects a RAS/VPN connection via RASDIAL_EXE /DISCONNECT.

    Unlike connect (rasdial_connect uses the RAS API because RASDIAL_EXE does
    not see saved credentials of "modern" VPNs), DISCONNECT does not require
    credentials. Reproducing RASCONNW via ctypes is unnecessary: the structure
    could not be described stably (ERROR_INVALID_SIZE), and RASDIAL_EXE does
    it internally.
    """
    if not IS_WINDOWS:
        return False
    try:
        name = _validate_vpn_name(name)
    except ValueError:
        logger.warning("rasdial_disconnect: invalid VPN name %r", name)
        return False
    args = [RASDIAL_EXE, name, "/DISCONNECT"]
    phonebook = _ras_phonebook_path(all_user)
    if all_user is not None and phonebook is None:
        logger.error("Phonebook of the selected VPN profile %r not found", name)
        return False
    if phonebook:
        args.insert(1, f"/PHONEBOOK:{phonebook}")
    try:
        proc = _run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error("rasdial /DISCONNECT: timeout")
        return False
    ok = proc.returncode == 0
    if ok:
        logger.info("VPN %r disconnected (rasdial /DISCONNECT)", name)
        # rasdial /DISCONNECT returns 0 BEFORE the RAS service has actually
        # finished session teardown. If immediately after that (including from
        # another process — the typical fast close/reopen scenario
        # of the program) one calls RasDial on the same entry, Windows still sees
        # a "zombie" handle from the previous connection and returns 691.
        # A short pause gives RAS time to finish teardown before
        # a new client takes the entry. It also closes the race with
        # the helper's _on_gui_died, which does disconnect in parallel.
        time.sleep(0.8)
        return True

    # A non-zero rasdial /DISCONNECT code does not necessarily mean the VPN remained
    # connected: it is also returned when the connection was already gone (e.g. it
    # dropped on its own before the call). Treating this as "failed to disconnect" is wrong — recovery paths
    # (self-heal on start, rollback, release_and_disconnect, etc.) would start
    # repeated/emergency actions on an already non-existent connection. Therefore
    # the actual state is re-checked via get_vpn_connected():
    #   connected is False -> really disconnected, treat as success;
    #   connected is True  -> indeed did not disconnect, this is failure;
    #   connected is None  -> could not check, stay with the conservative
    #                         rasdial answer (failure).
    #
    # The check timeout is separate and short (not the rasdial timeout itself, which
    # can be 20+ s): this is PowerShell (Get-VpnConnection), and rasdial_disconnect
    # is called from hot paths (_on_gui_died, self-heal on start,
    # release_and_disconnect), where an extra ~10 s of blocking just to confirm
    # an almost obvious success is unacceptable. If the check did not finish in time,
    # None is returned (see the branch below), not a longer wait.
    logger.info(
        "rasdial %r /DISCONNECT returned code %s — checking the actual "
        "connection state (it may mean it was already inactive)",
        name, proc.returncode,
    )
    try:
        connected = get_vpn_connected(name, all_user=all_user, timeout=5.0)
    except Exception:
        logger.debug("rasdial_disconnect: the get_vpn_connected check failed", exc_info=True)
        connected = None

    if connected is False:
        logger.info(
            "VPN %r is in fact already disconnected (rasdial code %s, but "
            "get_vpn_connected=False) — treating disconnect as successful",
            name, proc.returncode,
        )
        return True
    if connected is None:
        logger.warning(
            "rasdial /DISCONNECT for %r returned code %s, and the actual "
            "state could not be checked — treating disconnect as failed",
            name, proc.returncode,
        )
    return False


def get_vpn_connected(name: str, all_user: Optional[bool] = None, timeout: float = 10.0) -> Optional[bool]:
    """True/False — status of a specific User or All-User VPN, None — error (incl.
    if the name is not found in any scope).

    all_user should be passed explicitly wherever it is known to the caller (GUI
    stores it in the config together with the connection name — see
    ScannerConfig.vpn_connection_all_user). all_user=None — compatible fallback
    for when the scope was not determined in advance (e.g. a config without this
    field): both scopes are queried, but if a profile with that name is found in both
    (a rare name collision), the result is treated as ambiguous and
    None is returned, not the status of the first matching scope: otherwise the caller would not see
    the ambiguity.
    """
    def _parse(raw: Any) -> Optional[bool]:
        if isinstance(raw, str):
            return raw.strip().lower() == "connected"
        return None

    return _query_vpn_field_per_scope(
        name, all_user,
        "Select-Object -ExpandProperty ConnectionStatus | ConvertTo-Json -Compress",
        _parse,
        timeout=timeout,
        field_name="ConnectionStatus",
    )


def get_vpn_split_tunneling(name: str, all_user: Optional[bool] = None,
                            timeout: float = 8.0) -> Optional[bool]:
    """Current SplitTunneling value of the profile. None — error / profile not found.

    Semantics are deliberately the same as get_vpn_connected(): with
    all_user=None both scopes are queried, and if the name is found in BOTH User AND
    All-User (name collision), the result is ambiguous -> None + warning, not
    a silent pick of the first found scope by fixed priority.
    This is especially important here: SplitTunneling is a destructive
    configuration change applied in recovery paths, and substituting a value from
    the "wrong" profile can silently leave the user without full-tunnel.
    """
    def _parse(raw: Any) -> Optional[bool]:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            low = raw.strip().lower()
            if low in ("true", "false"):
                return low == "true"
        return None

    return _query_vpn_field_per_scope(
        name, all_user,
        "Select-Object -ExpandProperty SplitTunneling | ConvertTo-Json -Compress",
        _parse,
        timeout=timeout,
        field_name="SplitTunneling",
    )


def set_vpn_split_tunneling(name: str, enabled: bool, all_user: Optional[bool] = None,
                            timeout: float = 12.0) -> Tuple[bool, str]:
    """Enables/disables SplitTunneling on the profile (IpPrioritizeRemote).

    All-User requires an elevated process. Changes the on-disk profile — the caller
    must save the previous value and restore it on disconnect.
    """
    try:
        safe_name = _ps_quote(_validate_vpn_name(name))
    except ValueError as e:
        return False, str(e)
    flag = "$true" if enabled else "$false"
    extra = " -AllUserConnection" if all_user else ""
    # -Force suppresses confirmations; errors still go to stderr.
    cmd = (
        f"Set-VpnConnection -Name {safe_name}{extra} -SplitTunneling {flag} "
        "-ErrorAction Stop; 'OK'"
    )
    try:
        proc = _run(
            [
                POWERSHELL_EXE,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _PS_UTF8_PREFIX + cmd,
            ],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "Set-VpnConnection timed out"
    text = _decode_ps_output(proc.stdout)
    err = _decode_ps_output(proc.stderr)
    if proc.returncode != 0 or "OK" not in (text or ""):
        return False, (err or text or f"exit code {proc.returncode}")[:300]
    return True, ""


def set_interface_metric(if_index: int, metric: int, timeout: float = 8.0) -> bool:
    """Sets InterfaceMetric (affects default selection when there are several 0.0.0.0/0).

    Primary path — netsh: a built-in .exe (~100–200 ms instead of ~1 s with
    PowerShell on a cold start) with a purely numeric exit code — localization
    of Windows does not affect the result because we do not parse the output at all.
    This is NOT a strict Win32 API, but a full ctypes variant via
    SetIpInterfaceEntry would require defining the
    MIB_IPINTERFACE_ROW structure (30+ fields, two version-dependent
    bitfield structures NL_INTERFACE_OFFLOAD_ROD, mandatory zeroing of
    SiteId) — the cost of a mistake here (silently wrong metric, silently wrong
    interface) exceeds the gain of another ~150 ms.

    The PowerShell path is kept as a fallback: if netsh for some reason
    does not work (a very old or peculiar Windows build), the function
    will still do its job.
    """
    try:
        idx = int(if_index)
        m = int(metric)
    except (TypeError, ValueError):
        return False
    if idx <= 0 or m < 0:
        return False

    # Primary path — netsh.
    try:
        proc = _run(
            [NETSH_EXE, "interface", "ipv4", "set", "interface",
             str(idx), f"metric={m}"],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        proc = None
    if proc is not None and proc.returncode == 0:
        return True

    # Fallback — PowerShell.
    cmd = (
        f"Set-NetIPInterface -InterfaceIndex {idx} "
        f"-InterfaceMetric {m} -ErrorAction Stop; 'OK'"
    )
    try:
        proc = _run(
            [
                POWERSHELL_EXE,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _PS_UTF8_PREFIX + cmd,
            ],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False
    text = _decode_ps_output(proc.stdout)
    return proc.returncode == 0 and "OK" in (text or "")


class InterfaceLookupState(Enum):
    """Result of looking up a network adapter by FriendlyName (GetAdaptersAddresses).

    FOUND   — adapter found; IfIndex is set, IPv4 may be None
              (adapter already exists but IPv4 is not yet assigned — typical
              state of a PPP adapter in the narrow window between creation of
              the interface object in the kernel and obtaining an IP after RasDialW);
    MISSING — adapter table was read successfully, no adapter with that
              FriendlyName is in it;
    UNKNOWN — the table could not be read (iphlpapi failure) or the name is
              invalid. "I don't know" ≠ "absent": an API failure must not look
              like confirmed absence of the adapter.
    """
    FOUND = "found"
    MISSING = "missing"
    UNKNOWN = "unknown"


def _lookup_interface_by_name(
    name: str,
) -> Tuple[InterfaceLookupState, Optional[int], Optional[str]]:
    """Low-level adapter lookup by FriendlyName.

    Returns (state, if_index, ipv4). This is the only place that distinguishes
    the three cases — "found", "definitely absent", and "could not read the
    table"; all public wrappers (get_interface_info, get_vpn_session_state,
    wait_for_interface_state) are built on top of it.
    """
    if not IS_WINDOWS:
        return InterfaceLookupState.MISSING, None, None
    try:
        name = _validate_vpn_name(name)
    except ValueError:
        logger.warning("_lookup_interface_by_name: invalid interface name %r", name)
        # An invalid name cannot match any adapter: this is MISSING, not
        # UNKNOWN — the problem is in the request, not in reading the table.
        return InterfaceLookupState.MISSING, None, None

    flags = (GAA_FLAG_INCLUDE_PREFIX |
             GAA_FLAG_SKIP_ANYCAST |
             GAA_FLAG_SKIP_MULTICAST |
             GAA_FLAG_SKIP_DNS_SERVER)

    snapshot = _adapter_addresses_snapshot(flags)
    if snapshot is None:
        return InterfaceLookupState.UNKNOWN, None, None
    if not snapshot:
        # ok=True, buf=None — empty adapter table. On a live Windows this
        # does not occur (loopback is always present), but semantically this
        # is MISSING, not UNKNOWN: we know for sure the sought adapter is
        # absent because there are no adapters at all.
        return InterfaceLookupState.MISSING, None, None

    target = name.casefold()
    for adapter in _walk_adapters(snapshot):
        friendly = adapter.FriendlyName or ""
        if friendly.casefold() != target:
            continue
        if_index = int(adapter.IfIndex) if adapter.IfIndex else None
        # First IPv4 address (analogue of the old inline loop in get_interface_info).
        ip_str: Optional[str] = None
        for ip in _iter_ipv4_from_sockaddr_list(
            adapter.FirstUnicastAddress, usable_only=False,
        ):
            ip_str = ip
            break
        return InterfaceLookupState.FOUND, if_index, ip_str

    return InterfaceLookupState.MISSING, None, None


def get_interface_info(name: str, timeout: float = 5.0) -> Tuple[Optional[int], Optional[str]]:
    """Deprecated: use _lookup_interface_by_name() / get_vpn_session_state().

    Returns (None, None) both when there is no adapter with that name, when
    the adapter table could not be read, and when the adapter exists but
    IPv4 is not yet assigned. These three cases are indistinguishable in the
    return value — use _lookup_interface_by_name() to tell them apart.

    The timeout parameter is kept for signature backward compatibility;
    _lookup_interface_by_name() does not use it (two-phase
    GetAdaptersAddresses is a synchronous iphlpapi call for which the API
    has no timeout).
    """
    _state, if_index, ipv4 = _lookup_interface_by_name(name)
    return if_index, ipv4


def _known_if_indexes(timeout: float = 5.0) -> Optional["set[int]"]:
    """Set of InterfaceIndex values of all currently existing network
    adapters (ordinary + virtual/VPN).

    Used as a cheap sanity check of the if_index sent by the client in
    add_routes, for the rare path where the helper does not know the VPN
    connection name (routes are added from parent_pid without register_client
    — see the _routes_authorized_unlocked docstring) and therefore cannot
    bind if_index to a specific adapter by name the way remove_default_route
    does. This does not fully replace binding to a specific VPN adapter, but
    prevents adding a route via an if_index that does not exist on the
    machine at all.
    
    None — the table could not be read (GetAdaptersAddresses error): the
    caller must treat this as "I don't know" and NOT reject requests on that
    basis. An empty set is a valid "no adapters" answer (should not happen
    on a live Windows, but differs from an API error).
    """
    if not IS_WINDOWS:
        return None
    try:
        size = wintypes.ULONG(0)
        flags = (GAA_FLAG_INCLUDE_PREFIX |
                 GAA_FLAG_SKIP_ANYCAST |
                 GAA_FLAG_SKIP_MULTICAST |
                 GAA_FLAG_SKIP_DNS_SERVER)
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, None, ctypes.byref(size))
        if rc != 111 and rc != 0:
            logger.debug("_known_if_indexes: GetAdaptersAddresses (size) failed: %s", rc)
            return None
        if size.value == 0:
            return set()
        buf = ctypes.create_string_buffer(size.value)
        p_addrs = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, p_addrs, ctypes.byref(size))
        if rc != 0:
            logger.debug("_known_if_indexes: GetAdaptersAddresses failed: %s", rc)
            return None
        result: "set[int]" = set()
        current = p_addrs
        while current:
            adapter = current.contents
            if adapter.IfIndex:
                result.add(int(adapter.IfIndex))
            current = adapter.Next
        return result
    except Exception:
        logger.exception("_known_if_indexes: failed to enumerate adapters")
        return None


def _explain_lookup_failure(
    name: str,
    state: InterfaceLookupState,
    if_index: Optional[int],
    ipv4: Optional[str],
    *,
    expect_ipv4: bool = False,
) -> str:
    """Human-readable explanation of why _lookup_interface_by_name() did not
    produce the expected result. Takes into account state and which field
    was expected (if_index — always, ipv4 — optionally).

    Previously this role was played by _describe_iface_lookup_failure()
    returning (truly_missing, message) — but truly_missing was never used by
    callers, and the distinction was built via a second walk of the adapter
    table (_known_if_indexes()). Now state is known from the primary call and
    a second walk is not needed.
    """
    if state is InterfaceLookupState.MISSING:
        return f"VPN interface {name!r} is not present in the current adapter table"
    if state is InterfaceLookupState.UNKNOWN:
        return (
            f"GetAdaptersAddresses failed — could not determine whether the "
            f"VPN interface {name!r} exists (state unknown)"
        )
    # state is FOUND
    if if_index is None:
        return f"VPN interface {name!r} was found but has no IfIndex"
    if expect_ipv4 and not ipv4:
        return (
            f"VPN interface {name!r} exists (ifIndex={if_index}), but its "
            f"IPv4 address is not assigned"
        )
    return f"Unexpected lookup state for VPN interface {name!r}: {state}"


def is_adapter_api_available() -> bool:
    """True — GetAdaptersAddresses responds; False — iphlpapi API is
    unavailable (adapter table read error).

    The same
    tri-state principle as get_interface_status()/get_interface_counters():
    "I don't know" must not turn into either "up" or "down".
    """
    return _known_if_indexes() is not None


def get_interface_status(if_index: int) -> Optional[str]:
    """Status of the adapter with the given IfIndex right now, via
    GetAdaptersAddresses (the same call as get_interface_info() /
    _known_if_indexes() — no new Windows API is brought in just for this).

    Returns:
      "up"      — adapter exists, OperStatus == Up;
      "down"    — adapter exists, but OperStatus != Up;
      "missing" — no adapter with that IfIndex is in the list at all (typical
                  picture mid-RAS-handshake on reconnect: the kernel has
                  already torn down the old interface object, the new one is
                  not ready yet);
      None      — the adapter table could not be read (iphlpapi error).
                  Tri-state "I don't know" — a single GetAdaptersAddresses
                  failure must not be treated as "up" or "down"/"missing"
                  (see _VpnSessionWatch.check).
    """
    if not IS_WINDOWS:
        return None
    try:
        idx = int(if_index)
    except (TypeError, ValueError):
        return None
    try:
        size = wintypes.ULONG(0)
        flags = (GAA_FLAG_INCLUDE_PREFIX |
                 GAA_FLAG_SKIP_ANYCAST |
                 GAA_FLAG_SKIP_MULTICAST |
                 GAA_FLAG_SKIP_DNS_SERVER)
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, None, ctypes.byref(size))
        if rc != 111 and rc != 0:  # ERROR_BUFFER_OVERFLOW / ERROR_SUCCESS
            return None
        if size.value == 0:
            return "missing"
        buf = ctypes.create_string_buffer(size.value)
        p_addrs = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, p_addrs, ctypes.byref(size))
        if rc != 0:
            return None
        current = p_addrs
        while current:
            adapter = current.contents
            if adapter.IfIndex and int(adapter.IfIndex) == idx:
                return "up" if adapter.OperStatus == IF_OPER_STATUS_UP else "down"
            current = adapter.Next
        return "missing"
    except Exception:
        logger.debug("get_interface_status(%s) failed", if_index, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# GetIfEntry2 (MIB_IF_ROW2) — 64-bit interface traffic counters.
#
# Why: InOctets/OutOctets are reset to 0 when RAS recreates the tunnel object
# in the kernel — even if ifIndex is reused for the same profile (Windows
# often reissues the same index). This is direct observation of "we have a new
# interface in front of us", unlike ifIndex/local_ip: on reconnect of the same
# profile they usually do not change, so sessions cannot be told apart by them.
# Verified on a live connection: on manual VPN disconnect/connect ifIndex stays
# the same, while InOctets/OutOctets zero out and grow again.
#
# The MIB_IF_ROW2 structure itself (its _fields_ — see the _MIB_IF_ROW2 class in
# the ctypes bindings block above, `if IS_WINDOWS:`) is a full copy of netioapi.h.
# ---------------------------------------------------------------------------


class InterfaceCounters(NamedTuple):
    oper_up: bool
    in_octets: int
    out_octets: int


# ---------------------------------------------------------------------------
# Shared GetAdaptersAddresses walks
#
# The four public functions below (get_interface_info, get_interface_status,
# get_interface_dns_servers, get_interface_gateways) and _physical_adapter_ifindexes
# all do the same thing: obtain a GetAdaptersAddresses buffer, walk the adapter
# list, find the needed IfIndex and parse one of its fields. Previously each
# function copied this scaffolding wholesale — with the risk that the filter for
# "junk" IPv4 addresses (0.x / 169.254.x / 255.255.255.255) would diverge between
# copies (which is what happened: _physical_adapter_ifindexes has no filter at
# all, because it returns IfIndex, not IP).
#
# Three levels are factored out here:
#   _adapter_addresses_snapshot() — obtain a buffer with the needed GAA flags;
#   _walk_adapters(snapshot)      — iterate adapters;
#   _iter_ipv4_from_sockaddr_list() — iterate a linked list of IPv4 addresses.
# ---------------------------------------------------------------------------


class _AdaptersSnapshot:
    """Result of _adapter_addresses_snapshot().

    Holds the ctypes buffer ITSELF (create_string_buffer), not a bytes copy of
    it: GetAdaptersAddresses plants pointers inside the buffer (Next,
    FirstUnicastAddress, FirstGatewayAddress, lpSockaddr) that point into
    THAT SAME buffer. A bytes copy does not "re-plant" those pointers — they
    remain valid only while the allocator happens to give the new buffer the
    same address the old one had. Any intermediate allocation — and the
    pointers become dangling; walking Next/lpSockaddr crashes with an
    access violation (Windows fatal exception).

    Contract (three states, distinguished by fields):
      ok=False, buf=None          — iphlpapi error;
      ok=True,  buf=None          — adapter table is empty (size.value == 0);
      ok=True,  buf!=None         — success, buf is a ctypes.create_string_buffer.
    """

    __slots__ = ("ok", "buf")

    def __init__(self, ok: bool, buf: Any) -> None:
        self.ok = ok
        self.buf = buf

    def __bool__(self) -> bool:
        """True if there is data to walk (ok=True and buf!=None).

        Needed so callers can write `if snapshot:` without an explicit field
        check — semantics match the former `if snapshot:` for bytes
        (`b""` is false, non-empty bytes is true).
        """
        return self.ok and self.buf is not None


def _adapter_addresses_snapshot(flags: int) -> Optional[_AdaptersSnapshot]:
    """Two-phase GetAdaptersAddresses call.

    Returns an _AdaptersSnapshot (see its docstring) or None when the call
    cannot be performed (not Windows, API error).

    The returned buffer is a ctypes.create_string_buffer (NOT a bytes copy):
    GetAdaptersAddresses plants pointers inside the buffer (Next,
    FirstUnicastAddress, FirstGatewayAddress, lpSockaddr) that point into
    THAT SAME buffer. If a bytes copy (buf.raw) is returned, those pointers
    remain valid only while the allocator happens to reuse the same address
    for the new copy. Any intermediate allocation — and the pointers become
    dangling; walking Next/lpSockaddr in _walk_adapters/
    _iter_ipv4_from_sockaddr_list crashes with an access violation (this is
    exactly what appeared in scanner_fatal.log on calls from
    _network_health_loop → _poll_vpn_health_tick → get_vpn_session_state →
    _lookup_interface_by_name).
    """
    if not IS_WINDOWS:
        return None
    try:
        size = wintypes.ULONG(0)
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, None, ctypes.byref(size))
        # ERROR_BUFFER_OVERFLOW = 111, ERROR_SUCCESS = 0.
        if rc not in (0, 111):
            logger.debug(
                "_adapter_addresses_snapshot: GetAdaptersAddresses (size) failed: %s",
                rc,
            )
            return None
        if size.value == 0:
            # Successful "no adapters" response. On a live Windows this is
            # impossible (the loopback interface always exists), but the
            # contract must distinguish "empty table" from "API error".
            return _AdaptersSnapshot(ok=True, buf=None)
        buf = ctypes.create_string_buffer(size.value)
        p_addrs = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, p_addrs, ctypes.byref(size))
        if rc != 0:
            logger.debug(
                "_adapter_addresses_snapshot: GetAdaptersAddresses failed: %s", rc,
            )
            return None
        return _AdaptersSnapshot(ok=True, buf=buf)
    except Exception:
        logger.debug("_adapter_addresses_snapshot failed", exc_info=True)
        return None


def _walk_adapters(snapshot: _AdaptersSnapshot):
    """Generator of adapters from an _AdaptersSnapshot.

    No buffer copying: we walk exactly the same ctypes buffer that
    GetAdaptersAddresses returned — otherwise the internal pointers
    (Next, FirstUnicastAddress, ...) would be dangling (see the detailed
    comment in _adapter_addresses_snapshot).

    The buffer must live for the duration of the iteration: the generator
    holds it in its frame, and the returned structures in _b_base_; so the
    caller can safely read adapters directly in the loop body (including
    dereferencing their pointer fields, as _iter_ipv4_from_sockaddr_list
    does).
    """
    if not snapshot or snapshot.buf is None:
        return
    current = ctypes.cast(
        snapshot.buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES)
    )
    while current:
        adapter = current.contents
        yield adapter
        current = adapter.Next


def _iter_ipv4_from_sockaddr_list(head, *, usable_only: bool) -> Iterable[str]:
    """Walks a linked list of SOCKET_ADDRESS (FirstDnsServerAddress /
    FirstGatewayAddress / FirstUnicastAddress, etc.) and yields IPv4
    addresses as strings.

    head is passed as a ctypes pointer of the appropriate type; the
    Length/Next/Address fields of all these structures coincide in offsets,
    so the function works with any of them without a type cast.

    usable_only=True — additionally filter out "junk" addresses via
    _is_usable_unicast_ipv4(). Needed where the list is used for real
    routing/ARP (DNS/gateway): 0.0.0.0 (no gateway), 169.254.x.x
    (link-local, APIPA), 255.255.255.255 (broadcast) must not appear there.
    usable_only=False — yield everything that parses as IPv4 (needed e.g.
    if we wanted a full list for diagnostics).

    Duplicates are not deduplicated: that is the caller's concern (in
    get_interface_* they are deduplicated via a set because order does not
    matter, while in get_interface_info order matters — the first IPv4 is
    the one sought).
    """
    while head:
        entry = head.contents
        if entry.Address.iSockaddrLength >= 16:
            sa_buf = ctypes.string_at(
                entry.Address.lpSockaddr, entry.Address.iSockaddrLength,
            )
            family = int.from_bytes(sa_buf[0:2], byteorder="little")
            if family == AF_INET:
                ip = socket.inet_ntoa(sa_buf[4:8])
                if not usable_only or _is_usable_unicast_ipv4(ip):
                    yield ip
        head = entry.Next


def _is_usable_unicast_ipv4(ip: str) -> bool:
    """True if the address is suitable for real use (DNS server, gateway):
    not 0.x.x.x, not 169.254.x.x (link-local), not 255.255.255.255.

    Previously this check was duplicated in get_interface_dns_servers and
    get_interface_gateways; now both use it via
    _iter_ipv4_from_sockaddr_list(usable_only=True).
    """
    return (
        bool(ip)
        and not ip.startswith("0.")
        and not ip.startswith("169.254.")
        and ip != "255.255.255.255"
    )


def get_interface_counters(if_index: int) -> Optional[InterfaceCounters]:
    """OperStatus + 64-bit InOctets/OutOctets for the given IfIndex via
    GetIfEntry2 (MIB_IF_ROW2). None — adapter not found, GetIfEntry2
    unavailable, or the call failed — tri-state "I don't know" (see
    _VpnSessionWatch.check): a single iphlpapi failure must not be treated
    as interface recreation.
    """
    if not IS_WINDOWS or _GetIfEntry2 is None:
        return None
    try:
        idx = int(if_index)
    except (TypeError, ValueError):
        return None
    if idx <= 0:
        return None
    try:
        row = _MIB_IF_ROW2()
        row.InterfaceIndex = idx
        rc = _GetIfEntry2(ctypes.byref(row))
        if rc != 0:  # NO_ERROR
            return None
        return InterfaceCounters(
            oper_up=(int(row.OperStatus) == IF_OPER_STATUS_UP),
            in_octets=int(row.InOctets),
            out_octets=int(row.OutOctets),
        )
    except Exception:
        logger.debug("get_interface_counters(%s) failed", if_index, exc_info=True)
        return None


def get_interface_dns_servers(if_index: int) -> List[str]:
    """IPv4 DNS servers assigned to the interface (usually corporate after
    full-tunnel).

    Needed so that after force-split-tunnel (remove_default_route) DNS queries
    to these servers do not lose their route: Windows often sets the VPN
    adapter DNS as the only/preferred one, and without a /32 route to the DNS
    server corporate name resolution breaks.

    Implemented via GetAdaptersAddresses (Win32 IP Helper) — the same function
    used by get_interface_info. The call takes ~1 ms; PowerShell
    (Get-DnsClientServerAddress) would cost 0.7–1 s on every connect, and this
    is the hot path of _vpn_precheck_worker.
    """
    if not IS_WINDOWS:
        return []
    try:
        idx = int(if_index)
    except (TypeError, ValueError):
        return []
    if idx <= 0:
        return []

    # We need DNS addresses, the other categories — not; INCLUDE_PREFIX is
    # not required, but GAA_FLAG_SKIP_ANYCAST/MULTICAST shorten the walk.
    flags = (GAA_FLAG_INCLUDE_PREFIX |
             GAA_FLAG_SKIP_ANYCAST |
             GAA_FLAG_SKIP_MULTICAST)

    snapshot = _adapter_addresses_snapshot(flags)
    if not snapshot:
        return []

    out: List[str] = []
    seen = set()
    for adapter in _walk_adapters(snapshot):
        if int(adapter.IfIndex) != idx:
            continue
        for ip in _iter_ipv4_from_sockaddr_list(
            adapter.FirstDnsServerAddress, usable_only=True,
        ):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out
    return out


def get_interface_gateways(if_index: int) -> List[str]:
    """IPv4 gateway addresses of the interface — analogue of
    get_interface_dns_servers(), but reads the FirstGatewayAddress list
    (GAA_FLAG_INCLUDE_GATEWAYS).

    Used by get_physical_gateway_ip() for ARP hygiene: the real L2 neighbour is
    the physical adapter gateway, and only for it does it make sense to flush
    the ARP entry. Proxy hosts behind the gateway do not appear in the client's
    ARP table, so arp -d <proxy_ip> would be a no-op.

    Implemented via GetAdaptersAddresses (Win32 IP Helper): ~1 ms versus
    PowerShell/Get-NetRoute.
    """
    if not IS_WINDOWS:
        return []
    try:
        idx = int(if_index)
    except (TypeError, ValueError):
        return []
    if idx <= 0:
        return []

    flags = (GAA_FLAG_INCLUDE_PREFIX |
             GAA_FLAG_INCLUDE_GATEWAYS |
             GAA_FLAG_SKIP_ANYCAST |
             GAA_FLAG_SKIP_MULTICAST |
             GAA_FLAG_SKIP_DNS_SERVER)

    snapshot = _adapter_addresses_snapshot(flags)
    if not snapshot:
        return []

    out: List[str] = []
    seen = set()
    for adapter in _walk_adapters(snapshot):
        if int(adapter.IfIndex) != idx:
            continue
        for ip in _iter_ipv4_from_sockaddr_list(
            adapter.FirstGatewayAddress, usable_only=True,
        ):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out
    return out


def wait_for_interface_state(
    name: str, attempts: int = IF_INDEX_POLL_ATTEMPTS,
    interval: float = IF_INDEX_POLL_INTERVAL,
) -> Tuple[InterfaceLookupState, Optional[int], Optional[str]]:
    """
    Right after a rasdial connect the adapter may not yet have obtained an
    IP / appeared in GetAdaptersAddresses — we briefly poll the index AND
    the adapter's local IP together (both are needed for a correct route add).

    Returns the last result of _lookup_interface_by_name(): a successful
    (FOUND, if_index, ipv4) or the final unsuccessful one (MISSING/UNKNOWN/
    FOUND-without-IPv4) after attempts are exhausted.
    """
    state = InterfaceLookupState.MISSING
    if_index: Optional[int] = None
    local_ip: Optional[str] = None
    for _ in range(attempts):
        state, if_index, local_ip = _lookup_interface_by_name(name)
        if state is InterfaceLookupState.FOUND and if_index is not None and local_ip is not None:
            return state, if_index, local_ip
        time.sleep(interval)
    return state, if_index, local_ip


# ======================================================================
# VPN session identity and route table snapshot
#
# ifIndex is NOT a VPN session identifier: Windows RAS adapters reuse the
# same ifIndex on reconnect of the same profile (observed: ifIndex=37 before
# and after manual Disconnect→Connect, local IP the same too — the VPN server
# issues an address from the pool by account). "ifIndex/local_ip did not
# change" does NOT mean "same session", and these two fields change so rarely
# that comparing them almost never fires either way. A reliable connection
# instance identifier (RASCONNW.guidCorrelationId) is deliberately absent
# here: its ctypes layout
# is too fragile.
#
# Therefore the session is told apart by the consequences of interface
# recreation — see _VpnSessionWatch in IPTV_scanner.pyw:
#   * the adapter with that ifIndex disappeared or its OperStatus is not Up
#     (get_interface_status());
#   * 64-bit interface traffic counters rolled back
#     (get_interface_counters()) — when the interface object is recreated in
#     the kernel they are guaranteed to zero out, even if ifIndex is the same;
#   * ALL of our /32s disappeared from the routing table while the adapter is
#     up — Windows removes routes together with the interface
#     (routes_snapshot()/count_alive_routes()).
# ======================================================================


@dataclass(frozen=True)
class VpnSession:
    """Snapshot of the observed state of the VPN adapter at a specific moment.

    if_index/local_ip — what is needed for route.exe; local_ip may be
    None in the narrow window when the adapter already exists but IPv4 is
    not yet assigned (see InterfaceLookupState.FOUND). For session-watch
    tasks (_VpnSessionWatch.check) if_index is what matters; local_ip is
    used only in diagnostic messages.
    """

    connection_name: str
    if_index: int
    local_ip: Optional[str]


class VpnSessionState(Enum):
    """Tri-state result of looking up a VPN session by profile name.

    UP      — adapter exists; session is filled (session.local_ip may be
              None — IPv4 not yet assigned, see InterfaceLookupState.FOUND);
    DOWN    — adapter table was read, adapter is absent;
    UNKNOWN — the table could not be read (iphlpapi failure). "I don't know" ≠
              "session disappeared": a single GetAdaptersAddresses failure
              must not trigger recovery.
    """
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


def get_vpn_session_state(
    connection_name: str,
) -> Tuple[VpnSessionState, Optional[VpnSession]]:
    """
    Returns:
      (VpnSessionState.UP,      session) — adapter is present; session.if_index
                                            is set, session.local_ip may be None;
      (VpnSessionState.DOWN,    None)    — adapter is definitely absent;
      (VpnSessionState.UNKNOWN, None)    — the adapter table could not be
                                            read.
    """
    if not connection_name:
        return VpnSessionState.DOWN, None
    lookup_state, if_index, local_ip = _lookup_interface_by_name(connection_name)
    if lookup_state is InterfaceLookupState.UNKNOWN:
        return VpnSessionState.UNKNOWN, None
    if lookup_state is InterfaceLookupState.MISSING or if_index is None:
        return VpnSessionState.DOWN, None
    return VpnSessionState.UP, VpnSession(
        connection_name=connection_name,
        if_index=int(if_index),
        local_ip=local_ip,
    )


def routes_snapshot() -> Optional["set[Tuple[int, int]]"]:
    """Snapshot of all /32 routes in the IPv4 table: {(dest_int, if_index), ...}.

    Returns None if the table could not be read. None is NOT "no routes":
    an empty set and a read error must be handled differently, otherwise a
    single iphlpapi failure would look like all our routes disappearing and
    would trigger false recovery (the same discipline as get_vpn_connected(),
    which returns True/False/None).

    The destination address is put into the set in both byte orders — for
    the same reason as in _unicast_route_exists(): interpretation of
    dwForwardDest depends on which path the entry took into the table.

    One call is ~1 ms (GetIpForwardTable), so the health monitor takes
    ONE snapshot per tick and checks all of its routes against it at once —
    instead of calling _unicast_route_exists() per IP, where the whole table
    would be re-read each time.
    """
    rows = _enumerate_ipv4_forward_rows()
    if rows is None:
        return None
    # An empty table ([]) is also "I don't know": on a live Windows the
    # routing table is never empty (loopback entries at least), and if it
    # is empty — that is a read anomaly, not a valid "none of our routes
    # exist" answer. Return None so that count_alive_routes() does not
    # interpret this as "all our routes are gone" and trigger false
    # recovery. This matches the former behaviour of the original
    # routes_snapshot() when size.value == 0.
    if not rows:
        return None
    out: "set[Tuple[int, int]]" = set()
    for row in rows:
        if row.dwForwardMask != 0xFFFFFFFF:
            continue
        out.add((int(row.dwForwardDest), int(row.dwForwardIfIndex)))
    return out


def _unicast_route_exists(ip: str, if_index: int) -> bool:
    """True if the routing table has a /32 host route to ip via if_index.

    Implemented via routes_snapshot() (GetIpForwardTable, ~1 ms). One
    table snapshot yields both byte orders of dwForwardDest at once — see
    the docstring of routes_snapshot().
    """
    if not _is_valid_route_ip(ip):
        logger.error("_unicast_route_exists: invalid ip %r — rejected", ip)
        return False
    if not IS_WINDOWS:
        return False
    try:
        idx = int(if_index)
    except (TypeError, ValueError):
        return False
    if idx <= 0:
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False

    snapshot = routes_snapshot()
    if snapshot is None:
        # The table could not be read — treat as "I don't know". For the
        # caller this is already a separate path (see add_route: on route.exe
        # failure the "already exists" check must not false-positive).
        return False
    dst_be = int(addr)
    dst_le = int.from_bytes(addr.packed, "little")
    return (dst_be, idx) in snapshot or (dst_le, idx) in snapshot


def count_alive_routes(routes: Iterable[Tuple[str, int]],
                       snapshot: Optional["set[Tuple[int, int]]"],
                       ) -> Tuple[int, int]:
    """(alive, total) for the list of our routes [(ip, if_index), ...].

    snapshot=None (table not read) → (0, 0): "nothing is known",
    the caller must treat such a tick as skipped, not failed.
    Invalid IPs in the list do not count toward total.
    """
    if snapshot is None:
        return 0, 0
    alive = 0
    total = 0
    for ip, if_index in routes:
        try:
            addr = ipaddress.IPv4Address(str(ip))
            idx = int(if_index)
        except (ipaddress.AddressValueError, ValueError, TypeError):
            continue
        total += 1
        dst_be = int(addr)
        dst_le = int.from_bytes(addr.packed, "little")
        if (dst_be, idx) in snapshot or (dst_le, idx) in snapshot:
            alive += 1
    return alive, total


def add_route(ip: str, if_index: int, gateway: str, timeout: float = 8.0) -> bool:
    # The gateway is the VPN adapter's own IP address (assigned by Windows
    # to this end of the PPP link), not 0.0.0.0 — in practice ROUTE_EXE can
    # "successfully" accept 0.0.0.0 as a gateway for a PPP adapter (return
    # code 0), but the resulting entry sometimes turns out non-functional and
    # traffic does not actually go through the tunnel, even though the command
    # formally reports no error.
    route_log = logging.getLogger("vpn_helper")  # once per call, not 4 separate getLogger()
    # route.exe is called via an argv list (not shell), so it is not injectable
    # by itself, but ip/gateway also reach _unicast_route_exists() below, where
    # they are substituted into a PowerShell command. Validate immediately here
    # — the same way as in add_routes() — so we do not rely on every current
    # and future add_route() call validating everything itself.
    if not _is_valid_route_ip(ip) or not _is_valid_route_ip(gateway):
        route_log.error("add_route: invalid ip=%r/gateway=%r — rejected", ip, gateway)
        return False
    try:
        proc = _run(
            [ROUTE_EXE, "add", ip, "mask", "255.255.255.255", gateway,
             "metric", "5", "if", str(if_index)],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False
    if proc.returncode == 0:
        ok = True
    else:
        # "Already exists" is determined only from the actual routing table, not
        # from route.exe message text: that is localized, and parsing would only
        # work on locales for which markers were written by hand. _unicast_route_exists
        # is cheap (~1 ms) and locale-independent.
        if _unicast_route_exists(ip, if_index):
            route_log.info(
                "Route %s via ifIndex=%s already exists (checked against the "
                "routing table) — treating as success",
                ip, if_index,
            )
            ok = True
        else:
            ok = False
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            route_log.error(
                "route add %s ... returned code %s: stdout=%r stderr=%r",
                ip, proc.returncode, stdout.strip(), stderr.strip(),
            )
    if ok and route_log.isEnabledFor(logging.DEBUG):
        try:
            check = _run([ROUTE_EXE, "print", "-4", ip], timeout=5.0)
            route_log.debug(
                "route print %s after add:\n%s",
                ip, check.stdout.decode("utf-8", errors="replace").strip()
            )
        except Exception:
            route_log.debug("Diagnostic route print %s failed", ip, exc_info=True)
    return ok


def delete_route(ip: str, if_index: int, gateway: str, timeout: float = 8.0) -> bool:
    # See the comment in add_route(): the same protection is needed here, since
    # delete_route can also end up calling _unicast_route_exists().
    if not _is_valid_route_ip(ip) or not _is_valid_route_ip(gateway):
        logging.getLogger("vpn_helper").error(
            "delete_route: invalid ip=%r/gateway=%r — rejected", ip, gateway
        )
        return False
    try:
        proc = _run(
            [ROUTE_EXE, "delete", ip, "mask", "255.255.255.255", gateway,
             "if", str(if_index)],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False
    if proc.returncode == 0:
        return True
    # The route may already have disappeared together with the VPN interface — this is a normal
    # idempotent cleanup outcome. We check physical presence only at debug level.
    return not _unicast_route_exists(ip, if_index)


def _active_ipv6_default_ifindexes() -> Optional[List[int]]:
    """ifIndexes with an active ::/0.

    Uses Get-NetRoute — fully independent of the Windows UI language.
    Goes through a cache: in a single VpnHelperState.remove_default_route call
    this function is invoked twice, and without a cache that would be 2 separate
    powershell.exe launches (~1 s each) even though the answer does not change
    between them.
    """
    return _cached_default_route_ifindexes(ipv6=True)

if IS_WINDOWS:
    # --- Fast-path for IPv4 default routes via Win32 API ---
    # GetIpForwardTable (iphlpapi.dll) returns the entire IPv4 routing table
    # in ~1 ms, unlike Get-NetRoute via subprocess (powershell.exe launch
    # ~1 s). VpnHelperState.remove_default_route in a single call requests
    # the default-route list 9 times in a row — with PowerShell that is
    # ~9 seconds on queries alone, which shows in the log as a huge pause between
    # "Adding route to DNS..." and "connect_and_route: success". Via
    # GetIpForwardTable the same 9 queries take fractions of a millisecond.
    class _MIB_IPFORWARDROW(ctypes.Structure):
        _fields_ = [
            ("dwForwardDest", wintypes.DWORD),
            ("dwForwardMask", wintypes.DWORD),
            ("dwForwardPolicy", wintypes.DWORD),
            ("dwForwardNextHop", wintypes.DWORD),
            ("dwForwardIfIndex", wintypes.DWORD),
            ("dwForwardType", wintypes.DWORD),
            ("dwForwardProto", wintypes.DWORD),
            ("dwForwardAge", wintypes.DWORD),
            ("dwForwardNextHopAS", wintypes.DWORD),
            ("dwForwardMetric1", wintypes.DWORD),
            ("dwForwardMetric2", wintypes.DWORD),
            ("dwForwardMetric3", wintypes.DWORD),
            ("dwForwardMetric4", wintypes.DWORD),
            ("dwForwardMetric5", wintypes.DWORD),
        ]


# ---------------------------------------------------------------------------
# Shared walk of the IPv4 route table (GetIpForwardTable / MIB_IPFORWARDROW).
#
# routes_snapshot() and _ipv4_default_routes_fast() do the same thing:
# a two-phase GetIpForwardTable call (first learn the size, then read),
# reading the row count from the first 4 bytes of the buffer, parsing the
# _MIB_IPFORWARDROW array. Previously this scaffolding was copied into both
# functions — with the risk of diverging when editing one of them (new rc
# handling, field offsets, fallback on size.value==0). Now it lives in one place.
#
# The result is materialized (List, not Iterator), because callers must be
# able to tell "table is empty" ([]) from "could not read" (None) — otherwise
# routes_snapshot() could not return its semantic None on an empty table
# without introducing a separate sentinel for that.
#
# Row copies are made via from_buffer_copy(), not from_buffer(): the latter
# creates a view over the internal ctypes buffer, and if we returned a list
# of such views they would "hang" on an already-freed buffer (ctypes does not
# reliably keep the source alive via ._b_base_ in this scenario). Materialization
# + copy() permanently detaches the result from the buffer.
# ---------------------------------------------------------------------------
def _enumerate_ipv4_forward_rows() -> Optional[List["_MIB_IPFORWARDROW"]]:
    if not IS_WINDOWS:
        return None
    try:
        _iphlpapi.GetIpForwardTable.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
        ]
        _iphlpapi.GetIpForwardTable.restype = wintypes.DWORD

        size = wintypes.ULONG(0)
        rc = _iphlpapi.GetIpForwardTable(None, ctypes.byref(size), False)
        if rc not in (0, 122):  # NO_ERROR / ERROR_INSUFFICIENT_BUFFER
            logger.debug(
                "_enumerate_ipv4_forward_rows: GetIpForwardTable (size) failed: %s",
                rc,
            )
            return None
        if size.value == 0:
            return []

        buf = ctypes.create_string_buffer(size.value)
        rc = _iphlpapi.GetIpForwardTable(buf, ctypes.byref(size), False)
        if rc != 0:
            logger.debug(
                "_enumerate_ipv4_forward_rows: GetIpForwardTable failed: %s", rc,
            )
            return None

        num = ctypes.c_uint32.from_buffer(buf).value
        if num == 0:
            return []
        row_size = ctypes.sizeof(_MIB_IPFORWARDROW)
        rows: List[_MIB_IPFORWARDROW] = []
        for i in range(num):
            # from_buffer_copy() — not from_buffer(): see the helper comment
            # above about buffer lifetime. Offset 4 — past dwNumEntries
            # (DWORD), after which the row array follows.
            rows.append(
                _MIB_IPFORWARDROW.from_buffer_copy(buf, 4 + i * row_size)
            )
        return rows
    except Exception:
        logger.debug(
            "_enumerate_ipv4_forward_rows (GetIpForwardTable) failed", exc_info=True,
        )
        return None


def _ipv4_default_routes_fast() -> Optional[List[Dict[str, Any]]]:
    """IPv4 default routes (0.0.0.0/0) via GetIpForwardTable.

    Returns a list [{"if_index": int, "gateway": str, "metric": int}, ...].
    Empty list — no routes. None — Win32 API failed, the caller must fall
    back to PowerShell.

    Replaces the PowerShell variant of get_default_routes(ipv6=False). This
    function is on the hot path of connect_and_route() — the pre_defaults_v4
    snapshot before rasdial — and with PowerShell wasted ~1 s on every VPN
    connect. Via GetIpForwardTable the same thing is read in ~1 ms.

    Differs from _ipv4_default_route_ifindexes_fast(): that one returns only
    ifIndexes (used in remove_default_route and get_physical_gateway_ip to
    check "is there a default"), this one returns full rows with gateway and
    metric (used by connect_and_route for the pre_defaults_v4 snapshot so the
    physical default can later be restored after force-split-tunnel).

    Byte order of dwForwardDest/dwForwardMask: for an "equals zero" check
    it does not matter (0 in any order is 0), so the default row is found
    equally reliably. For dwForwardNextHop the bytes in memory are in
    address-octet order (verified empirically), so little-endian correctly
    decodes it to an IPv4 string.
    """
    rows = _enumerate_ipv4_forward_rows()
    if rows is None:
        return None
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for row in rows:
        # Default route = dest 0.0.0.0/0.
        if row.dwForwardDest != 0 or row.dwForwardMask != 0:
            continue
        if_index = int(row.dwForwardIfIndex)
        try:
            next_hop_raw = int(row.dwForwardNextHop)
            gateway = str(ipaddress.IPv4Address(
                next_hop_raw.to_bytes(4, "little")
            ))
        except Exception:
            gateway = "0.0.0.0"
        try:
            metric = int(row.dwForwardMetric1)
        except (TypeError, ValueError):
            metric = 0
        if metric < 0:
            metric = 0
        key = (if_index, gateway, metric)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "if_index": if_index,
            "gateway": gateway,
            "metric": metric,
        })
    return out


def _ipv4_default_route_ifindexes_fast() -> Optional[List[int]]:
    """IPv4 default routes (0.0.0.0/0) via GetIpForwardTable.

    Thin wrapper over _ipv4_default_routes_fast(): that returns full rows
    (if_index, gateway, metric); here only ifIndexes are needed —
    used in remove_default_route() and _physical_gateway_ip().

    Contract: list of ifIndexes, [] if there are no default routes, None —
    Win32 API failed (the caller falls back to PowerShell).
    """
    routes = _ipv4_default_routes_fast()
    if routes is None:
        return None
    return [r["if_index"] for r in routes]


def _default_route_ifindexes(
    ipv6: bool = False,
    timeout: float = 5.0,
) -> Optional[List[int]]:
    """Default routes via Get-NetRoute (PowerShell).

    Returns:
      []       — query succeeded, no default routes;
      [int,...] — query succeeded, routes found;
      None     — state could not be determined.
    """
    if not ipv6:
        fast = _ipv4_default_route_ifindexes_fast()
        if fast is not None:
            return fast

    prefix = "::/0" if ipv6 else "0.0.0.0/0"
    family = "IPv6" if ipv6 else "IPv4"
    cmd = (
        f"Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty InterfaceIndex | ConvertTo-Json -Compress"
    )
    try:
        result = run_powershell_json(cmd, timeout=timeout)
    except Exception:
        logger.debug(
            "_default_route_ifindexes(%s): PowerShell query failed",
            "IPv6" if ipv6 else "IPv4",
            exc_info=True,
        )
        return None
    if isinstance(result, (int, float)):
        return [int(result)]
    if isinstance(result, list):
        out: List[int] = []
        for x in result:
            try:
                out.append(int(x))
            except (TypeError, ValueError):
                continue
        return out
    logger.debug(
        "_default_route_ifindexes(%s): unexpected PowerShell result type: %s",
        "IPv6" if ipv6 else "IPv4",
        type(result).__name__,
    )
    return None


# Cache of the last Get-NetRoute response (v4/v6). VpnHelperState.remove_default_route
# in a single call queries default routes 5+ times, and on PowerShell that is 5+
# seconds wasted (pause between "Adding route to DNS..." and "connect_and_route:
# success" in the log). IPv4 is covered by the fast-path via GetIpForwardTable
# (see _ipv4_default_route_ifindexes_fast); IPv6 stays on PowerShell — this
# cache is specifically about that.
#
# TTL is deliberately large (15 s): a single PowerShell call itself takes ~1 s,
# and a short TTL would not even cover two sequential lookups within one
# remove_default_route. 15 s covers the whole call with margin. Invalidation is
# on actual mutation (see _delete_default_route/_add_default_route), so a change
# to the IPv4 table does not clear the IPv6 cache, and vice versa.
_default_route_cache: Dict[bool, Tuple[float, List[int]]] = {}
_DEFAULT_ROUTE_CACHE_TTL = 15.0


def _cached_default_route_ifindexes(
    ipv6: bool = False,
) -> Optional[List[int]]:
    now = time.monotonic()
    cached = _default_route_cache.get(ipv6)

    if cached is not None and now - cached[0] < _DEFAULT_ROUTE_CACHE_TTL:
        return list(cached[1])

    val = _default_route_ifindexes(ipv6=ipv6)

    # None means "state could not be determined".
    # Such a result must not be turned into [] and must not be cached:
    # otherwise a transient PowerShell failure would poison the cache for 15 seconds.
    if val is None:
        return None

    _default_route_cache[ipv6] = (now, list(val))
    return val


def _invalidate_default_route_cache(ipv6: Optional[bool] = None) -> None:
    """Clears the cache. ipv6=None — all; ipv6=True/False — only that family,
    so that a mutation of the IPv4 table does not invalidate the IPv6 cache (and vice versa)."""
    if ipv6 is None:
        _default_route_cache.clear()
    else:
        _default_route_cache.pop(ipv6, None)


def get_default_routes(
    ipv6: bool = False,
    timeout: float = 5.0,
) -> Optional[List[Dict[str, Any]]]:
    """Snapshot of active default routes (not persistent).

    Returns:
      []       — query succeeded, no default routes;
      [dict]   — query succeeded, routes found;
      None     — state could not be determined.
    """
    if not ipv6:
        fast = _ipv4_default_routes_fast()
        if fast is not None:
            return fast
    # PowerShell fallback (including the primary path for IPv6).
    prefix = "::/0" if ipv6 else "0.0.0.0/0"
    family = "IPv6" if ipv6 else "IPv4"
    cmd = (
        f"Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object InterfaceIndex, NextHop, RouteMetric | ConvertTo-Json -Compress"
    )
    try:
        result = run_powershell_json(cmd, timeout=timeout)
    except Exception:
        logger.debug(
            "get_default_routes(%s): PowerShell query failed",
            "IPv6" if ipv6 else "IPv4",
            exc_info=True,
        )
        return None
    rows: List[Any]
    if isinstance(result, dict):
        rows = [result]
    elif isinstance(result, list):
        rows = result
    else:
        logger.debug(
            "get_default_routes(%s): unexpected PowerShell result type: %s",
            "IPv6" if ipv6 else "IPv4",
            type(result).__name__,
        )
        return None
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_idx: Any = row.get("InterfaceIndex")
        try:
            idx = int(raw_idx)
        except (TypeError, ValueError):
            continue
        gw_raw = row.get("NextHop")
        gateway = str(gw_raw).strip() if gw_raw is not None else ""
        if not gateway:
            gateway = "::" if ipv6 else "0.0.0.0"
        try:
            metric = int(row.get("RouteMetric") or 0)
        except (TypeError, ValueError):
            metric = 0
        key = (idx, gateway, metric)
        if key in seen:
            continue
        seen.add(key)
        out.append({"if_index": idx, "gateway": gateway, "metric": metric})
    return out


def _physical_adapter_ifindexes() -> "set[int]":
    """Set of InterfaceIndex values of physical adapters (not PPP/Tunnel/Loopback).

    Needed to distinguish a physical default route from a VPN one when a
    full-tunnel VPN is up: both may be active at the same time, but
    ARP/L2 hygiene only makes sense for the physical neighbour. A VPN adapter
    (IfType=PPP for L2TP/SSTP, Tunnel for IKEv2, etc.) is not an L2
    neighbour in ARP terms: ARP resolution happens on top of an already
    existing IP connection, and there is no entry for the VPN "gateway"
    in the ARP table.

    Returns an empty set both when "there are no adapters" and on an API
    error: callers (get_physical_gateway_ip, get_active_physical_adapter_info)
    in both cases simply cannot determine the physical adapter and
    degrade correctly ("I don't know" → skip ARP hygiene).
    """
    if not IS_WINDOWS:
        return set()

    flags = (GAA_FLAG_SKIP_ANYCAST |
             GAA_FLAG_SKIP_MULTICAST |
             GAA_FLAG_SKIP_DNS_SERVER)

    snapshot = _adapter_addresses_snapshot(flags)
    # not snapshot covers both an API error (snapshot is None) and an empty
    # table (ok=True, buf=None): in both cases there are no adapters to walk.
    if not snapshot:
        return set()

    result: "set[int]" = set()
    for adapter in _walk_adapters(snapshot):
        if int(adapter.IfType) in (
            IF_TYPE_PPP, IF_TYPE_TUNNEL, IF_TYPE_SOFTWARE_LOOPBACK,
        ):
            continue
        if adapter.IfIndex:
            result.add(int(adapter.IfIndex))
    return result


def get_physical_gateway_ip() -> Optional[str]:
    """IPv4 address of the physical adapter gateway through which outgoing
    traffic actually goes.

    Not the same as the "default route gateway": when a full-tunnel VPN is
    up there are several default routes in the table (VPN + physical), and
    we need the physical one specifically — only it is an L2 neighbour for
    which an ARP entry makes sense (see _physical_adapter_ifindexes).

    Strategy: take the ifIndexes of all active IPv4 default routes,
    filter by adapter "physicality", and for the first suitable one
    return its gateway via get_interface_gateways().

    Automatically survives Wi-Fi ↔ Ethernet switching without a separate
    adapter-type detector: _default_route_ifindexes() will return the
    ifIndex of the adapter currently carrying traffic, and it will also
    be "physical" in _physical_adapter_ifindexes().

    Returns None if it could not be determined (no default routes, only
    VPN adapters, or Win32 API failed). The caller must treat None as
    "I don't know" and skip ARP hygiene.
    """
    if not IS_WINDOWS:
        return None
    try:
        default_indexes = _default_route_ifindexes(ipv6=False)
    except Exception:
        logger.debug(
            "get_physical_gateway_ip: _default_route_ifindexes failed",
            exc_info=True,
        )
        return None
    if not default_indexes:
        return None

    physical = _physical_adapter_ifindexes()
    if not physical:
        return None

    for if_index in default_indexes:
        if if_index not in physical:
            continue
        try:
            gws = get_interface_gateways(if_index)
        except Exception:
            logger.debug(
                "get_physical_gateway_ip: get_interface_gateways(%s) failed",
                if_index, exc_info=True,
            )
            continue
        for gw in gws:
            if _is_valid_route_ip(gw):
                return gw
    return None


def get_active_physical_adapter_info() -> Optional[Dict[str, Any]]:
    """Information about the active physical adapter (the one through which
    outgoing traffic currently goes):
        {"if_index": int, "name": str, "kind": "wifi"|"ethernet"|"other"}
    or None if it could not be determined.

    The same principle as in get_physical_gateway_ip(): look at default
    routes, discard VPN/Tunnel/Loopback, take the first physical one.
    Automatically survives Wi-Fi ↔ Ethernet switching without a separate
    detector.
    """
    if not IS_WINDOWS:
        return None
    try:
        default_indexes = _default_route_ifindexes(ipv6=False)
    except Exception:
        logger.debug(
            "get_active_physical_adapter_info: _default_route_ifindexes failed",
            exc_info=True,
        )
        return None
    if not default_indexes:
        return None

    physical = _physical_adapter_ifindexes()
    if not physical:
        return None

    target: Optional[int] = None
    for idx in default_indexes:
        if idx in physical:
            target = idx
            break
    if target is None:
        return None

    try:
        flags = (GAA_FLAG_SKIP_ANYCAST |
                 GAA_FLAG_SKIP_MULTICAST |
                 GAA_FLAG_SKIP_DNS_SERVER)
        size = wintypes.ULONG(0)
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, None, ctypes.byref(size))
        if rc not in (0, 111):  # NO_ERROR / ERROR_BUFFER_OVERFLOW
            return None
        if size.value == 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        p_addrs = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        rc = _GetAdaptersAddresses(AF_UNSPEC, flags, None, p_addrs, ctypes.byref(size))
        if rc != 0:
            return None
        current = p_addrs
        while current:
            adapter = current.contents
            if adapter.IfIndex and int(adapter.IfIndex) == target:
                if_type = int(adapter.IfType)
                name = adapter.FriendlyName or ""
                if if_type == IF_TYPE_IEEE80211:
                    kind = "wifi"
                elif if_type == IF_TYPE_ETHERNET_CSMACD:
                    kind = "ethernet"
                else:
                    kind = "other"
                return {
                    "if_index": target,
                    "name": name,
                    "kind": kind,
                }
            current = adapter.Next
        return None
    except Exception:
        logger.debug("get_active_physical_adapter_info failed", exc_info=True)
        return None


def _add_default_route(if_index: int, gateway: str, metric: int = 0,
                       ipv6: bool = False, timeout: float = 8.0) -> bool:
    """Restores 0.0.0.0/0 or ::/0 via the given interface."""
    if ipv6:
        gw = gateway if gateway and gateway != "::" else "::"
        args = [ROUTE_EXE, "-6", "add", "::/0", gw, "if", str(if_index)]
        if metric and metric > 0:
            args.extend(["metric", str(int(metric))])
    else:
        gw = gateway if gateway else "0.0.0.0"
        args = [ROUTE_EXE, "add", "0.0.0.0", "mask", "0.0.0.0", gw,
                "if", str(if_index)]
        if metric and metric > 0:
            args.extend(["metric", str(int(metric))])
    try:
        proc = _run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    if proc.returncode == 0:
        _invalidate_default_route_cache(ipv6)
        return True
    # Checking by the text of route.exe messages is not used (see add_route). For
    # a default route "already exists" does not require a separate check: the caller
    # first checks presence via
    # _default_route_ifindexes.
    return False


def _delete_default_route(if_index: int, ipv6: bool, timeout: float = 8.0) -> bool:
    if ipv6:
        args = [ROUTE_EXE, "-6", "delete", "::/0", "if", str(if_index)]
    else:
        args = [ROUTE_EXE, "delete", "0.0.0.0", "mask", "0.0.0.0", "if", str(if_index)]
    try:
        proc = _run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    ok = proc.returncode == 0
    if ok:
        # Invalidate only this family's cache: deleting an IPv4 default
        # does not change the IPv6-default table, and vice versa.
        _invalidate_default_route_cache(ipv6)
    return ok


def resolve_host_ips(host: str) -> List[str]:
    """All IPv4 addresses of the name (A records). A literal IPv4 is returned as-is."""
    host = (host or "").strip()
    if not host:
        return []
    try:
        socket.inet_pton(socket.AF_INET, host)
        return [host]
    except OSError:
        pass
    ips: List[str] = []
    seen = set()
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            # For AF_INET, sockaddr is always (ip: str, port: int), but the
            # general getaddrinfo() type in typeshed is a union with the
            # AF_INET6 sockaddr variant, so under mypy it is str|int without
            # an explicit str().
            ip = str(info[4][0])
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    except OSError:
        return []
    return ips


def _process_alive(pid: int) -> bool:
    if not IS_WINDOWS:
        return False
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD(0)
        if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == STILL_ACTIVE
    finally:
        _kernel32.CloseHandle(handle)


def _process_start_time(pid: int) -> Optional[int]:
    """Creation time of the process with the given PID (raw 64-bit FILETIME)
    or None if the process is not found/unavailable.

    Windows freely reuses a PID almost immediately after process exit, so the
    pair (pid, creation time) is the standard way to distinguish "that very"
    process from a completely different one to which the OS happened to give
    the same PID later. Used in self_heal_client_on_startup together with the
    value saved in vpn_client_state.json so that a reused PID is not mistaken
    for a still-running previous instance.

    The value is deliberately NOT converted to Unix time: the comparison is
    done on two "raw" FILETIMEs obtained from the OS — this is more reliable
    and avoids precision loss on rounding.
    """
    if not IS_WINDOWS:
        return None
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not _kernel32.GetProcessTimes(
            handle, ctypes.byref(creation), ctypes.byref(exit_time),
            ctypes.byref(kernel_time), ctypes.byref(user_time),
        ):
            return None
        return (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    except Exception:
        logger.debug("GetProcessTimes(%s) failed", pid, exc_info=True)
        return None
    finally:
        _kernel32.CloseHandle(handle)


def _open_process_watch_handle(pid: int) -> Optional[int]:
    """Handle for WaitForSingleObject: not subject to PID reuse."""
    if not IS_WINDOWS:
        return None
    handle = _kernel32.OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    return int(handle) if handle else None


def _wait_process_handle(handle: int, timeout_ms: int) -> Optional[bool]:
    """True — process has exited, False — still alive, None — WaitForSingleObject failed."""
    if not IS_WINDOWS:
        return None
    rc = int(_kernel32.WaitForSingleObject(handle, int(timeout_ms)))
    if rc == WAIT_OBJECT_0:
        return True
    if rc == WAIT_TIMEOUT:
        return False
    return None


# ═══════════════════════════════════════════════════════════════════════
# PART 1. CLIENT — runs in the ordinary (unprivileged) GUI process
# ═══════════════════════════════════════════════════════════════════════

class HelperError(RuntimeError):
    """Error exchanging with the elevated server (failed to connect / timeout)."""


# Serializes concurrent launch_helper() calls within THIS process (GUI).
# Protects against a repeated UAC prompt / repeated launch of the elevated
# process if launch_helper() is called almost simultaneously from two places.
_launch_lock = threading.Lock()


def is_helper_alive(timeout: float = 1.0) -> bool:
    """Quick check: is the elevated process alive and responding on the pipe."""
    if not IS_WINDOWS:
        return False
    handle = None
    try:
        handle = _client_open_pipe(timeout_ms=int(timeout * 1000) + 1)
        pipe_write_message(handle, {"cmd": "ping"})
        resp = _read_message_with_timeout(handle, timeout)
        return bool(resp.get("ok"))
    except Exception:
        return False
    finally:
        if handle is not None:
            pipe_close(handle)


def send_command(payload: Dict[str, Any], timeout: float = DEFAULT_CMD_TIMEOUT,
                  connect_timeout: float = 5.0) -> Dict[str, Any]:
    """Opens a connection, sends one command, closes the connection.

    Each command is a separate connection to the named pipe (simpler and more
    reliable than keeping a single long-lived socket open on the GUI side
    across different parts of the interface); the server does not interpret
    the closing of each individual connection as a GUI crash — see the module
    docstring above.

    Blocks the calling thread for the duration of the command — do not call
    from the GUI thread.
    """
    _warn_if_main_thread("send_command")
    if not IS_WINDOWS:
        raise HelperError("VPN functionality is available only on Windows")
    handle = None
    try:
        handle = _client_open_pipe(timeout_ms=int(connect_timeout * 1000) + 1)
    except Exception as e:
        raise HelperError(f"Failed to connect to the VPN helper: {e}") from e
    try:
        pipe_write_message(handle, payload)
        try:
            return _read_message_with_timeout(handle, timeout)
        except TimeoutError as e:
            raise HelperError(
                f"Timed out waiting for the helper's reply to command {payload.get('cmd')!r}"
            ) from e
        except Exception as e:
            raise HelperError(f"Invalid helper response: {e}") from e
    finally:
        pipe_close(handle)


def _helper_launch_target(base_path: Path) -> Tuple[str, str]:
    """Returns (executable, args_string) for ShellExecuteW — that is, exactly
    what to restart and with which arguments to relaunch THIS SAME file in
    the server role.

    In development mode (a normal .py/.pyw) — using the same python.exe as
    the main script, with the path to this same vpn.py and the --base-path
    flag (by which the file will understand that the server role needs to be
    executed — see main() at the very bottom of the file). For the
    PyInstaller build, a separate vpn.exe is assumed, built from this same
    source by a separate spec file and located next to the main exe."""
    this_file = Path(__file__).resolve()
    argv: List[str] = []
    if getattr(sys, "frozen", False):
        executable = str(base_path / "vpn.exe")
    else:
        executable = sys.executable
        argv.append(str(this_file))
    argv += ["--parent-pid", str(os.getpid())]
    # Identity of the parent besides PID: the same FILETIME snapshot that is
    # placed in vpn_client_state.json. Needed so that the elevated helper can
    # distinguish "the very GUI that launched me" from "another process of the
    # same user to which Windows gave the same PID after the GUI died".
    # On non-Windows _process_start_time() returns None — then the argument is
    # not added and the server falls back to the PID-only check (as before).
    parent_start_time = _process_start_time(os.getpid())
    if parent_start_time is not None:
        argv += ["--parent-start-time", str(parent_start_time)]
    return executable, subprocess.list2cmdline(argv)


def _helper_integrity_target(base_path: Path) -> Path:
    """The file whose SHA-256 is verified before elevation: vpn.exe in the
    frozen build, vpn.py itself in development mode."""
    if getattr(sys, "frozen", False):
        return base_path / "vpn.exe"
    return Path(__file__).resolve()


def file_sha256(path: Path) -> str:
    """SHA-256 of the file (hex lowercase). Reads in blocks so as not to load
    large exe files entirely into memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_helper_integrity(base_path: Path) -> Tuple[bool, str]:
    """Checks the SHA-256 of the elevated helper against EXPECTED_VPN_HELPER_SHA256.

    Returns:
      (True, "") — ok (or the check is disabled by an empty EXPECTED_*);
      (False, reason) — file missing / hash mismatch / read error.
    """
    expected = (EXPECTED_VPN_HELPER_SHA256 or "").strip().lower()
    if not expected:
        return True, ""
    # The hash in the repository/source is of vpn.exe (written by build.py).
    # In dev we launch vpn.py via python.exe; comparing it to the exe hash
    # is meaningless and breaks launch after a build.
    if not getattr(sys, "frozen", False):
        return True, ""
    target = _helper_integrity_target(base_path)
    if not target.is_file():
        return False, f"helper file not found: {target}"
    try:
        actual = file_sha256(target)
    except OSError as e:
        return False, f"failed to read {target}: {e}"
    if actual != expected:
        logger.error(
            "VPN helper integrity check failed: %s sha256=%s expected=%s",
            target, actual, expected,
        )
        return False, (
            f"VPN helper hash mismatch (the file may have been tampered with).\n"
            f"File: {target.name}\n"
            f"Expected: {expected}\n"
            f"Actual: {actual}"
        )
    return True, ""


def launch_helper(base_path: Path, wait_ready: float = CONNECT_POLL_TIMEOUT) -> str:
    """Launches the elevated process (this same file, server role) via UAC
    (verb "runas").

    Returns a result code string:
      "ok"        — the server came up and answered ping;
      "declined"  — the user declined the UAC prompt (or elevation
                    is blocked by policy);
      "timeout"   — UAC was accepted, the process was started, but it did
                    not come online in time — typical cause: a named-pipe
                    conflict with a previously unterminated process (see
                    vpn_helper.log for the exact reason);
      "not_found" — the helper executable (this same vpn.py/vpn.exe) was
                    not found next to the script;
      "integrity" — the helper SHA-256 did not match EXPECTED_VPN_HELPER_SHA256
                    (possible file substitution; see verify_helper_integrity).

    If the server is already running (e.g. left over from a previous
    settings-open cycle) — a relaunch is not needed; return "ok"
    immediately after checking that first.

    Blocks the calling thread (UAC dialog + readiness wait) —
    do not call from the GUI thread.
    """
    _warn_if_main_thread("launch_helper")
    if not IS_WINDOWS:
        return "declined"
    if is_helper_alive(timeout=0.8):
        return "ok"

    with _launch_lock:
        if is_helper_alive(timeout=0.8):
            return "ok"

        # Integrity — before ShellExecute: otherwise a substituted vpn.exe would
        # already get UAC and administrator rights.
        ok_integrity, integrity_err = verify_helper_integrity(base_path)
        if not ok_integrity:
            logger.error("VPN helper integrity check failed: %s", integrity_err)
            return "integrity"

        executable, args = _helper_launch_target(base_path)
        if not Path(executable).exists():
            logger.error("VPN helper executable not found: %s", executable)
            return "not_found"

        SEE_MASK_NOASYNC = 0x00000100
        SW_HIDE = 0

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", wintypes.ULONG),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR),
                ("hKeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_NOASYNC
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = executable
        sei.lpParameters = args
        sei.lpDirectory = str(base_path)
        sei.nShow = SW_HIDE
        sei.hInstApp = None

        _shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
        _shell32.ShellExecuteExW.restype = wintypes.BOOL
        ok = _shell32.ShellExecuteExW(ctypes.byref(sei))
        if not ok:
            err = ctypes.get_last_error()
            logger.info("VPN helper elevation declined or failed (WinError %s)", err)
            return "declined"

        if sei.hProcess:
            try:
                _kernel32.CloseHandle(sei.hProcess)
            except Exception:
                logger.debug("CloseHandle(sei.hProcess) failed in launch_helper", exc_info=True)

        if not is_helper_alive(timeout=0.5):
            deadline = time.monotonic() + wait_ready
            while time.monotonic() < deadline:
                if is_helper_alive(timeout=0.5):
                    return "ok"
                time.sleep(CONNECT_POLL_INTERVAL)
            logger.error(
                "VPN helper did not become ready within %.1fs — elevation "
                "was accepted (UAC not declined), see vpn_helper.log for the "
                "actual reason (often: a stale process already holding the pipe)",
                wait_ready
            )
            return "timeout"
    return "ok"


def stop_helper(timeout: float = 10.0) -> None:
    """Asks the elevated process to drop VPN/routes and exit. Does not raise exceptions."""
    if not IS_WINDOWS:
        return
    try:
        send_command({"cmd": "shutdown"}, timeout=timeout, connect_timeout=1.5)
    except HelperError as e:
        logger.info("stop_helper: helper did not confirm shutdown (%s) — "
                    "possibly already stopped", e)


# Tracks whether WE (this GUI process) connected the VPN, or it was already
# active before us (brought up by the user manually or by another program) —
# in the latter case we must not disconnect it on exit. IMPORTANT: the
# rasdial connect/disconnect is performed here, in the client
# (unprivileged) process, and NOT in the elevated helper — otherwise it does
# not see the saved credentials of "modern" VPN connections.
CLIENT_STATE_FILE_NAME = "vpn_client_state.json"

APP_DIR_NAME = "IPTV_Scanner"


@functools.lru_cache(maxsize=1)
def _appdata_dir() -> Path:
    """%LOCALAPPDATA%\\IPTV_Scanner\\ — a single, always-writable location for
    runtime state (vpn_client_state.json) and logs.

    A directory next to the program (base_path) is not suitable: when
    installed into Program Files the ACL forbids write access for a regular
    user. LOCALAPPDATA belongs to the current user and is writable both from
    the ordinary GUI process and from the elevated helper (the same user,
    only with an elevated token), therefore both processes are guaranteed to
    use the same directory. Created on first access if it does not exist.
    """
    base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home())
    d = base / APP_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


@functools.lru_cache(maxsize=1)
def _logs_dir() -> Path:
    """%LOCALAPPDATA%\\IPTV_Scanner\\logs\\ — subfolder for vpn_helper.log
    (and scanner.log — see the same-named function in IPTV_scanner.pyw)."""
    d = _appdata_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _client_state_path() -> Path:
    """Path to vpn_client_state.json — always inside _appdata_dir()."""
    return _appdata_dir() / CLIENT_STATE_FILE_NAME


def _restrict_file_acl_current_user(path: Path) -> None:
    """Restricts the file ACL to the current user (+ SYSTEM).

    Best-effort: errors are only logged. We use icacls — simpler and more
    reliable than manually assembling a SECURITY_DESCRIPTOR via ctypes.
    """
    if not IS_WINDOWS:
        return
    try:
        sid = _current_user_sid()
        if not sid:
            return
        # /inheritance:r — remove inherited ACEs; then explicit permissions.
        _run(
            ["icacls", str(path), "/inheritance:r",
             "/grant:r", f"{sid}:(R,W)", "/grant:r", "SYSTEM:(F)"],
            timeout=5.0,
        )
    except Exception:
        logger.debug("Failed to restrict the ACL on %s", path, exc_info=True)


def _write_client_state(
    connection_name: str,
    all_user: Optional[bool] = None,
    previous_split_tunneling: Optional[bool] = None,
    split_tunnel_changed: bool = False,
    registered: bool = False,
    if_index: Optional[int] = None,
    route_ips: Optional[List[str]] = None,
) -> bool:
    """Crash-safety marker of the last session; runtime ownership is kept in the helper.

    The file is not the source of truth: that remains the elevated helper (see
    _helper_owner). But once the VPN is actually up (rasdial_connect completed),
    this file is the only crash-safety mechanism that survives the simultaneous
    abnormal disappearance of both the GUI and the helper process
    (self_heal_client_on_startup reads exactly this file). Therefore a failed
    write is a reason to consider the whole operation unsuccessful and roll the
    VPN back: a bool is returned and the error is not swallowed (see the caller
    connect_and_route()).

    previous_split_tunneling/split_tunnel_changed — the same data as
    saved_split_tunneling/split_tunnel_connection_name in the elevated helper
    (see VpnHelperState.prepare_split_tunnel), duplicated into the file on the
    client side. In the helper's memory they do not survive its death:
    _restore_split_tunneling_unlocked() first clears them and only then performs
    Set-VpnConnection — if the command failed (or the helper died right after),
    the profile stays with SplitTunneling=True forever, and self_heal cannot see
    it. With a copy in the file, self_heal can restore the value even if both
    the helper and the GUI died simultaneously.

    The write is atomic so as not to leave truncated JSON after a
    power/process failure. After writing, the ACL is restricted to the current
    user.

    if_index — a snapshot of the VPN adapter's IfIndex at the moment of writing
    (see get_interface_info), if it is already known.
    self_heal_client_on_startup() uses it as an additional identity check of the
    session: PID/start_time protect against PID reuse, but not against the
    situation where the user, after an abnormal exit, has manually brought up a
    NEW connection with the same connection_name — get_vpn_connected(prev_name)
    will return True, although it does not relate to our old session. An ifIndex
    change is a strong signal that this is a different adapter/session.

    route_ips — list of /32 destination addresses of the routes that we
    confirmedly added in this session (what the client received in the response
    of connect_and_route() in the routes field). Used by
    self_heal_client_on_startup() as the MAIN signal "this is definitely our
    session": if the interface was torn down and recreated (typical scenario of
    manual Disconnect→Connect with ifIndex reuse), Windows removes all routes
    bound to it, including our /32s. An empty list = "no routes were added"
    (all proxy hosts turned out to be reachable through the already up tunnel) —
    in that case self-heal cannot distinguish our old session from the user's
    new one and must behave conservatively (not disconnect).
    """
    path = _client_state_path()
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        payload = {
            "connection_name": connection_name,
            "all_user": all_user,
            "pid": os.getpid(),
            "start_time": _process_start_time(os.getpid()),
            "written_ts": time.time(),
            "registered": bool(registered),
            "split_tunnel_changed": bool(split_tunnel_changed),
            "previous_split_tunneling": (
                bool(previous_split_tunneling) if split_tunnel_changed else None
            ),
            "if_index": if_index,
            "route_ips": [str(ip) for ip in (route_ips or [])],
        }
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
        _restrict_file_acl_current_user(path)
        return True
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        logger.exception("Failed to atomically write vpn_client_state.json")
        return False


def _clear_client_state() -> None:
    try:
        _client_state_path().unlink(missing_ok=True)
    except OSError:
        logger.exception("Failed to delete vpn_client_state.json")


def _read_client_state() -> Optional[dict]:
    """Reads vpn_client_state.json without raising exceptions outward.

    Returns None if the file is missing, corrupted, or unreadable — the caller
    in that case simply has nothing to compare against and must behave as if
    there is nothing to compare with.
    """
    p = _client_state_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _clear_client_state_if_matches(
    connection_name: Optional[str], all_user: Optional[bool] = None
) -> None:
    """Deletes vpn_client_state.json only if it describes exactly this
    (connection_name, all_user) session.

    Unconditional deletion is dangerous: in the owned=False branch,
    disconnect_and_unroute() does not know which connection_name the marker
    refers to. Example race:

        Session A: VPN="vpn-name", vpn_client_state.json describes "vpn-name"
        ...configuration changes to "other"...
        disconnect_and_unroute(base_path, "other") -> helper: owned=False
        -> the file (still describing "vpn-name"!) would be deleted

    and self_heal_client_on_startup() on the next run would lose the only
    crash-safety marker of the real "vpn-name" session. Therefore the
    connection_name/all_user from the file are compared with what was actually
    disconnected/checked; the file is deleted only on a match, otherwise it is
    kept for self-heal.
    """
    if not connection_name:
        return
    data = _read_client_state()
    if data is None:
        return
    state_name = data.get("connection_name")
    state_all_user = data.get("all_user") if isinstance(data.get("all_user"), bool) else None
    normalized_all_user = all_user if isinstance(all_user, bool) else None
    if state_name == connection_name and state_all_user == normalized_all_user:
        _clear_client_state()
    else:
        logger.debug(
            "vpn_client_state.json describes a different session (%r/%s) — "
            "leaving it untouched when disconnecting %r/%s",
            state_name, state_all_user, connection_name, normalized_all_user,
        )


def _helper_owner(timeout: float = 3.0) -> Optional[dict]:
    """Returns the owner information of the elevated helper as the source of truth."""
    if not IS_WINDOWS:
        return None
    try:
        resp = send_command({"cmd": "status"}, timeout=timeout, connect_timeout=1.5)
    except HelperError:
        return None
    if not resp.get("ok"):
        return None
    return {
        "pid": resp.get("owner_pid"),
        "connection_name": resp.get("owner_connection_name"),
        "owner_all_user": resp.get("owner_all_user"),
    }


def _helper_owns_current_process(connection_name: str, all_user: Optional[bool] = None, timeout: float = 3.0) -> bool:
    owner = _helper_owner(timeout=timeout)
    if not owner:
        return False
    return (owner.get("pid") == os.getpid() and
            owner.get("connection_name") == connection_name and
            owner.get("owner_all_user") == all_user)


def self_heal_client_on_startup() -> None:
    """Recovers only the VPN that really hung after a crash.

    In the normal case, ownership is tracked by the elevated helper: its
    monitor disconnects the VPN by itself when the GUI disappears. The state
    file is used only as a fallback if the helper itself disappeared together
    with the previous run.

    Besides the VPN connection itself, it also restores (via the same fallback
    path) the profile's SplitTunneling if the previous run had managed to
    temporarily enable it (see split_tunnel_changed/previous_split_tunneling
    in _write_client_state) and did not manage/could not restore it back —
    otherwise Set-VpnConnection SplitTunneling=True could hang in the profile
    forever after a simultaneous crash of the GUI and the helper.
    """
    if not IS_WINDOWS:
        return

    # If the helper is still alive, it is the source of truth. If ownership
    # is already gone, the old client state can be safely removed. If the
    # helper still has a live owner, we do not interfere.
    if is_helper_alive(timeout=0.8):
        owner = _helper_owner(timeout=1.0)
        if not owner or owner.get("pid") is None:
            _clear_client_state()
        return

    p = _client_state_path()
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _clear_client_state()
        return
    prev_pid = data.get("pid")
    prev_name = data.get("connection_name")
    prev_all_user = data.get("all_user") if isinstance(data.get("all_user"), bool) else None
    prev_start_time = data.get("start_time")
    prev_if_index = data.get("if_index")
    prev_if_index = prev_if_index if isinstance(prev_if_index, int) else None
    raw_route_ips = data.get("route_ips")
    prev_route_ips: List[str] = []
    if isinstance(raw_route_ips, list):
        for item in raw_route_ips:
            if isinstance(item, str) and _is_valid_route_ip(item):
                prev_route_ips.append(item)
    prev_split_changed = bool(data.get("split_tunnel_changed"))
    prev_split_previous = (
        bool(data.get("previous_split_tunneling"))
        if isinstance(data.get("previous_split_tunneling"), bool)
        else False
    )
    if not prev_name:
        _clear_client_state()
        return
    if isinstance(prev_pid, int) and _process_alive(prev_pid):
        # PID is alive — but Windows may reuse a PID for a completely different
        # process between the abnormal exit of the previous run and this start.
        # If the file has saved the process creation time (start_time) and it can
        # be obtained for the current live PID, the values are compared. A
        # mismatch means a different process: the previous instance is actually
        # not alive, and self-heal must continue rather than exit.
        #
        # If comparison is not possible (the file has no start_time, or
        # GetProcessTimes failed), the process is conservatively considered the
        # same one: a false "alive" in this rare case is safer than a false
        # "dead", because we must not remove the VPN/routes from a process that
        # really still owns them.
        current_start_time = _process_start_time(prev_pid)
        same_process = (
            not isinstance(prev_start_time, int)
            or current_start_time is None
            or current_start_time == prev_start_time
        )
        if same_process:
            return
        logger.warning(
            "PID=%s from vpn_client_state.json is alive, but the process creation time "
            "does not match — the PID was reused by another process, "
            "so the previous run is actually not alive",
            prev_pid,
        )
        
    recovery_ok = True
        
    try:
        vpn_connected = get_vpn_connected(
            prev_name,
            all_user=prev_all_user,
        )

        if vpn_connected:
            # Try unconditionally to learn the current ifIndex: it is needed
            # both for comparison with the snapshot and for the route check
            # below.
            current_if_index_before: Optional[int] = None
            try:
                _lookup_state, current_if_index_before, _ = _lookup_interface_by_name(prev_name)
            except Exception:
                current_if_index_before = None
                logger.debug(
                    "_lookup_interface_by_name() before the self-heal disconnect "
                    "failed", exc_info=True,
                )

            skip_disconnect = False
            skip_reason: Optional[str] = None

            # Signal 1: ifIndex does not match — definitely a different adapter.
            if (
                prev_if_index is not None
                and current_if_index_before is not None
                and current_if_index_before != prev_if_index
            ):
                skip_disconnect = True
                skip_reason = (
                    f"ifIndex does not match the snapshot "
                    f"({prev_if_index} -> {current_if_index_before})"
                )

            # Signal 2 is stronger than signal 1. On manual
            # Disconnect→Connect Windows often reuses ifIndex (see
            # the comment at VpnSession at the top of the file), therefore a
            # MATCH of ifIndex says nothing about session identity. But our
            # /32 routes do: they are bound to a specific interface object,
            # and when it is torn down Windows removes all of them. If the
            # recorded routes are gone from the current table, the interface
            # has definitely been recreated since then, which means this is a
            # new session.
            elif prev_route_ips and current_if_index_before is not None:
                try:
                    snapshot = routes_snapshot()
                except Exception:
                    snapshot = None
                    logger.debug(
                        "routes_snapshot() in self-heal failed", exc_info=True,
                    )
                if snapshot is not None:
                    alive, total = count_alive_routes(
                        [(ip, current_if_index_before) for ip in prev_route_ips],
                        snapshot,
                    )
                    if total > 0 and alive == 0:
                        skip_disconnect = True
                        skip_reason = (
                            f"none of the {total} recorded /32 routes are "
                            f"alive (the interface was torn down and "
                            f"recreated with a reused ifIndex)"
                        )
                        logger.info(
                            "Self-heal: all %d recorded routes are gone while "
                            "connection %r is up with the same ifIndex=%s — "
                            "likely a fresh session on a reused index",
                            total, prev_name, current_if_index_before,
                        )

            else:
                # There is not a single reliable signal: either the state file
                # has no route snapshot (old format, or we brought up the VPN
                # but added no /32s — e.g. all proxy hosts turned out to be
                # reachable through the already up tunnel), or the current
                # ifIndex could not be determined. Disconnecting in such a
                # situation is dangerous — we could kill the user's session
                # (see the scenario in the comment for _write_client_state).
                # We go conservative: do NOT disconnect, but still check the
                # profile below.
                skip_disconnect = True
                if not prev_route_ips:
                    skip_reason = (
                        "the state file has no route snapshot — session "
                        "identity cannot be positively confirmed"
                    )
                else:
                    skip_reason = (
                        "the current ifIndex could not be determined for a "
                        "route cross-check"
                    )

            if skip_disconnect:
                logger.warning(
                    "Fallback: connection %r is active, but %s — this looks "
                    "like a new session brought up manually by the user, not "
                    "a stale old one. Not disconnecting; SplitTunneling is "
                    "still checked/restored below (it's a profile setting "
                    "that outlives a reconnect).",
                    prev_name, skip_reason,
                )
                # IMPORTANT: no early return here — otherwise we would skip
                # the SplitTunneling restore (see the existing bug: the old
                # ifIndex-mismatch behaviour returned from here, leaving the
                # profile with SplitTunneling=True forever).
            else:
                logger.warning(
                    "Fallback: no helper from the previous run, but "
                    "vpn_client_state.json lists connection %r — disconnecting it",
                    prev_name,
                )
                disconnected = rasdial_disconnect(
                    prev_name,
                    all_user=prev_all_user,
                )
                if not disconnected:
                    # A non-zero rasdial /DISCONNECT code does not necessarily
                    # mean the VPN is still connected: rasdial can return an
                    # error if the connection is already gone.
                    #
                    # Therefore we check the actual state rather than
                    # automatically considering the recovery unsuccessful.
                    vpn_connected_after = get_vpn_connected(
                        prev_name,
                        all_user=prev_all_user,
                    )

                    if vpn_connected_after is True:
                        recovery_ok = False
                        logger.error(
                            "Fallback: rasdial /DISCONNECT did not disconnect VPN %r",
                            prev_name,
                        )
                    elif vpn_connected_after is None:
                        recovery_ok = False
                        logger.error(
                            "Fallback: could not determine the state of VPN %r after "
                            "a failed rasdial /DISCONNECT",
                            prev_name,
                        )
                    else:
                        logger.info(
                            "Fallback: VPN %r is actually disconnected despite "
                            "a non-zero rasdial /DISCONNECT code",
                            prev_name,
                        )

    except Exception:
        recovery_ok = False
        logger.exception("Error during fallback VPN recovery at startup")
    
    if prev_split_changed:
        # SplitTunneling is a setting of the profile itself, not a runtime
        # state of the connection. Therefore we check the actual state of the
        # profile regardless of whether the VPN was disconnected.
        #
        # IMPORTANT: if the restore failed, we do NOT delete the state. The
        # next run must get another chance to fix the profile.
        try:
            current = get_vpn_split_tunneling(
                prev_name,
                all_user=prev_all_user,
            )

            if current is None:
                recovery_ok = False
                logger.error(
                    "Fallback: could not determine the current "
                    "SplitTunneling for %r",
                    prev_name,
                )
            elif current != prev_split_previous:
                ok, err = set_vpn_split_tunneling(
                    prev_name,
                    prev_split_previous,
                    all_user=prev_all_user,
                )
                if ok:
                    logger.warning(
                        "Fallback: restored SplitTunneling=%s for %r "
                        "after the previous run crashed",
                        prev_split_previous,
                        prev_name,
                    )
                else:
                    recovery_ok = False
                    logger.error(
                        "Fallback: failed to restore "
                        "SplitTunneling=%s for %r: %s",
                        prev_split_previous,
                        prev_name,
                        err,
                    )
            else:
                logger.info(
                    "Fallback: SplitTunneling for %r already has the expected "
                    "value %s",
                    prev_name,
                    prev_split_previous,
                )

        except Exception:
            recovery_ok = False
            logger.exception(
                "Error during fallback SplitTunneling recovery at startup"
            )

    if recovery_ok:
        _clear_client_state()
    else:
        logger.warning(
            "vpn_client_state.json NOT deleted: recovery of the previous "
            "VPN session did not complete fully; the next run "
            "will try recovery again"
        )

def connect_and_route(base_path: Path, connection_name: str,
                       hosts: Iterable[Tuple[Any, ...]], all_user: Optional[bool] = None,
                       route_timeout: float = DEFAULT_CMD_TIMEOUT) -> Dict[str, Any]:
    """Connects the VPN if needed and configures only the required routes.

    `hosts` accepts (host, port) or (host, port, scheme).
    Runtime split-tunnel is provided exclusively by routing: the Windows VPN
    profile is NOT modified here via Set-VpnConnection.

    On ok=True, the response additionally returns:
        if_index, local_ip — parameters of the interface through which the
                             routes were installed;
        routes             — [[ip, if_index, gateway], ...] of the routes
                             actually added (confirmed by the helper).

    `routes` is needed by the GUI to keep its own mirror of "our" /32s and to
    watch for their disappearance (a detector of RAS-session change with the
    same ifIndex — see _VpnSessionWatch in IPTV_scanner.pyw). Without it the
    GUI would have to query the status command over the pipe on every monitor
    tick: the list lives only in the memory of the elevated helper
    (VpnHelperState.routes).
    """
    _warn_if_main_thread("connect_and_route")
    empty: Dict[str, Any] = {
        "resolved": {}, "resolved_all": {},
        "if_index": None, "local_ip": None, "routes": [],
    }
    if not IS_WINDOWS:
        return {"ok": False, "error": "VPN functionality is available only on Windows", **empty}

    hosts_list = list(hosts)
    already = get_vpn_connected(connection_name, all_user=all_user)
    if already is None:
        return {
            "ok": False,
            "error": "Could not determine the VPN connection status (PowerShell)",
            **empty,
        }

    we_connected = False
    helper_ok = is_helper_alive(timeout=0.8)
    # Snapshot of default routes BEFORE rasdial + temporary SplitTunneling in
    # the profile: otherwise Windows installs 0.0.0.0/0 via the VPN with a
    # better metric and all outgoing traffic goes into the tunnel.
    pre_defaults_v4: List[Dict[str, Any]] = []
    pre_defaults_v6: List[Dict[str, Any]] = []
    # Duplicate here what the helper already holds in memory
    # (saved_split_tunneling/split_tunnel_connection_name) — in case the
    # helper and the GUI die simultaneously BEFORE SplitTunneling is restored
    # back, self_heal_client_on_startup() must have this information not only
    # in the helper's memory but also in vpn_client_state.json
    # (see _write_client_state and disconnect_and_unroute).
    split_tunnel_changed = False
    previous_split_tunneling: Optional[bool] = None
    if not already:
        try:
            # get_default_routes() returns None if the state could not be
            # determined; we keep Optional in temporary variables and put the
            # already normalized list into pre_defaults_*.
            snap_v4 = get_default_routes(ipv6=False)
            if snap_v4 is None:
                logger.warning(
                    "Could not determine the IPv4 default-route snapshot before VPN connect"
                )
                snap_v4 = []
            pre_defaults_v4 = snap_v4

            snap_v6 = get_default_routes(ipv6=True)
            if snap_v6 is None:
                logger.warning(
                    "Could not determine the IPv6 default-route snapshot before VPN connect"
                )
                snap_v6 = []
            pre_defaults_v6 = snap_v6

            logger.info(
                "Default-route snapshot before connect: v4=%s v6=%s",
                pre_defaults_v4, pre_defaults_v6,
            )

        except Exception:
            logger.exception("Failed to snapshot the default routes before connect")

        # SplitTunneling must be enabled BEFORE rasdial (while the profile is
        # disconnected).
        if not helper_ok:
            helper_ok = is_helper_alive(timeout=1.0)
        if helper_ok:
            try:
                prep = send_command(
                    {
                        "cmd": "prepare_split_tunnel",
                        "connection_name": connection_name,
                        "all_user": all_user,
                    },
                    timeout=15.0,
                )
                if not prep.get("ok"):
                    logger.warning(
                        "prepare_split_tunnel failed: %s — continuing with "
                        "force-remove default route",
                        prep.get("error"),
                    )
                else:
                    logger.info(
                        "prepare_split_tunnel: already=%s previous=%s",
                        prep.get("already"), prep.get("previous"),
                    )
                    if not prep.get("already"):
                        # The profile was really modified (already=False) —
                        # remember the previous value so that self_heal can
                        # restore it if the restore via
                        # restore_split_tunnel/_rollback_owned_vpn below does
                        # not happen (e.g. due to a simultaneous crash of the
                        # GUI and the helper).
                        split_tunnel_changed = True
                        previous_split_tunneling = bool(prep.get("previous"))
            except HelperError as e:
                logger.warning("prepare_split_tunnel: the helper did not respond: %s", e)
        else:
            logger.warning(
                "elevated helper unavailable before connect — SplitTunneling in the profile "
                "is not enabled; relying on remove_default_route after connect"
            )

        logger.info("VPN %r was not active — connecting via rasdial", connection_name)
        ok, err = rasdial_connect(connection_name, all_user=all_user)
        if not ok:
            logger.error("rasdial connect failed: %s", err)
            # Restore SplitTunneling if we managed to modify the profile
            # before connect.
            try:
                if helper_ok:
                    send_command({"cmd": "restore_split_tunnel"}, timeout=10.0, connect_timeout=1.5)
            except HelperError:
                pass
            return {"ok": False, "error": f"Failed to connect VPN: {err}", **empty}
        logger.info("VPN %r connected successfully", connection_name)
        we_connected = True

        # Snapshot of ifIndex right after connect — best-effort: the adapter
        # may not have fully come up yet, in which case get_interface_info()
        # returns None and the state file will not contain this extra check
        # (self-heal acts more conservatively for such a record — see
        # _write_client_state).
        try:
            _if_index_snapshot, _ = get_interface_info(connection_name)
        except Exception:
            _if_index_snapshot = None
            logger.debug(
                "get_interface_info() right after connect failed",
                exc_info=True,
            )

        # The crash-safety marker must appear IMMEDIATELY after a successful
        # rasdial_connect(), before register_client().
        #
        # If the process dies in this window, self_heal_client_on_startup()
        # will be able to see that the VPN was brought up by our process, even
        # if the elevated helper has not yet obtained ownership.
        if not _write_client_state(
            connection_name, all_user,
            previous_split_tunneling=previous_split_tunneling,
            split_tunnel_changed=split_tunnel_changed,
            registered=False,
            if_index=_if_index_snapshot,
        ):
            logger.error(
                "VPN connected, but failed to write the crash-safety marker "
                "before registering with the helper — disconnecting VPN"
            )
            try:
                rasdial_disconnect(connection_name, all_user=all_user)
            except Exception:
                logger.exception(
                    "Failed to disconnect VPN after the crash-safety "
                    "marker write error"
                )
            try:
                if helper_ok:
                    send_command(
                        {"cmd": "restore_split_tunnel"},
                        timeout=10.0,
                        connect_timeout=1.5,
                    )
            except HelperError:
                pass
            return {
                "ok": False,
                "error": "VPN connected, but failed to write the crash-recovery state",
                **empty,
            }

        def _restore_profile_split() -> None:
            try:
                if is_helper_alive(timeout=0.8):
                    send_command({"cmd": "restore_split_tunnel"}, timeout=10.0, connect_timeout=1.5)
            except HelperError:
                pass

        if not helper_ok:
            helper_ok = is_helper_alive(timeout=1.0)
        if not helper_ok:
            rasdial_disconnect(connection_name, all_user=all_user)
            _restore_profile_split()
            _clear_client_state()
            return {
                "ok": False,
                "error": "VPN connected, but the elevated helper is unavailable for route setup",
                **empty,
            }

        try:
            reg = send_command(
                {"cmd": "register_client", "pid": os.getpid(),
                 "connection_name": connection_name, "all_user": all_user},
                timeout=5.0,
            )
        except HelperError as e:
            rasdial_disconnect(connection_name, all_user=all_user)
            _restore_profile_split()
            _clear_client_state()
            return {
                "ok": False,
                "error": f"Failed to register the VPN session: {e}",
                **empty,
            }
        if not reg.get("ok"):
            rasdial_disconnect(connection_name, all_user=all_user)
            _restore_profile_split()
            _clear_client_state()
            return {
                "ok": False,
                "error": reg.get("error") or "The helper rejected the VPN session registration",
                **empty,
            }

        # Restore the user profile IMMEDIATELY, not only on
        # disconnect/release. The profile needed SplitTunneling=True exactly
        # for the duration of RasDialW: Windows reads this flag at connect time
        # and decides whether to install 0.0.0.0/0 via the tunnel. After the
        # session is up and we are registered as owner, the on-disk profile no
        # longer influences anything — but a leftover Split=True means the
        # user's setting has been temporarily overwritten. If the user at that
        # moment does their own Disconnect→Connect (e.g. from Windows Settings,
        # to get full-tunnel for corporate sites), the new session will come up
        # with OUR temporary value, not with their own — on a fast reset
        # (faster than the monitor manages to see down and start cleanup with
        # restore on the disconnect path) the user will get a split session
        # instead of full, even though Windows shows the VPN came up normally.
        #
        # The runtime state of our current session does not change from this:
        # Split is read only at RasDialW, so an already established session
        # stays in the mode rasdial brought it up in (without 0.0.0.0/0 via
        # the VPN). Our /32 routes are not touched either — they are in the
        # routing table, regardless of the profile setting.
        #
        # We do not clear the local split_tunnel_changed flag: the state file
        # must stay with previous_split_tunneling so that self-heal, in the
        # event of a crash between register_client and this restore, can still
        # return the profile. If the restore here succeeded, self-heal will
        # try to restore once more, but it is a no-op (it checks the current
        # value before set — see self_heal_client_on_startup).
        if split_tunnel_changed:
            try:
                sresp = send_command(
                    {"cmd": "restore_split_tunnel"},
                    timeout=10.0, connect_timeout=1.5,
                )
                if sresp.get("ok"):
                    logger.info(
                        "connect_and_route: SplitTunneling profile restored "
                        "to the user's value right after connect (previous=%s) — "
                        "any user-initiated reconnect from now on will bring "
                        "up the profile as the user configured it",
                        previous_split_tunneling,
                    )
                else:
                    logger.warning(
                        "connect_and_route: restore_split_tunnel right after "
                        "connect returned not-ok: %s — will retry on disconnect",
                        sresp.get("error"),
                    )
            except HelperError as e:
                logger.warning(
                    "connect_and_route: restore_split_tunnel right after "
                    "connect failed: %s — will retry on disconnect", e,
                )

        # By this point (after rasdial + register_client) the adapter is more
        # likely to be up than right after connect — we try to refresh the
        # ifIndex snapshot; if that fails, we use the one taken earlier
        # (which may be None).
        try:
            _if_index_now, _ = get_interface_info(connection_name)
            if _if_index_now is not None:
                _if_index_snapshot = _if_index_now
        except Exception:
            logger.debug(
                "get_interface_info() before the final state write failed",
                exc_info=True,
            )

        if not _write_client_state(
            connection_name, all_user,
            previous_split_tunneling=previous_split_tunneling,
            split_tunnel_changed=split_tunnel_changed,
            registered=True,
            if_index=_if_index_snapshot,
        ):
            # The VPN is already up and registered with the helper, but the
            # crash-safety marker could not be written — both crash-recovery
            # mechanisms (helper ownership + state file) must be operational
            # at the same time, so we do not continue "as if nothing
            # happened" but roll back the already-raised VPN in the same way
            # as the other errors below (see _rollback_owned_vpn).
            try:
                send_command({"cmd": "release_and_disconnect"}, timeout=25.0, connect_timeout=1.5)
            except HelperError:
                pass
            try:
                rasdial_disconnect(connection_name, all_user=all_user)
            except Exception:
                logger.exception("rollback (write_client_state failed): rasdial_disconnect(%r)", connection_name)
            return {
                "ok": False,
                "error": "Failed to write the VPN client state file (crash safety) — connection cancelled",
                **empty,
            }
    else:
        logger.info("VPN %r was already active (not started by us) — using it as is", connection_name)

    def _rollback_owned_vpn() -> None:
        if not we_connected:
            return
        logger.warning("Rolling back VPN %r that we brought up, due to an error in a later step", connection_name)
        try:
            # release_and_disconnect — a single pipe command: the helper
            # itself removes the routes, releases ownership AND disconnects
            # the VPN (rasdial disconnect does not require credentials, see
            # the module docstring). Two separate round-trip commands
            # (release_client, then client-side rasdial_disconnect) would
            # leave a race window between them.
            resp = send_command({"cmd": "release_and_disconnect"}, timeout=25.0, connect_timeout=1.5)
            owned = resp.get("owned")
            if owned and not resp.get("vpn_disconnected", True):
                # The helper released ownership, but its own rasdial_disconnect
                # failed — we back it up with a client-side call (which also
                # requires no privileges).
                release_name = str(resp.get("connection_name") or connection_name)
                returned_scope = resp.get("all_user")
                release_scope = returned_scope if isinstance(returned_scope, bool) else all_user
                rasdial_disconnect(release_name, all_user=release_scope)
            elif not owned:
                # owned=False should not normally happen here (we have just
                # brought this tunnel up — we_connected=True), but it is
                # theoretically possible under a race/registration reset on
                # the helper side (e.g. it decided this was not our session).
                # Without handling, the tunnel would stay up: the elif above
                # would not fire (owned=False), and we would not enter the
                # except HelperError branch because the command completed
                # without an exception. Therefore a direct client-side
                # rasdial_disconnect is performed — it requires no privileges
                # and is safe even if the tunnel is already gone (see the
                # rasdial_disconnect semantics above).
                logger.warning(
                    "release_and_disconnect: the helper did not confirm ownership of VPN "
                    "%r although we definitely brought it up (we_connected=True) — "
                    "disconnecting directly (fallback)", connection_name,
                )
                rasdial_disconnect(connection_name, all_user=all_user)
        except HelperError:
            try:
                # The helper is unavailable at all — the only remaining path.
                rasdial_disconnect(connection_name, all_user=all_user)
            except Exception:
                logger.exception("rollback: rasdial_disconnect(%r) (helper unavailable)", connection_name)
        except Exception:
            logger.exception("rollback: release_and_disconnect(%r)", connection_name)
        _clear_client_state()

    # After rasdial the adapter/IP often appear within 1–3 s; after UAC/cold
    # start — longer. A single window instead of "standard + retry": less log
    # noise, the same time budget (~18 s when we_connected).
    _iface_attempts = (
        IF_INDEX_POLL_ATTEMPTS + IF_INDEX_RETRY_EXTRA_ATTEMPTS  # 40×0.2 + 50×0.2 ≈ 18 s
        if we_connected
        else IF_INDEX_POLL_ATTEMPTS
    )
    lookup_state, if_index, local_ip = wait_for_interface_state(
        connection_name,
        attempts=_iface_attempts,
        interval=IF_INDEX_POLL_INTERVAL,
    )
    if (
        lookup_state is not InterfaceLookupState.FOUND
        or if_index is None
        or local_ip is None
    ):
        # The action is the same in all three cases — we roll back, because
        # without if_index/local_ip we cannot add routes; we only distinguish
        # the log/message text (see _explain_lookup_failure).
        explanation = _explain_lookup_failure(
            connection_name, lookup_state, if_index, local_ip,
            expect_ipv4=True,
        )
        logger.error(
            "wait_for_interface_state(%r) failed (state=%s, ifIndex=%s, "
            "local_ip=%s) — %s; rolling back the VPN we brought up",
            connection_name, lookup_state.value, if_index, local_ip, explanation,
        )
        _rollback_owned_vpn()
        return {
            "ok": False,
            "error": f"VPN connected, but the network {IFACE_UNDETERMINED_MARKER}",
            **empty,
        }
    logger.info("VPN %r interface: ifIndex=%s, local_ip=%s", connection_name, if_index, local_ip)


    # Resolve hosts BEFORE remove_default_route.
    #
    # With a full-tunnel profile (the "Use default gateway on remote network"
    # checkbox), Windows after RasDial substitutes corporate DNS on the VPN
    # adapter. If 0.0.0.0/0 is removed first, the path to those DNS servers
    # disappears and getaddrinfo for internal names fails with "does not
    # resolve". While the default route via the tunnel still exists, DNS is
    # alive and resolution succeeds; then we force split-tunnel and install
    # /32s only for the required IPs (+ DNS).
    resolved: Dict[str, str] = {}
    resolved_all: Dict[str, List[str]] = {}
    routes_to_add: List[List[Any]] = []
    errors: List[str] = []
    for item in hosts_list:
        host = str(item[0])
        ips = resolve_host_ips(host)
        if not ips:
            errors.append(f"{host}: does not resolve")
            continue
        resolved[host] = ips[0]
        resolved_all[host] = ips
        for ip in ips:
            # IPv4 runtime routing; we do not add IPv6 yet.
            if ":" not in ip:
                routes_to_add.append([ip, if_index, local_ip])

    # Routes to the DNS of the VPN interface — so that after split-tunnel
    # resolution (repeat or system) is not broken. We do this both for
    # we_connected and already-connected: the profile may have been
    # full-tunnel.
    for dns_ip in get_interface_dns_servers(if_index):
        if dns_ip not in {r[0] for r in routes_to_add}:
            routes_to_add.append([dns_ip, if_index, local_ip])
            logger.info("Adding a route to the DNS of the VPN interface: %s", dns_ip)

    if we_connected:
        try:
            dr_resp = send_command(
                {
                    "cmd": "remove_default_route",
                    "if_index": if_index,
                    "pre_defaults_v4": pre_defaults_v4,
                    "pre_defaults_v6": pre_defaults_v6,
                },
                timeout=20.0,
            )
            if not dr_resp.get("ok"):
                _rollback_owned_vpn()
                return {"ok": False, "error": dr_resp.get("error") or "Failed to remove the VPN default route", **empty}
            if dr_resp.get("restored_v4") or dr_resp.get("restored_v6"):
                logger.info(
                    "Physical gateways restored after removing the VPN default: "
                    "v4=%s v6=%s",
                    dr_resp.get("restored_v4"), dr_resp.get("restored_v6"),
                )
            # state_ok — an aggregated answer "split-tunnel is actually in
            # effect" (see the remove_default_route docstring). ok=True only
            # means "the command was processed"; the separate state_ok check
            # is needed because ok does not guarantee that Windows/RAS did
            # not restore the VPN default after our route delete, or that the
            # machine has a physical default.
            if dr_resp.get("state_ok") is False:
                logger.warning(
                    "Split-tunnel for VPN %r did not reach the target state "
                    "(postcondition_ok=%s has_other_default=%s "
                    "restore_errors=%s metric_set=%s) — some traffic may still "
                    "go through the tunnel, or a physical default may be missing. "
                    "Continuing: the VPN itself is up and host routes are set, "
                    "rollback would be heavier than the degradation.",
                    connection_name,
                    dr_resp.get("postcondition_ok"),
                    dr_resp.get("has_other_default"),
                    dr_resp.get("restore_errors"),
                    dr_resp.get("metric_set"),
                )
        except HelperError as e:
            _rollback_owned_vpn()
            return {"ok": False, "error": f"Failed to configure split-tunnel: {e}", **empty}

    added: List[str] = []
    # Routes are needed both when we brought the VPN up (split-tunnel) and
    # when it was already active for the user: the Windows profile is often
    # split-tunnel despite a "full" tunnel. We do not take ownership in the
    # already case — otherwise on exit we would disconnect someone else's
    # VPN; the helper allows add_routes from parent_pid without
    # register_client (see _routes_authorized_unlocked).
    if routes_to_add:
        if not helper_ok:
            helper_ok = is_helper_alive(timeout=0.8)
        if not helper_ok:
            errors.append("the elevated helper for adding routes is not running")
        else:
            try:
                resp = send_command({"cmd": "add_routes", "routes": routes_to_add}, timeout=route_timeout)
            except HelperError as e:
                errors.append(f"failed to add routes (helper): {e}")
            else:
                added = [str(x) for x in (resp.get("added") or [])]
                if not resp.get("ok"):
                    errors.append(resp.get("error") or "add_routes: unknown error")
                elif resp.get("error"):
                    errors.append(resp["error"])

    # For an already-connected VPN we do not require any routes of our own
    # if the user explicitly keeps the VPN up themselves. For we_connected,
    # the absence of routes means there is nothing to scan through the tunnel.
    if routes_to_add and not added:
        logger.warning("connect_and_route: no routes were added: %s", "; ".join(errors))
        _rollback_owned_vpn()
        return {
            "ok": False,
            "error": "; ".join(errors) if errors else "failed to add routes",
            "resolved": resolved,
            "resolved_all": resolved_all,
            "if_index": if_index,
            "local_ip": local_ip,
            "routes": [],
        }

    if errors:
        logger.warning("connect_and_route: %s", "; ".join(errors))
    else:
        logger.info("connect_and_route: success, resolved_all=%s", resolved_all)

    # We hand out exactly the routes CONFIRMED by the helper (added), not
    # routes_to_add: if some did not get installed, the GUI mirror must not
    # consider them "ours" — otherwise the route-disappearance detector would
    # start with entries that are known to be dead and would produce false
    # positives.
    added_set = set(added)
    # We update the crash-safety marker with the list of routes ACTUALLY
    # confirmed by the helper. Only for we_connected: in the already=True
    # branch the state file is not ours, and overwriting it is not allowed
    # (we do not control that session). For we_connected=True, this very
    # list is the main "ours/not ours" signal during self-heal (see the
    # _write_client_state docstring).
    if we_connected:
        if not _write_client_state(
            connection_name, all_user,
            previous_split_tunneling=previous_split_tunneling,
            split_tunnel_changed=split_tunnel_changed,
            registered=True,
            if_index=if_index,
            route_ips=sorted(added_set),
        ):
            # We do not fail connect_and_route: the VPN is already up and
            # working, routes are installed. It is just that self-heal next
            # time will get a weaker signal (ifIndex only) — as it was
            # before this change.
            logger.warning(
                "connect_and_route: failed to update the crash-safety "
                "marker with the confirmed routes — self-heal will fall "
                "back to a weaker (ifIndex-only) identity check",
            )
    return {
        "ok": True, "error": "; ".join(errors) if errors else None,
        "resolved": resolved, "resolved_all": resolved_all,
        "we_connected": we_connected,
        "if_index": if_index, "local_ip": local_ip,
        "routes": [list(r) for r in routes_to_add if r[0] in added_set],
    }


def disconnect_and_unroute(base_path: Path, connection_name: str,
                            all_user: Optional[bool] = None) -> Dict[str, Any]:
    """Releases the program-owned VPN session via the helper.

    The decision "did we connect the VPN" is made by the helper. If the
    connection was started by the user beforehand, the program does not
    disconnect it.

    Returns a structured result:
      {"ok": bool, "owned": bool, "routes_removed": bool, "vpn_disconnected": bool}
    "ok" — overall success of the operation. Even if it is False, the
    individual fields show what exactly failed: e.g. ownership was released
    and routes were removed, but the VPN itself could not be disconnected.
    That way the calling code (GUI) can distinguish "all good" from "the VPN
    probably stayed up" and show/log it.

    vpn_client_state.json is deleted only when we either know for sure that
    the VPN was disconnected by us, or know for sure that the VPN was not
    ours (owned=False) — that is, the file could not describe this session.
    If the result is unknown (helper unavailable / disconnect not confirmed),
    the file is deliberately NOT touched, so that self_heal_client_on_startup()
    on the next run can pick up and disconnect the VPN.

    In addition, the file is deleted only if it describes exactly the
    (connection_name, all_user) session that was checked/disconnected here
    (see _clear_client_state_if_matches): otherwise the marker of another,
    not-yet-disconnected session (e.g. after changing the VPN profile in the
    settings) could be erased by mistake.
    """
    result: Dict[str, Any] = {"ok": True, "owned": False, "routes_removed": True, "vpn_disconnected": True}
    if not IS_WINDOWS:
        return result

    if not is_helper_alive(timeout=1.0):
        # The helper is unavailable — neither ownership can be learned nor
        # routes/VPN removed through it. Ownership being unknown means it is
        # safer to keep the state file than to delete it blindly.
        result.update(ok=False, routes_removed=False, vpn_disconnected=False)
        logger.warning(
            "disconnect_and_unroute: elevated helper unavailable — state of "
            "VPN %r not verified, vpn_client_state.json kept for self-heal",
            connection_name,
        )
        return result

    try:
        # release_and_disconnect — one pipe command instead of release_client
        # + client-side rasdial_disconnect (see _rollback_owned_vpn):
        # eliminates the window in which the GUI could die after ownership
        # was released but before the VPN was actually disconnected.
        resp = send_command({"cmd": "release_and_disconnect"}, timeout=25.0, connect_timeout=1.5)
    except HelperError as e:
        result.update(ok=False, routes_removed=False, vpn_disconnected=False)
        logger.warning("disconnect_and_unroute: release_and_disconnect failed: %s", e)
        return result

    owned = bool(resp.get("owned"))
    result["owned"] = owned
    result["routes_removed"] = bool(resp.get("routes_removed", True))
    if not resp.get("ok"):
        result["ok"] = False
    if owned:
        result["vpn_disconnected"] = bool(resp.get("vpn_disconnected", False))
        if not result["vpn_disconnected"]:
            result["ok"] = False
            logger.warning(
                "disconnect_and_unroute: the helper did not confirm the disconnect of VPN %r — "
                "vpn_client_state.json kept for self-heal on the next start",
                connection_name,
            )
    else:
        # The VPN was not ours — the marker of the previous OUR session can
        # be removed, but only if it related to THIS connection_name/all_user
        # (see _clear_client_state_if_matches) — otherwise we risk erasing
        # the marker of another, not-yet-disconnected session of ours.
        result["vpn_disconnected"] = True

    if result["vpn_disconnected"]:
        if owned:
            # The helper returned the real connection_name/all_user of the
            # session it disconnected (see release_and_disconnect on the
            # server side) — they are more authoritative than the parameters
            # passed here and are used for the comparison first; just in
            # case, we fall back to the passed parameters if the helper did
            # not send them.
            released_name = str(resp.get("connection_name") or connection_name)
            released_all_user = resp.get("all_user")
            if not isinstance(released_all_user, bool):
                released_all_user = all_user
            _clear_client_state_if_matches(released_name, released_all_user)
        else:
            _clear_client_state_if_matches(connection_name, all_user)
    return result


def list_connection_profiles(timeout: float = 8.0) -> List[dict]:
    """Returns VPN profiles with an explicit scope, including identical names."""
    if not IS_WINDOWS:
        return []
    result: List[dict] = []
    for extra, all_user in (("", False), (" -AllUserConnection", True)):
        ps_cmd = (
            f"Get-VpnConnection{extra} -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
        )
        try:
            out = run_powershell_json(ps_cmd, timeout=timeout)
        except Exception:
            out = None
        names = [out] if isinstance(out, str) else (out if isinstance(out, list) else [])
        for name in names:
            if name:
                result.append({"name": str(name), "all_user": all_user})
    seen = set()
    unique = []
    for item in result:
        key = (item["name"], item["all_user"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _arp_flush_ips(ips: Iterable[str], timeout: float = 5.0) -> Dict[str, Any]:
    """Executes `arp -d <ip>` for each valid IPv4 address from ips.

    Validation via _is_valid_route_ip — the same protection against command
    injection as for add_routes/remove_routes (see its docstring): values go
    straight into argv of subprocess.run, but the IPv4-literal format is
    checked in advance so that junk is cut off before calling arp.exe.

    Does not raise exceptions outward — best-effort.
    """
    attempted: List[str] = []
    for raw_ip in ips:
        if not _is_valid_route_ip(raw_ip):
            continue
        ip = str(ipaddress.IPv4Address(raw_ip))
        attempted.append(ip)
        try:
            _run([ARP_EXE, "-d", ip], timeout=timeout)
        except Exception:
            logger.debug("arp -d %s failed", ip, exc_info=True)
    return {"ok": True, "attempted": attempted}


# ═══════════════════════════════════════════════════════════════════════
# PART 2. SERVER (ELEVATED HELPER) — runs only when this same file is
# started as a separate process with --base-path (see main() at the bottom).
# Runs with administrator rights obtained via UAC at launch from launch_helper().
# ═══════════════════════════════════════════════════════════════════════

LOG_FILE_NAME = "vpn_helper.log"
LOG_MAX_BYTES = 500_000

def ping_probe(host: str, timeout: float = 5.0) -> bool:
    """One `ping -n 1` to the given IPv4 address. Does not raise exceptions —
    best-effort, called from hot-path recovery logic.
    """
    if not _is_valid_route_ip(host):
        return False
    try:
        proc = _run([PING_EXE, "-n", "1", "-w", "2000", host], timeout=timeout)
        return proc.returncode == 0
    except Exception:
        logger.debug("ping_probe(%s) failed", host, exc_info=True)
        return False


def _adapter_restart(interface_name: str, timeout: float = 45.0) -> Dict[str, Any]:
    """netsh interface set interface <name> admin=disable; sleep 3;
    admin=enable. Full recreation of the interface object in the kernel — the
    same as Restart-NetAdapter, but without PowerShell.

    Returns {"ok": bool, "interface": str, "error": str|None}.
    """
    if not IS_WINDOWS:
        return {"ok": False, "interface": interface_name, "error": "not Windows"}
    try:
        name = _validate_vpn_name(interface_name)
    except ValueError as e:
        return {"ok": False, "interface": interface_name, "error": str(e)}

    try:
        proc = _run(
            [NETSH_EXE, "interface", "set", "interface", name, "admin=disable"],
            timeout=15.0,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "interface": name, "error": "disable timeout"}
    if proc.returncode != 0:
        return {
            "ok": False,
            "interface": name,
            "error": f"disable returned {proc.returncode}",
        }

    time.sleep(3.0)

    try:
        proc = _run(
            [NETSH_EXE, "interface", "set", "interface", name, "admin=enable"],
            timeout=15.0,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "interface": name, "error": "enable timeout"}
    if proc.returncode != 0:
        return {
            "ok": False,
            "interface": name,
            "error": f"enable returned {proc.returncode}",
        }

    return {"ok": True, "interface": name, "error": None}

# PID of the client whose command the server thread is currently handling.
# Stored in _handle_client() and read deep in the stack (VpnHelperState.add_routes/
# disconnect_and_unroute) without threading it through every signature.
#
# threading.local(), not a module-level global and not a Thread object attribute:
# the server currently handles clients strictly sequentially on one thread (see
# the main loop below), but threading.local() remains correct even with
# parallel handling of multiple clients.
_client_context = threading.local()


class VpnHelperState:
    """State of the elevated helper. rasdial connect/disconnect run in the
    unprivileged client process; the helper is responsible for route
    add/delete, removing the default route, and emergency disconnect if the GUI is killed.

    A separate crash-safety state file for routes is not required: routes are
    bound to a specific VPN-adapter ifIndex, and Windows removes them from the
    table automatically when that adapter disappears.

    NOTE: this is about binding of a table entry, NOT about session identity.
    ifIndex does not identify a VPN session: RAS reuses the same index on
    reconnect of the same profile. Therefore add_routes() below, even when
    (if_index, gateway) match the cache, additionally checks physical presence
    of the entry via _unicast_route_exists(). Session change is detected by the
    GUI from the consequences of interface recreation (see _VpnSessionWatch in IPTV_scanner.pyw).

    DISCONNECT (rasdial /DISCONNECT) does not require credentials, so the helper
    can watch the GUI process PID and, if it disappears WITHOUT an explicit
    shutdown command, disconnect the VPN itself and exit. Without this last
    step Task Manager would keep an orphaned python.exe: the elevated process,
    launched via UAC is not a child of the GUI, and Windows does not kill it itself.
    """

    def __init__(self, parent_pid: Optional[int] = None,
                 parent_start_time: Optional[int] = None):
        self.log = logging.getLogger("vpn_helper")
        self.routes: Dict[str, Tuple[int, str]] = {}  # ip -> (if_index, gateway)
        self.owner_pid: Optional[int] = None
        self.owner_connection_name: Optional[str] = None
        self.owner_all_user: Optional[bool] = None
        self.parent_pid: Optional[int] = parent_pid
        # If we temporarily enabled SplitTunneling — remember the previous
        # value to return it on release / abnormal exit.
        self.saved_split_tunneling: Optional[bool] = None
        self.split_tunnel_connection_name: Optional[str] = None
        self.split_tunnel_all_user: Optional[bool] = None
        # Which value of SplitTunneling we ourselves set in this profile.
        # None — we did not change anything (the profile was already in the
        # required state, see the already=True branch in prepare_split_tunnel).
        #
        # Needed to distinguish "our change is still in effect" from
        # "the profile has since been changed externally" (the user via
        # Windows Settings, a script, another program). On restore we read the
        # actual value and, if it does not match what we applied, do not write —
        # otherwise we might overwrite someone else's change. The same
        # principle is used in self_heal_client_on_startup()
        # (vpn_client_state.json), where ifIndex/route_ips filter out
        # "a fresh user session" from "our old one".
        self.applied_split_tunneling: Optional[bool] = None
        self._lock = threading.Lock()
        self._monitor_lock = threading.Lock()
        self._monitor_started = False
        self._stop = threading.Event()
        # A paired identity label to parent_pid: the FILETIME of the creation
        # of the process that launched this helper via UAC. Protects
        # parent authorization (register_client, shutdown, network ops,
        # routes without owner) from PID reuse by the operating system — the
        # same technique that is already used in vpn_client_state.json (see
        # _process_start_time / self_heal). None (old client / non-Windows) —
        # we fall back to _process_alive() without comparison, i.e. we behave
        # as before this change.
        self.parent_start_time: Optional[int] = (
            int(parent_start_time) if isinstance(parent_start_time, int) else None
        )

    def _parent_alive(self) -> bool:
        """True if the process parent_pid is alive and (when start_time is
        available) is the same process that launched the helper.

        Purpose: the decision "when the helper should exit if the parent has
        disappeared and no owner is registered" (see _monitor_loop). Here,
        with parent_start_time=None, we DELIBERATELY return True if
        _process_alive(pid) — because the helper must not kill itself just
        because it could not read the timestamp; let it live while the parent
        is alive.

        WARNING: this function must NOT be used for granting parent privileges
        (register_client, shutdown, add_routes via the parent path, network
        ops) — with parent_start_time=None it does not distinguish the real
        parent from an unrelated process to which Windows reused the PID
        after the GUI died. For authorization use _parent_authorized()
        (fail-closed).
        """
        pid = self.parent_pid
        if pid is None or not _process_alive(pid):
            return False
        if self.parent_start_time is None:
            return True
        actual = _process_start_time(pid)
        return actual is not None and actual == self.parent_start_time

    def _parent_authorized(self) -> bool:
        """True if parent_pid is sufficiently trustworthy for granting
        parent privileges.

        Unlike _parent_alive(), it also requires the parent's identity to be
        confirmed via start_time: with parent_start_time=None the PID-reuse
        protection degrades to "a process with this PID is alive", and we do
        not know whether it is the same process that launched us. Fail-closed:
        the inability to check is not a reason to assume there is nothing to
        check.

        Does not take the lock: reading self.parent_pid /
        self.parent_start_time is atomic under the GIL, and the
        _parent_alive() call is also read-only with respect to these fields.
        Can be called both under self._lock (from
        _*_authorized_unlocked) and without it.
        """
        if self.parent_start_time is None:
            return False
        return self._parent_alive()

    def start_monitor(self) -> None:
        with self._monitor_lock:
            if not self._monitor_started:
                self._monitor_started = True
                threading.Thread(
                    target=self._monitor_loop,
                    daemon=True,
                    name="vpn-helper-monitor",
                ).start()

    def register_client(self, pid: int, connection_name: str, all_user: Optional[bool] = None,
                         pipe_client_pid: Optional[int] = None) -> dict:
        if pipe_client_pid is not None and int(pid) != int(pipe_client_pid):
            self.log.warning(
                "register_client rejected: claimed PID=%s, PID on the pipe=%s",
                pid, pipe_client_pid,
            )
            return {
                "ok": False,
                "error": "PID does not match the process at the other end of the pipe",
            }
        if IS_WINDOWS and not _process_same_user(pid):
            self.log.warning(
                "register_client rejected: PID=%s belongs to another user",
                pid,
            )
            return {"ok": False, "error": "The process belongs to another user"}
        with self._lock:
            if (self.owner_pid is not None and
                    (self.owner_pid != pid or self.owner_connection_name != connection_name or
                     self.owner_all_user != all_user)):
                return {"ok": False, "error": "Another client already owns the VPN session"}
            if self.owner_pid is None and not self._register_authorized_unlocked(pid):
                # We distinguish three rejection cases (in priority order):
                #   1. parent_pid is dead — the helper is orphaned and must exit;
                #   2. parent_start_time is missing — PID-reuse protection is
                #      unavailable, authorization is denied fail-closed;
                #   3. parent_pid is alive and protection is in effect, but the
                #      caller is not it — a registration-hijack attempt.
                parent_dead = (
                    self.parent_pid is not None
                    and not self._parent_alive()
                )
                if parent_dead:
                    self.log.warning(
                        "register_client from PID=%s rejected: parent PID=%s "
                        "is dead, the helper is orphaned — shutting down "
                        "(UAC boundary protection)",
                        pid, self.parent_pid,
                    )
                    # Release resources and terminate the elevated process.
                    # _exit_helper() does not return.
                    self._remove_routes_unlocked()
                    self._restore_split_tunneling_unlocked()
                    self._exit_helper()
                    # Control never reaches here.
                if self.parent_start_time is None:
                    # A separate branch from the "hijack attempt": here the
                    # parent may be alive and real, but we cannot prove it.
                    # The message must be actionable — the user needs to
                    # restart the helper with a client that passes
                    # --parent-start-time.
                    self.log.error(
                        "register_client from PID=%s rejected: helper was "
                        "started without --parent-start-time (PID-reuse "
                        "protection unavailable). All parent-authorized "
                        "commands are DENIED until the helper is restarted "
                        "with start_time.",
                        pid,
                    )
                    return {
                        "ok": False,
                        "error": (
                            "VPN helper was started without PID-reuse "
                            "protection (missing --parent-start-time); "
                            "parent authorization is denied until the helper "
                            "is restarted with start_time"
                        ),
                    }
                self.log.warning(
                    "register_client rejected: PID=%s is trying to register while "
                    "parent_pid=%s is alive — likely a registration hijack attempt",
                    pid, self.parent_pid,
                )
                return {"ok": False, "error": "Registration unavailable: the helper is already bound to another process"}

            # (3) If an unrestored SplitTunneling is already "pending" for
            # another profile (prepare_split_tunnel was called but restore
            # was not), we do not allow registering a different profile: this
            # would leave the previous profile with SplitTunneling toggled
            # forever. The client must explicitly call restore_split_tunnel
            # and retry registration.
            if (
                self.split_tunnel_connection_name is not None
                and (connection_name != self.split_tunnel_connection_name
                     or all_user != self.split_tunnel_all_user)
            ):
                self.log.warning(
                    "register_client rejected: profile %r (all_user=%s) does "
                    "not match the pending SplitTunneling change for %r "
                    "(all_user=%s) — call restore_split_tunnel first",
                    connection_name, all_user,
                    self.split_tunnel_connection_name, self.split_tunnel_all_user,
                )
                return {
                    "ok": False,
                    "error": "register_client: a SplitTunneling change is "
                             "pending for another VPN profile; "
                             "call restore_split_tunnel first",
                }

            # Without the owner-field assignments, register_client would log
            # success and return {"ok": True}, but owner_pid would remain None.
            # As a result all subsequent commands requiring
            # _authorized_client (remove_default_route, release_and_disconnect,
            # add_routes via the owner path) would be rejected as "The client
            # is not the owner of the VPN session", even though
            # register_client had just succeeded.
            self.owner_pid = pid
            self.owner_connection_name = connection_name
            self.owner_all_user = all_user
            # If the helper was reused in the same GUI session — PID is the
            # same; if it happens to be a new GUI (rare reuse) — we switch
            # the observation.
            self.parent_pid = pid
        self.log.info(
            "Client registered for monitoring: PID=%s, VPN=%r",
            pid, connection_name
        )
        # Invariant: a successful register_client must set owner_pid.
        # Without this check, an accidental deletion of the line
        # `self.owner_pid = pid` above would not cause a registration error,
        # but all subsequent owner-only commands (remove_default_route,
        # release_and_disconnect) would be rejected as "not the owner",
        # which looks like an ownership problem rather than a bug in
        # register_client.
        assert self.owner_pid == pid, (
            "register_client returned ok but did not set owner_pid — "
            "check for a missing `self.owner_pid = pid` assignment"
        )
        self.start_monitor()
        return {"ok": True}

    def unregister_client(self, client_pid: Optional[int] = None) -> dict:
        if self.owner_pid is not None and not self._authorized_client(client_pid):
            return {"ok": False, "error": "The client is not the owner of the VPN session"}
        self.log.info("Client removed from monitoring (normal VPN disconnect)")
        with self._lock:
            self.owner_pid = None
            self.owner_connection_name = None
            self.owner_all_user = None
        return {"ok": True}

    def _monitor_loop(self) -> None:
        """Background thread: waits for the GUI process to exit.

        We watch parent_pid (passed at helper startup), or, if it is
        absent, owner_pid after register_client. WaitForSingleObject on a
        process handle is not subject to PID reuse — unlike periodic
        OpenProcess(pid).

        If the GUI disappears without a shutdown — we remove routes,
        disconnect the VPN (if the session was ours) and terminate this
        elevated process. Otherwise after "End task" in Task Manager an
        orphan python.exe remains: the UAC process is not part of the GUI's
        process tree.
        """
        if not IS_WINDOWS:
            return
        watch_handle: Optional[int] = None
        watch_pid: Optional[int] = None
        try:
            while not self._stop.is_set():
                with self._lock:
                    pid = self.parent_pid or self.owner_pid
                if pid is None:
                    time.sleep(0.5)
                    continue

                # Self-shutdown: parent is dead AND no owner is registered —
                # the helper belongs to no one and must not wait for
                # "adoption". We exit ourselves before anyone
                # can connect to the pipe and call register_client()
                # (see _register_authorized_unlocked: registration in this
                # state is forbidden, but the mere fact of a live High-IL process
                # with an open pipe is already a UAC-bypass surface, even if
                # destructive commands are unavailable).
                #
                # This is not a race with register_client: register_client checks
                # parent_pid is alive under the same self._lock, and we take
                # pid under it as well. If between taking pid and this check
                # parent came back to life — it is either the same PID reused
                # by another process (unlikely and protected by GetProcessTimes
                # in _register_authorized_unlocked), or a scenario in which
                # _on_gui_died has already run; both are safe.
                if (
                    self.owner_pid is None
                    and self.parent_pid is not None
                    and not self._parent_alive()
                ):
                    self.log.warning(
                        "Parent process PID=%s is dead (or the PID was reused "
                        "by an unrelated process) and no owner is "
                        "registered — the helper is orphaned and shuts down "
                        "instead of waiting to be adopted (UAC boundary protection)",
                        self.parent_pid,
                    )
                    self._remove_routes_unlocked()
                    self._restore_split_tunneling_unlocked()
                    self._exit_helper()
                    return

                if watch_pid != pid:
                    if watch_handle:
                        try:
                            _kernel32.CloseHandle(watch_handle)
                        except Exception:
                            self.log.debug("CloseHandle(watch_handle) failed on PID change", exc_info=True)
                        watch_handle = None
                    watch_pid = pid
                    watch_handle = _open_process_watch_handle(pid)
                    if not watch_handle:
                        if not _process_alive(pid):
                            if self._on_gui_died(pid):
                                return
                            watch_pid = None
                            continue
                        time.sleep(2.0)
                        watch_pid = None
                        continue

                # On this line watch_handle is guaranteed to be non-None:
                # all branches of `if not watch_handle:` above end with
                # return/continue.
                assert watch_handle is not None
                exited = _wait_process_handle(watch_handle, 2000)
                if exited is True:
                    if self._on_gui_died(pid):
                        return
                    watch_pid = None
                    continue
                if exited is None:
                    # WaitForSingleObject failed — check via GetExitCode.
                    if not _process_alive(pid):
                        if self._on_gui_died(pid):
                            return
                        watch_pid = None
                        continue
        finally:
            if watch_handle:
                try:
                    _kernel32.CloseHandle(watch_handle)
                except Exception:
                    self.log.debug("CloseHandle(watch_handle) failed on leaving _monitor_loop", exc_info=True)

    def _on_gui_died(self, pid: int) -> bool:
        """True — the helper is exiting (or os._exit has already been called). False — false alarm."""
        with self._lock:
            # The observed PID might have changed (new register_client) while
            # we were handling the death of the old one — then we do not
            # touch the live one.
            current = self.parent_pid or self.owner_pid
            if current is not None and int(current) != int(pid):
                if _process_alive(current):
                    self.log.info(
                        "Watched PID changed %s -> %s and is alive — not exiting",
                        pid, current,
                    )
                    return False
            name = self.owner_connection_name
            all_user = self.owner_all_user
            self.owner_pid = None
            self.owner_connection_name = None
            self.owner_all_user = None
            self.parent_pid = None
            try:
                self._remove_routes_unlocked()
            except Exception:
                self.log.exception("remove_routes() failed during emergency cleanup")
            try:
                self._restore_split_tunneling_unlocked()
            except Exception:
                self.log.exception("SplitTunneling restore failed during emergency cleanup")
        self.log.warning(
            "GUI process PID=%s disappeared without an explicit shutdown — "
            "forcibly disconnecting VPN (if the session is ours) and stopping the helper "
            "(the GUI was probably killed via Task Manager)",
            pid,
        )
        if name:
            try:
                ok = rasdial_disconnect(name, all_user=all_user)
                self.log.info("rasdial_disconnect(%r) -> %s", name, ok)
            except Exception:
                self.log.exception("rasdial_disconnect() failed during emergency cleanup")
        self._exit_helper()
        return True

    def _exit_helper(self) -> None:
        """Forcefully terminates the elevated process after emergency cleanup.

        The main thread is most likely blocked in ConnectNamedPipe, and the
        daemon monitor will not keep the process alive — but it will not wake
        the main thread either. os._exit bypasses this: the OS closes the
        pipe handles and the pipe name is released. sys.exit() from this
        thread would only raise SystemExit here and leave the helper alive.
        """
        self.log.info("Elevated helper is shutting down together with the GUI")
        self._stop.set()
        for handler in list(self.log.handlers):
            try:
                handler.flush()
            except Exception:
                pass
        os._exit(0)

    def _routes_authorized_unlocked(self, client_pid: Optional[int]) -> bool:
        """Routes can be changed by the session owner; if there is no owner
        yet — we allow the GUI that launched the helper (parent_pid). This
        is the "VPN already raised by the user" path: host routes are
        needed, but register_client/disconnect are not.

        In the parent branch, not only a PID match is required but also a
        live authorized parent (see _parent_authorized): without this check
        the helper would accept add_routes from any process to which Windows
        gave the parent PID after the GUI died — that is, arbitrary /32
        routes with administrator privileges without a new UAC. Fail-closed
        with parent_start_time=None.

        Call only under self._lock.
        """
        if client_pid is None:
            return False
        if self.owner_pid is not None:
            return int(client_pid) == int(self.owner_pid)
        return (
            self.parent_pid is not None
            and int(client_pid) == int(self.parent_pid)
            and self._parent_authorized()
        )

    def _authorized_client(self, client_pid: Optional[int]) -> bool:
        with self._lock:
            return (client_pid is not None and self.owner_pid is not None and
                    int(client_pid) == int(self.owner_pid))

    def _shutdown_authorized_unlocked(self, client_pid: Optional[int]) -> bool:
        """Like _authorized_client, but for the shutdown command: it
        additionally allows it for the process that launched this elevated
        helper via UAC (self.parent_pid), even if the VPN session is not yet
        registered (owner_pid is None) or has already been properly released
        by unregister_client.

        owner_pid is None must not by itself authorize shutdown of any
        process of the same user (_process_same_user() in _handle_client
        filters only other users, but not other processes of THE SAME user).
        In the window between helper start (it answers ping immediately) and
        a separate connection with register_client ("one command = one
        connection", see the file docstring), an arbitrary process of the
        same user could be the first to connect to the pipe and send
        shutdown, killing the helper before the real GUI.

        parent_pid is a suitable anchor: register_client/unregister_client do
        not touch it, and it remains reliable for the entire helper lifetime
        (cleared only in _on_gui_died, right before process exit).

        With parent_start_time=None authorization is rejected (see
        _parent_authorized): shutdown performs destructive operations
        (_remove_routes_unlocked, clearing ownership, restoring
        SplitTunneling), and opening them to a process whose identity we
        cannot confirm is unacceptable. The helper in this state will exit on
        its own when the parent disappears (see _monitor_loop).

        Call only under self._lock (same as _remove_routes_unlocked):
        otherwise owner_pid/parent_pid may change between the check and the
        use of the result.
        """
        if client_pid is None:
            return False
        if self.owner_pid is not None:
            return int(client_pid) == int(self.owner_pid)
        return (
            self.parent_pid is not None
            and int(client_pid) == int(self.parent_pid)
            and self._parent_authorized()
        )

    def _network_ops_authorized_unlocked(self, client_pid: Optional[int]) -> bool:
        """Network commands (arp_flush, ping_probe, adapter_restart).

        Authorization: the session owner (owner_pid), if registered;
        otherwise — the process that launched the helper via UAC
        (parent_pid).

        Previously, the docstring claimed that the parent is allowed even
        when an owner is already registered. This does not match either the
        code or the architecture: register_client() is called only from the
        parent (_register_authorized_unlocked checks client_pid == parent_pid
        AND _parent_authorized()), and it is the same call that assigns
        self.parent_pid = pid. Therefore after registration owner_pid and
        parent_pid always point to the same process. The "owner vs parent"
        distinction in this state is illusory — allowing the parent with a
        registered owner would allow exactly the same client. The docstring
        has been brought in line with actual behaviour; the code was not
        changed.

        This function currently differs from _routes_authorized_unlocked only
        in purpose (network operations vs routes) — the set of allowed
        identities is the same in both.

        Fail-closed: client_pid is None (pipe PID not determined), an
        "orphaned" helper (parent is dead, no owner is registered) and
        parent_start_time=None (parent identity not confirmed, see
        _parent_authorized) are all rejected — the commands are destructive
        (adapter_restart brings down a network adapter), and losing hygiene
        in a surviving helper is harmless (best-effort).

        Call only under self._lock.
        """
        if client_pid is None:
            return False
        if self.owner_pid is not None:
            return int(client_pid) == int(self.owner_pid)
        return (
            self.parent_pid is not None
            and int(client_pid) == int(self.parent_pid)
            and self._parent_authorized()
        )

    def check_network_ops(self, client_pid: Optional[int], cmd: str) -> Optional[dict]:
        """None — the command is allowed; otherwise a ready-made rejection response."""
        with self._lock:
            allowed = self._network_ops_authorized_unlocked(client_pid)
            owner, parent = self.owner_pid, self.parent_pid
            parent_start_time_missing = self.parent_start_time is None
        if allowed:
            return None
        detail = ""
        if (
            owner is None
            and parent is not None
            and parent_start_time_missing
            and client_pid is not None
            and int(client_pid) == int(parent)
        ):
            # The most common reason for rejection in this state: the client
            # is the real parent, but the helper cannot prove it without
            # start_time. A separate wording in the log saves us from a
            # false "this is not our client" diagnosis when investigating an
            # incident.
            detail = (
                " (helper started without --parent-start-time — parent "
                "authorization disabled by design; restart the helper to "
                "restore network ops)"
            )
        self.log.warning(
            "Command %s rejected: client_pid=%s is neither owner (%s) nor "
            "parent (%s)%s",
            cmd, client_pid, owner, parent, detail,
        )
        return {"ok": False, "error": f"{cmd}: client is not authorized"}

    def _register_authorized_unlocked(self, client_pid: Optional[int]) -> bool:
        """A client can register as the new owner (when owner_pid is None)
        only if it is the parent_pid — the process that launched this
        elevated helper via UAC.

        The check goes through _parent_authorized() (fail-closed): when
        start_time is absent, the helper cannot distinguish the real parent
        from an unrelated process to which Windows reused the PID after the
        GUI died. In this state, parent authorization is completely disabled
        — register_client and all owner-only commands will be rejected, the
        helper will live until the parent dies (see _monitor_loop) and then
        exit without having accepted a single destructive command.

        The "parent is dead" check is handled separately in register_client:
        there the decision to terminate the helper as orphaned is made.

        Call only under self._lock.
        """
        parent_pid = self.parent_pid
        if parent_pid is None or not self._parent_authorized():
            return False
        return client_pid is not None and int(client_pid) == int(parent_pid)

    def prepare_split_tunnel(self, connection_name: str, all_user: Optional[bool],
                             client_pid: Optional[int]) -> dict:
        """Before rasdial: enables SplitTunneling for the profile, saving the
        previous value.

        Without this, with a full-tunnel profile Windows installs 0.0.0.0/0
        via the VPN with a better metric — and all outgoing traffic goes into
        the tunnel, even if the physical default formally remains in the
        table. Allowed for parent_pid (the helper has no owner yet) or the
        current owner.
        """
        # Validate the name before any actions (the same policy as in
        # get/set_vpn_split_tunneling).
        try:
            connection_name = _validate_vpn_name(connection_name)
        except ValueError as e:
            return {"ok": False, "error": f"prepare_split_tunnel: {e}"}

        with self._lock:
            allowed = (
                (client_pid is not None and self.parent_pid is not None
                 and int(client_pid) == int(self.parent_pid))
                or self._routes_authorized_unlocked(client_pid)
            )
            if not allowed:
                return {"ok": False, "error": "prepare_split_tunnel: client is not authorized"}

            # (1) If the session is already registered — we lock the profile.
            # An authorized client must not change the SplitTunneling of an
            # arbitrary VPN profile different from the one declared by the
            # owner.
            if self.owner_connection_name is not None and (
                connection_name != self.owner_connection_name
                or all_user != self.owner_all_user
            ):
                self.log.warning(
                    "prepare_split_tunnel rejected: requested %r (all_user=%s) "
                    "does not match the registered session %r (all_user=%s)",
                    connection_name, all_user,
                    self.owner_connection_name, self.owner_all_user,
                )
                return {
                    "ok": False,
                    "error": "prepare_split_tunnel: profile does not match the "
                             "registered VPN session",
                }

            # (2) The helper holds SplitTunneling for only one profile at a
            # time — otherwise the previous value of the previous profile is
            # lost, and its SplitTunneling remains enabled forever.
            if (
                self.split_tunnel_connection_name is not None
                and (connection_name != self.split_tunnel_connection_name
                     or all_user != self.split_tunnel_all_user)
            ):
                self.log.warning(
                    "prepare_split_tunnel rejected: %r (all_user=%s) already has "
                    "a pending SplitTunneling change; refusing to touch a "
                    "different profile %r (all_user=%s)",
                    self.split_tunnel_connection_name, self.split_tunnel_all_user,
                    connection_name, all_user,
                )
                return {
                    "ok": False,
                    "error": "prepare_split_tunnel: another VPN profile is already "
                             "pending a SplitTunneling change",
                }

        prev = get_vpn_split_tunneling(connection_name, all_user=all_user)
        if prev is True:
            self.log.info(
                "SplitTunneling already enabled for %r — no need to change the profile",
                connection_name,
            )
            with self._lock:
                # We do not overwrite someone else's saved value if we were
                # already preparing this same profile.
                if self.saved_split_tunneling is None:
                    self.saved_split_tunneling = True
                    self.split_tunnel_connection_name = connection_name
                    self.split_tunnel_all_user = all_user
            return {"ok": True, "already": True, "previous": True}

        ok, err = set_vpn_split_tunneling(connection_name, True, all_user=all_user)
        if not ok:
            self.log.error(
                "Failed to enable SplitTunneling for %r: %s",
                connection_name, err,
            )
            return {"ok": False, "error": f"Set-VpnConnection SplitTunneling: {err}"}

        with self._lock:
            self.saved_split_tunneling = prev  # False or None
            # We remember that it was WE who set True. On restore we will
            # compare the current profile value with this — if it is already
            # different, the profile was changed externally after us, and we
            # must not overwrite someone else's change.
            self.applied_split_tunneling = True
            self.split_tunnel_connection_name = connection_name
            self.split_tunnel_all_user = all_user
        self.log.info(
            "SplitTunneling enabled for %r (was: %s) — the full-tunnel default "
            "should no longer be installed on connect",
            connection_name, prev,
        )
        return {"ok": True, "already": False, "previous": prev}

    def _restore_split_tunneling_unlocked(self) -> None:
        """Restore the previous SplitTunneling if we changed it. Without the
        lock from outside.

        Before writing, it compares the current profile value with the one we
        ourselves set (applied_split_tunneling). If it is already different,
        the profile has been changed by someone else since then, and we must
        not overwrite that change. If the current state cannot be read
        (None — "I don't know"), the state is NOT cleared, so that a repeated
        call (e.g. from disconnect_and_unroute after a failed
        restore-at-connect, or from shutdown) can resolve the situation.
        """
        name = self.split_tunnel_connection_name
        all_user = self.split_tunnel_all_user
        prev = self.saved_split_tunneling
        applied = self.applied_split_tunneling

        def _clear() -> None:
            self.saved_split_tunneling = None
            self.applied_split_tunneling = None
            self.split_tunnel_connection_name = None
            self.split_tunnel_all_user = None

        if name is None or prev is None:
            # Nothing to restore (state was not set, or the initial value
            # could not be read — see the comment about prev=None in
            # prepare_split_tunnel).
            _clear()
            return
        if prev is True:
            # The profile was already True before us — we did not touch it,
            # nothing to restore.
            _clear()
            return

        # prev is False — we set True, and want to return False. We check
        # the actual state BEFORE writing.
        if applied is not None:
            current = get_vpn_split_tunneling(name, all_user=all_user)
            if current is None:
                # "I don't know" != "changed by someone else": we do not
                # treat this as a state change and do not touch the state, so
                # that the next restore call can resolve it (e.g. if
                # PowerShell failed just once).
                self.log.warning(
                    "Cannot determine the current SplitTunneling for %r — "
                    "postponing the restore (state kept for a later attempt)",
                    name,
                )
                return
            if current != applied:
                # The profile was changed after us (the user via Windows
                # Settings, a script, another program). We do not overwrite
                # someone else's change.
                self.log.info(
                    "Not restoring SplitTunneling for %r: current value %s "
                    "differs from the value we set (%s) — the profile was "
                    "changed by someone else; leaving it as is",
                    name, current, applied,
                )
                _clear()
                return

        # Standard path: restore prev.
        _clear()
        ok, err = set_vpn_split_tunneling(name, bool(prev), all_user=all_user)
        if ok:
            self.log.info(
                "SplitTunneling=%s restored for %r", prev, name,
            )
        else:
            self.log.error(
                "Failed to restore SplitTunneling=%s for %r: %s",
                prev, name, err,
            )

    def restore_split_tunnel(self, client_pid: Optional[int] = None) -> dict:
        """Restores the saved SplitTunneling (after a failed connect)."""
        with self._lock:
            # WARNING: self._lock is already held here, and it is NOT
            # reentrant (threading.Lock). Therefore _authorized_client()
            # (which takes the same lock) must not be called — the call would
            # hang forever for any client that did not pass the two checks
            # above, and would block the entire helper. A separate "client is
            # the owner" check is not needed either: 
            # _routes_authorized_unlocked() already allows the session owner.
            allowed = (
                (client_pid is not None and self.parent_pid is not None
                 and int(client_pid) == int(self.parent_pid))
                or self._routes_authorized_unlocked(client_pid)
            )
            if not allowed and self.saved_split_tunneling is None:
                return {"ok": True, "restored": False}
            if not allowed:
                return {"ok": False, "error": "restore_split_tunnel: client is not authorized"}
            self._restore_split_tunneling_unlocked()
        return {"ok": True, "restored": True}

    def release_and_disconnect(self, client_pid: Optional[int]) -> dict:
        """Releases ownership, removes routes AND disconnects the VPN — via
        a single pipe command, inside the elevated process itself.

        Disconnecting the VPN via rasdial (/DISCONNECT) does not require
        saved credentials (see the module docstring and _on_gui_died) — the
        elevated helper performs it itself BEFORE forgetting
        connection_name.
        """
        if not self._authorized_client(client_pid):
            return {"ok": False, "owned": False, "error": "The client is not the owner of the VPN session"}
        with self._lock:
            name = self.owner_connection_name
            all_user = self.owner_all_user
            routes_result = self._remove_routes_unlocked()
            self.owner_pid = None
            self.owner_connection_name = None
            self.owner_all_user = None
            self._restore_split_tunneling_unlocked()
        self.log.info("Client PID=%s released from VPN %r (release_and_disconnect)", client_pid, name)
        if not name:
            # Ownership formally existed, but without a saved
            # connection_name there is nothing to disconnect (should not
            # happen normally).
            return {"ok": True, "owned": True, "routes_removed": bool(routes_result.get("ok", True))}
        try:
            vpn_disconnected = rasdial_disconnect(name, all_user=all_user)
        except Exception:
            self.log.exception("release_and_disconnect: rasdial_disconnect(%r) raised an exception", name)
            vpn_disconnected = False
        if not vpn_disconnected:
            self.log.error(
                "release_and_disconnect: failed to disconnect VPN %r — "
                "the client will handle it itself if it receives vpn_disconnected=False",
                name,
            )
        return {
            "ok": bool(routes_result.get("ok", True)) and vpn_disconnected,
            "owned": True,
            "connection_name": name,
            "all_user": all_user,
            "routes_removed": bool(routes_result.get("ok", True)),
            "vpn_disconnected": vpn_disconnected,
        }

    def add_routes(self, routes: List[Tuple[str, int, str]]) -> dict:
        """Adds routes, reinstalling them if necessary.

        IMPORTANT: presence of an IP in self.routes must not be treated as a sign
        of a working route. self.routes lives in the memory of this elevated process,
        which survives computer sleep/hibernate and is not restarted together with
        the main program. If during that time the VPN tunnel was re-established
        (by automatic Windows RAS reconnect or via connect_and_route() after wake),
        it very often gets a NEW ifIndex and/or a new local IP (gateway for ROUTE_EXE),
        and the old entry in the routing table points at an interface that no longer
        exists. Traffic goes nowhere (in the GUI this looks like "Connect timed out"
        on all channels after wake).

        Therefore: if an entry already exists for an IP but with a different
        ifIndex/gateway — the old (non-working) route is deleted and re-added for
        the current interface. If ifIndex/gateway match the cached ones, an
        additional check verifies that the entry is physically present in the
        routing table (see _unicast_route_exists): Windows sometimes loses
        individual routes on its own, without an interface change. Only then is
        the route considered ready and left untouched.
        """
        if len(routes) > MAX_ROUTES_PER_REQUEST:
            self.log.warning(
                "add_routes: request rejected — %d routes in one call "
                "(maximum %d)", len(routes), MAX_ROUTES_PER_REQUEST,
            )
            return {
                "ok": False,
                "error": f"Too many routes in one request: {len(routes)} "
                         f"(maximum {MAX_ROUTES_PER_REQUEST})",
                "added": [],
            }
        added: List[str] = []
        errors: List[str] = []
        # caller PID is substituted by the dispatcher (_handle_client) via
        # _client_context.
        client_pid = getattr(_client_context, "pid", None)
        with self._lock:
            if not self._routes_authorized_unlocked(client_pid):
                return {"ok": False, "error": "The client is not the owner of the VPN session", "added": []}

            # --- Validation before any route.exe/PowerShell execution ---
            # The helper is elevated: trusting arbitrary ip/gateway/if_index
            # from the request just because the client is authorized as the
            # session owner is not wise — authorization does not mean that
            # every specific field in the request is meaningful (neither a
            # buggy client nor a compromised one should be able to ask the
            # elevated helper to execute an arbitrary command).
            #
            # If the name of the current VPN session is known
            # (owner_connection_name, i.e. the client has passed
            # register_client) — we bind if_index strictly to the actual
            # adapter of that session. If the session is not yet registered
            # (the VPN was already raised by the user, routes are added from
            # parent_pid — see _routes_authorized_unlocked), the name is
            # unavailable; then we check at least that if_index corresponds
            # to a really existing network adapter.
            expected_if_index: Optional[int] = None
            known_indexes: Optional[set] = None  # None = "I don't know", not "empty"
            if self.owner_connection_name:
                lookup_state, expected_if_index, lookup_ipv4 = _lookup_interface_by_name(
                    self.owner_connection_name
                )
                if (
                    lookup_state is not InterfaceLookupState.FOUND
                    or expected_if_index is None
                ):
                    # IFACE_UNDETERMINED_MARKER is kept in both cases: the
                    # client uses it as a signal "do not start a heavy soft
                    # recovery over this" — and the reaction (do not touch
                    # the network, show the user) is the same regardless of
                    # what exactly happened with the API.
                    explanation = _explain_lookup_failure(
                        self.owner_connection_name,
                        lookup_state, expected_if_index, lookup_ipv4,
                    )
                    self.log.error(
                        "add_routes: %s — rejecting all routes of the request",
                        explanation,
                    )
                    return {
                        "ok": False,
                        "error": (
                            f"VPN {IFACE_UNDETERMINED_MARKER}: "
                            f"{self.owner_connection_name!r} — {explanation}"
                        ),
                        "added": [],
                    }
            else:
                known_indexes = _known_if_indexes()
                if known_indexes is None:
                    # Could not read the adapter table — we do not reject
                    # the request on this basis. Same semantics as for
                    # _unicast_route_exists: "I don't know" ≠ "no".
                    self.log.warning(
                        "add_routes: could not enumerate adapters — "
                        "if_index validation against the existing list is skipped",
                    )

            valid_routes: List[Tuple[str, int, str]] = []
            for raw_ip, raw_if_index, raw_gateway in routes:
                if not _is_valid_route_ip(raw_ip):
                    errors.append(f"{raw_ip}: invalid IPv4 destination address")
                    continue
                if not _is_valid_route_ip(raw_gateway):
                    errors.append(f"{raw_ip}: invalid IPv4 gateway address {raw_gateway!r}")
                    continue
                if not _is_valid_if_index(raw_if_index):
                    errors.append(f"{raw_ip}: invalid if_index {raw_if_index!r}")
                    continue
                if_index = int(raw_if_index)
                if expected_if_index is not None and if_index != expected_if_index:
                    self.log.warning(
                        "add_routes: route %s rejected — if_index=%s does not "
                        "match the actual ifIndex=%s of VPN session %r",
                        raw_ip, if_index, expected_if_index, self.owner_connection_name,
                    )
                    errors.append(f"{raw_ip}: if_index does not match the current VPN session")
                    continue
                if known_indexes is not None and if_index not in known_indexes:
                    self.log.warning(
                        "add_routes: route %s rejected — if_index=%s does not "
                        "match any existing adapter",
                        raw_ip, if_index,
                    )
                    errors.append(f"{raw_ip}: if_index does not match an existing adapter")
                    continue
                valid_routes.append((raw_ip, if_index, raw_gateway))

            for ip, if_index, gateway in valid_routes:
                cached = self.routes.get(ip)
                if cached is not None:
                    cached_if_index, cached_gateway = cached
                    if (cached_if_index, cached_gateway) == (if_index, gateway) and \
                            _unicast_route_exists(ip, if_index):
                        # Same interface/gateway, and the route is physically in place.
                        added.append(ip)
                        continue
                    # Interface/gateway changed (the tunnel was re-raised
                    # after sleep/hibernation) — or the route disappeared
                    # from the table on its own. The old entry is already
                    # useless either way — we delete it (best effort) and
                    # reinstall it.
                    self.log.info(
                        "Route %s: stale entry (ifIndex=%s, gw=%s) -> "
                        "reinstalling for ifIndex=%s, gw=%s",
                        ip, cached_if_index, cached_gateway, if_index, gateway,
                    )
                    try:
                        delete_route(ip, cached_if_index, cached_gateway)
                    except Exception:
                        self.log.exception(
                            "Failed to delete the stale route %s", ip
                        )
                    del self.routes[ip]
                if add_route(ip, if_index, gateway):
                    self.routes[ip] = (if_index, gateway)
                    added.append(ip)
                    self.log.info(
                        "Route added: %s via ifIndex=%s (gateway=%s)",
                        ip, if_index, gateway,
                    )
                else:
                    errors.append(f"{ip}: failed to add route")
        return {
            "ok": bool(added) or not errors,
            "error": "; ".join(errors) if errors else None,
            "added": added,
        }

    def _remove_routes_unlocked(self) -> dict:
        errors = []
        for ip, (if_index, gateway) in list(self.routes.items()):
            if delete_route(ip, if_index, gateway):
                self.log.info("Route removed: %s", ip)
                self.routes.pop(ip, None)
            else:
                errors.append(ip)
                self.log.error("Failed to remove route: %s", ip)
        return {
            "ok": not errors,
            "error": "; ".join(f"{ip}: failed to remove route" for ip in errors) if errors else None,
        }

    def remove_routes(self, client_pid: Optional[int] = None) -> dict:
        with self._lock:
            if not self._routes_authorized_unlocked(client_pid):
                return {"ok": False, "error": "The client is not the owner of the VPN session"}
            return self._remove_routes_unlocked()

    def remove_default_route(
        self,
        if_index: int,
        pre_defaults_v4: Optional[List[Dict[str, Any]]] = None,
        pre_defaults_v6: Optional[List[Dict[str, Any]]] = None,
        watch_seconds: float = DEFAULT_ROUTE_WATCH_SECONDS,
    ) -> dict:
        """Forced split-tunnel: always removes 0.0.0.0/0 and ::/0 via the VPN.
        Returns a best-effort result. The ok=True field means "the command
        was processed without internal errors", but NOT "split-tunnel is
        actually in effect": Windows/RAS may restore 0.0.0.0/0 via the
        tunnel after our check has already run. The aggregated assessment
        of the state reached is state_ok (postcondition_ok AND
        has_other_default AND not restore_errors). Details are in the
        individual fields postcondition_ok / has_other_default /
        restore_errors / metric_set.

        1) Always remove the default via the VPN if_index (no longer skip the
           "only one").
        2) If after removal no other IPv4 default remains — restore the
           snapshot taken by the client BEFORE rasdial_connect.
        3) Set a high InterfaceMetric on the VPN adapter — if RAS still
           returns a default via the tunnel, the physical gateway will
           remain preferable.
        """
        client_pid = getattr(_client_context, "pid", None)
        if not self._authorized_client(client_pid):
            return {"ok": False, "error": "The client is not the owner of the VPN session"}

        if not _is_valid_if_index(if_index):
            return {"ok": False, "error": f"Invalid if_index: {if_index!r}"}
        if_index = int(if_index)

        # The client is authorized as the owner of the VPN session — but authorization
        # of the client is not the same as trusting the concrete value of
        # if_index that it sent in this request. remove_default_route
        # is performed by the elevated helper and removes 0.0.0.0/0 via the given
        # interface; if the helper blindly trusted if_index, an authorized
        # (but buggy/compromised) client could theoretically
        # ask to remove the default route from an arbitrary interface, not
        # only from its own VPN adapter's gateway. Therefore here we ourselves compute
        # the actual IfIndex of the VPN-session adapter that the
        # current owner is bound to (by the name saved in register_client), and
        # accept only a matching value.
        expected_name = self.owner_connection_name
        if not expected_name:
            self.log.error(
                "remove_default_route: owner_connection_name is not set "
                "although client PID=%s is authorized as owner — rejecting the request "
                "with if_index=%s (should not happen normally)",
                client_pid, if_index,
            )
            return {"ok": False, "error": "Helper internal state does not match expectations"}

        lookup_state, expected_if_index, lookup_ipv4 = _lookup_interface_by_name(expected_name)
        if lookup_state is not InterfaceLookupState.FOUND or expected_if_index is None:
            # The action (reject the request without touching the network)
            # is the same in all cases; only the text in the log/response to
            # the client differs.
            explanation = _explain_lookup_failure(
                expected_name, lookup_state, expected_if_index, lookup_ipv4,
            )
            self.log.error(
                "remove_default_route: %s — rejecting the request with if_index=%s",
                explanation, if_index,
            )
            return {
                "ok": False,
                "error": f"VPN {IFACE_UNDETERMINED_MARKER}: {expected_name!r} — {explanation}",
            }

        if if_index != expected_if_index:
            self.log.warning(
                "remove_default_route rejected: the given if_index=%s does not "
                "match the actual ifIndex=%s of the current VPN session %r "
                "(PID=%s)",
                if_index, expected_if_index, expected_name, client_pid,
            )
            return {"ok": False, "error": "if_index does not match the current VPN session"}

        pre_v4 = list(pre_defaults_v4 or [])
        pre_v6 = list(pre_defaults_v6 or [])

        removed_v4 = 0
        removed_v6 = 0
        vpn_default_seen = False
        deadline = time.monotonic() + max(float(watch_seconds), 0.0)
        checks = 0

        while True:
            checks += 1

            current_v4 = _default_route_ifindexes(ipv6=False)

            if current_v4 is not None and if_index in current_v4:
                vpn_default_seen = True
                if _delete_default_route(if_index, ipv6=False):
                    removed_v4 += 1
                    self.log.info(
                        "Removed the 0.0.0.0/0 entry via ifIndex=%s",
                        if_index,
                    )

            if if_index in (_active_ipv6_default_ifindexes() or []):
                vpn_default_seen = True
                if _delete_default_route(if_index, ipv6=True):
                    removed_v6 += 1
                    self.log.info("Removed the ::/0 entry via ifIndex=%s", if_index)

            now = time.monotonic()
            if now >= deadline:
                break
            # Early exit: a default via the VPN did not appear — no full-tunnel.
            if checks >= 2 and not vpn_default_seen:
                break
            # Early exit: we removed the default and it did not come back on
            # the next tick.
            if checks >= 2 and vpn_default_seen and (removed_v4 or removed_v6):
                still_v4 = _default_route_ifindexes(ipv6=False)
                still_v6 = _cached_default_route_ifindexes(True)

                # If at least one query did not give a reliable answer, the
                # postcondition cannot be considered fulfilled and we cannot
                # do the early exit.
                if (
                    still_v4 is not None
                    and still_v6 is not None
                    and if_index not in still_v4
                    and if_index not in still_v6
                ):
                    break
            time.sleep(DEFAULT_ROUTE_WATCH_INTERVAL)

        if removed_v4 or removed_v6:
            self.log.info(
                "Forced split-tunnel: removed v4=%d v6=%d via ifIndex=%s",
                removed_v4, removed_v6, if_index,
            )
        else:
            self.log.info(
                "No default route via ifIndex=%s found — "
                "the connection was not full-tunnel anyway", if_index,
            )

        restored_v4 = 0
        restored_v6 = 0
        restore_errors: List[str] = []

        # pre_defaults_v4/v6 come from the client (a snapshot of the routing table,
        # taken BEFORE rasdial_connect) and are used by the elevated helper
        # to restore the physical default route. The same principle as
        # for if_index in remove_default_route itself: client authorization does not
        # mean that every field in the sent snapshot can be trusted —
        # the helper itself checks that if_index corresponds to a really
        # existing adapter, and that gateway is a valid address, before
        # performing route add with administrator rights.
        known_if_indexes = _known_if_indexes()
        if known_if_indexes is None:
            self.log.warning(
                "remove_default_route: could not enumerate adapters — "
                "skipping if_index validation of restore candidates",
            )
            known_if_indexes = None  # semantic marker, not an empty set

        remaining_v4 = _default_route_ifindexes(ipv6=False)

        if remaining_v4 is None:
            self.log.warning(
                "remove_default_route: could not determine remaining IPv4 default routes; "
                "skipping IPv4 default restoration"
            )
            others_v4 = None
        else:
            others_v4 = [i for i in remaining_v4 if i != if_index]

        if others_v4 == []:
            candidates = [
                r for r in pre_v4
                if isinstance(r, dict) and int(r.get("if_index", -1)) != int(if_index)
            ]
            if not candidates:
                self.log.warning(
                    "No IPv4 default left after removing the VPN default, and the "
                    "pre-connect snapshot is empty or contains only VPN — internet may be "
                    "unavailable until a DHCP/physical default appears"
                )
            for r in candidates:
                try:
                    idx = int(r["if_index"])
                    gw = str(r.get("gateway") or "0.0.0.0")
                    metric = int(r.get("metric") or 0)
                except (KeyError, TypeError, ValueError):
                    continue
                if not _is_valid_if_index(idx) or (
                    known_if_indexes is not None and idx not in known_if_indexes
                ):
                    self.log.warning(
                        "Skipping IPv4 default restore: if_index=%s from "
                        "pre_defaults_v4 does not match an existing adapter",
                        idx,
                    )
                    restore_errors.append(f"ifIndex={idx}: adapter does not exist")
                    continue
                if gw != "0.0.0.0" and not _is_valid_route_ip(gw):
                    self.log.warning(
                        "Skipping IPv4 default restore: gateway=%r from "
                        "pre_defaults_v4 is not a valid IPv4 address",
                        gw,
                    )
                    restore_errors.append(f"ifIndex={idx}: invalid gateway {gw!r}")
                    continue
                if _add_default_route(idx, gw, metric=metric, ipv6=False):
                    restored_v4 += 1
                    self.log.info(
                        "IPv4 default restored: ifIndex=%s gateway=%s metric=%s",
                        idx, gw, metric,
                    )
                else:
                    msg = f"ifIndex={idx} gw={gw}"
                    restore_errors.append(msg)
                    self.log.error("Failed to restore the IPv4 default: %s", msg)

        remaining_v6 = _cached_default_route_ifindexes(True)

        if remaining_v6 is None:
            self.log.warning(
                "remove_default_route: could not determine remaining IPv6 default routes; "
                "skipping IPv6 default restoration"
            )
            others_v6 = None
        else:
            others_v6 = [i for i in remaining_v6 if i != if_index]

        if others_v6 == [] and pre_v6:
            candidates = [
                r for r in pre_v6
                if isinstance(r, dict) and int(r.get("if_index", -1)) != int(if_index)
            ]
            for r in candidates:
                try:
                    idx = int(r["if_index"])
                    gw = str(r.get("gateway") or "::")
                    metric = int(r.get("metric") or 0)
                except (KeyError, TypeError, ValueError):
                    continue
                if not _is_valid_if_index(idx) or (
                    known_if_indexes is not None and idx not in known_if_indexes
                ):
                    self.log.warning(
                        "Skipping IPv6 default restore: if_index=%s from "
                        "pre_defaults_v6 does not match an existing adapter",
                        idx,
                    )
                    restore_errors.append(f"ifIndex={idx} (v6): adapter does not exist")
                    continue
                if gw != "::":
                    try:
                        gw_addr = ipaddress.IPv6Address(gw)
                    except (ipaddress.AddressValueError, ValueError):
                        gw_addr = None
                    if gw_addr is None or gw_addr.is_multicast or gw_addr.is_loopback or \
                            gw_addr.is_unspecified:
                        self.log.warning(
                            "Skipping IPv6 default restore: gateway=%r from "
                            "pre_defaults_v6 is not a valid IPv6 address",
                            gw,
                        )
                        restore_errors.append(f"ifIndex={idx} (v6): invalid gateway {gw!r}")
                        continue
                if _add_default_route(idx, gw, metric=metric, ipv6=True):
                    restored_v6 += 1
                    self.log.info(
                        "IPv6 default restored: ifIndex=%s gateway=%s metric=%s",
                        idx, gw, metric,
                    )
                else:
                    msg = f"ifIndex={idx} gw={gw} (v6)"
                    restore_errors.append(msg)
                    self.log.error("Failed to restore the IPv6 default: %s", msg)

        if restored_v4 or restored_v6:
            self.log.info(
                "Default routes restored: v4=%d v6=%d",
                restored_v4, restored_v6,
            )

        # High metric for the VPN interface: even if RAS restores 0.0.0.0/0,
        # the physical default with ~25 will remain preferable.
        metric_ok = set_interface_metric(if_index, VPN_INTERFACE_METRIC_HIGH)
        if metric_ok:
            self.log.info(
                "InterfaceMetric of ifIndex=%s set to %s",
                if_index, VPN_INTERFACE_METRIC_HIGH,
            )
        else:
            self.log.warning(
                "Failed to set a high InterfaceMetric on ifIndex=%s",
                if_index,
            )

        still_v4 = _default_route_ifindexes(ipv6=False)
        still_v6 = _cached_default_route_ifindexes(True)

        # Explicit None checks inside the condition — otherwise mypy does
        # not narrow Optional[List[int]] through an intermediate bool flag.
        if still_v4 is not None and still_v6 is not None:
            postcondition_ok = (
                if_index not in still_v4
                and if_index not in still_v6
            )
        else:
            postcondition_ok = False

        if not postcondition_ok:
            self.log.warning(
                "remove_default_route: postcondition not met or route state is unknown — "
                "ifIndex=%s v4=%s v6=%s",
                if_index,
                still_v4,
                still_v6,
            )

        other_defaults_v4 = _default_route_ifindexes(ipv6=False)

        if other_defaults_v4 is None:
            has_other_default = False
            self.log.warning(
                "remove_default_route: could not determine whether another "
                "IPv4 default route exists"
            )
        else:
            has_other_default = any(
                i != if_index for i in other_defaults_v4
            )

        # Separation of the protocol-level ok and the semantic state_ok:
        #
        #   ok = True    — the command was processed (validation passed,
        #                  route delete/restore and checks completed without
        #                  internal errors). This is exactly the contractual
        #                  meaning of ok in all other helper commands
        #                  (ping, add_routes, register_client,
        #                  release_and_disconnect). It does NOT mean
        #                  "split-tunnel is actually in effect": Windows/
        #                  RAS may restore 0.0.0.0/0 via the tunnel after
        #                  route delete has already run, and our postcondition
        #                  check will see that, but cannot influence it.
        #
        #   state_ok     — the target split-tunnel state was reached:
        #                  VPN default removed (postcondition_ok) AND the
        #                  machine has a physical default
        #                  (has_other_default) AND there were no restore
        #                  errors for previously removed defaults
        #                  (restore_errors — filled in when a restore was
        #                  needed and did not succeed). This field, not ok,
        #                  answers the question "will traffic go through
        #                  the physical interface rather than the tunnel".
        #
        # Previously a caller could easily read ok=True as "split-tunnel
        # definitely works" — with postcondition_ok=False that is wrong.
        # Now both fields are returned explicitly with different semantics.
        state_ok = bool(postcondition_ok and has_other_default and not restore_errors)

        return {
            "ok": True,
            "state_ok": state_ok,
            "removed": removed_v4,
            "removed_v6": removed_v6,
            "restored_v4": restored_v4,
            "restored_v6": restored_v6,
            "restore_errors": restore_errors or None,
            "has_other_default": has_other_default,
            "metric_set": metric_ok,
            "postcondition_ok": postcondition_ok,
        }


    def status(self) -> dict:
        with self._lock:
            return {"ok": True, "routes": list(self.routes.keys()),
                    "owner_pid": self.owner_pid,
                    "owner_connection_name": self.owner_connection_name,
                    "owner_all_user": self.owner_all_user}


def _setup_server_logging() -> None:
    """Configures a RotatingFileHandler in %LOCALAPPDATA%\\IPTV_Scanner\\logs\\vpn_helper.log."""
    log = logging.getLogger("vpn_helper")
    log.setLevel(logging.INFO)
    log.propagate = False
    try:
        handler = logging.handlers.RotatingFileHandler(
            _logs_dir() / LOG_FILE_NAME, maxBytes=LOG_MAX_BYTES, backupCount=1, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        log.addHandler(handler)
    except OSError:
        log.addHandler(logging.NullHandler())
        return

    client_logger = logging.getLogger("iptv_scanner.vpn")
    client_logger.setLevel(logging.INFO)
    client_logger.addHandler(handler)


# Commands that change the network state of the host system with
# administrator privileges. Without an owner check, any Medium-IL process
# of the same user could, for example, bring down a network adapter via
# adapter_restart. ping / status remain available to any client of the
# same user (diagnostics).
_NETWORK_OPS_COMMANDS = frozenset(
    {"arp_flush", "ping_probe", "adapter_restart"}
)


def _handle_client(handle: int, state: VpnHelperState) -> bool:
    """Handles commands of one client connection until it is closed.
    Returns True if a shutdown command arrived (the whole server needs to
    stop), otherwise False."""
    log = state.log

    def _abort_read() -> None:
        # DisconnectNamedPipe only — CloseHandle would kill the only instance.
        try:
            _kernel32.DisconnectNamedPipe(handle)
        except Exception:
            log.debug("DisconnectNamedPipe failed in _abort_read", exc_info=True)

    client_pid = _pipe_client_pid(handle) if IS_WINDOWS else None
    _client_context.pid = client_pid
    if client_pid is not None and not _process_same_user(client_pid):
        log.warning("Rejecting client PID=%s: another user", client_pid)
        _reply(handle, {"ok": False, "error": "access denied"})
        return False

    while True:
        try:
            request = _read_message_with_timeout(handle, 60.0, abort=_abort_read)
        except (EOFError, TimeoutError):
            return False
        except Exception:
            log.exception("Error reading from the pipe")
            return False

        cmd = request.get("cmd")
        log.info("Command: %s (client_pid=%s)", cmd, client_pid)

        if cmd in _NETWORK_OPS_COMMANDS:
            denied = state.check_network_ops(client_pid, str(cmd))
            if denied is not None:
                _reply(handle, denied)
                continue

        if cmd == "ping":
            _reply(handle, {"ok": True})

        elif cmd == "add_routes":
            try:
                routes = [(ip, idx, gw) for ip, idx, gw in (request.get("routes") or [])]
                _reply(handle, state.add_routes(routes))
            except Exception as e:
                log.exception("add_routes raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "remove_routes":
            try:
                _reply(handle, state.remove_routes(client_pid))
            except Exception as e:
                log.exception("remove_routes raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "remove_default_route":
            try:
                if_index_raw = request.get("if_index")
                if if_index_raw is None:
                    raise ValueError("remove_default_route: if_index is missing")
                if_index = int(if_index_raw)
                pre_v4 = request.get("pre_defaults_v4") or []
                pre_v6 = request.get("pre_defaults_v6") or []
                if not isinstance(pre_v4, list):
                    pre_v4 = []
                if not isinstance(pre_v6, list):
                    pre_v6 = []
                _reply(handle, state.remove_default_route(
                    if_index,
                    pre_defaults_v4=pre_v4,
                    pre_defaults_v6=pre_v6,
                ))
            except Exception as e:
                log.exception("remove_default_route raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "register_client":
            try:
                pid_raw = request.get("pid")
                if pid_raw is None:
                    raise ValueError("register_client: pid is missing")
                pid = int(pid_raw)
                name = str(request.get("connection_name") or "")
                all_user_raw = request.get("all_user")
                all_user = all_user_raw if isinstance(all_user_raw, bool) else None
                _reply(handle, state.register_client(
                    pid, name, all_user=all_user, pipe_client_pid=client_pid,
                ))
            except Exception as e:
                log.exception("register_client raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "release_and_disconnect":
            try:
                _reply(handle, state.release_and_disconnect(client_pid))
            except Exception as e:
                log.exception("release_and_disconnect raised an exception")
                _reply(handle, {"ok": False, "owned": False, "error": str(e)})
        elif cmd == "unregister_client":
            try:
                _reply(handle, state.unregister_client(client_pid))
            except Exception as e:
                log.exception("unregister_client raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "status":
            _reply(handle, state.status())
        elif cmd == "arp_flush":
            # Not tied to VPN ownership: it is a system operation (arp -d)
            # independent of the VPN, and we simply take advantage of the
            # fact that the helper is already elevated with administrator
            # privileges — see the _arp_flush_ips() docstring. Access: the
            # same Windows user (_process_same_user() above) AND
            # owner_pid/parent_pid (the common gate _NETWORK_OPS_COMMANDS at
            # the start of the loop).
            try:
                ips_raw = request.get("ips") or []
                if not isinstance(ips_raw, list):
                    ips_raw = []
                ips = [str(ip) for ip in ips_raw if isinstance(ip, str)]
                _reply(handle, _arp_flush_ips(ips))
            except Exception as e:
                log.exception("arp_flush raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "ping_probe":
            try:
                host = str(request.get("host") or "")
                _reply(handle, {"ok": ping_probe(host), "host": host})
            except Exception as e:
                log.exception("ping_probe raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "adapter_restart":
            try:
                iface = str(request.get("interface_name") or "")
                _reply(handle, _adapter_restart(iface))
            except Exception as e:
                log.exception("adapter_restart raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "prepare_split_tunnel":
            try:
                name = str(request.get("connection_name") or "")
                all_user_raw = request.get("all_user")
                all_user = all_user_raw if isinstance(all_user_raw, bool) else None
                _reply(handle, state.prepare_split_tunnel(name, all_user, client_pid))
            except Exception as e:
                log.exception("prepare_split_tunnel raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "restore_split_tunnel":
            try:
                _reply(handle, state.restore_split_tunnel(client_pid))
            except Exception as e:
                log.exception("restore_split_tunnel raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
        elif cmd == "shutdown":
            try:
                with state._lock:
                    if not state._shutdown_authorized_unlocked(client_pid):
                        _reply(handle, {"ok": False, "error": "The client is not the owner of the VPN session"})
                        continue
                    state._remove_routes_unlocked()
                    state.owner_pid = None
                    state.owner_connection_name = None
                    state.owner_all_user = None
                    state._restore_split_tunneling_unlocked()
                _reply(handle, {"ok": True})
            except Exception as e:
                log.exception("shutdown raised an exception")
                _reply(handle, {"ok": False, "error": str(e)})
            return True
        else:
            _reply(handle, {"ok": False, "error": f"unknown command {cmd!r}"})


def _reply(handle: int, payload: dict) -> None:
    try:
        pipe_write_message(handle, payload)
    except Exception:
        logging.getLogger("vpn_helper").debug(
            "Failed to send the reply to the client — it probably already disconnected",
            exc_info=True,
        )


def run_server(parent_pid: Optional[int] = None,
               parent_start_time: Optional[int] = None) -> None:
    _setup_server_logging()
    log = logging.getLogger("vpn_helper")
    log.info("VPN helper (elevated) started, PID=%s", os.getpid())

    if parent_pid is not None:
        parent_pid = int(parent_pid)
        if parent_pid <= 0:
            parent_pid = None
        elif not _process_alive(parent_pid):
            log.warning(
                "GUI process PID=%s is no longer alive at helper startup — exiting",
                parent_pid,
            )
            return
        elif IS_WINDOWS and not _process_same_user(parent_pid):
            log.warning(
                "parent-pid %s belongs to another user — ignoring",
                parent_pid,
            )
            parent_pid = None
        elif parent_start_time is not None:
            # Startup check: if start_time does not match what the process
            # parent_pid actually has, then either the GUI died and the PID
            # has already been reused by another process, or a fake PID was
            # slipped to us. In both cases we must not bind to this PID —
            # otherwise the whole parent-client authorization would end up
            # being granted to the wrong process.
            actual = _process_start_time(parent_pid)
            if actual is None or actual != int(parent_start_time):
                log.warning(
                    "parent-pid %s creation time mismatch "
                    "(expected=%s, actual=%s) — the PID was probably reused; "
                    "refusing to bind the helper to it",
                    parent_pid, parent_start_time, actual,
                )
                return

    if parent_pid is not None and parent_start_time is None:
        # parent_start_time can be None for three reasons: an old client
        # (built before --parent-start-time was introduced), a
        # GetProcessTimes failure on the client, or a launch in dev mode.
        # In all cases the PID-reuse protection is unavailable, and
        # _parent_authorized() returns False — authorization is completely
        # disabled (fail-closed).
        #
        # The helper remains alive (the monitor continues to watch the
        # parent, see _monitor_loop), but will not accept a single
        # parent-authorized command. The VPN fallback in this session
        # effectively does not work: register_client is rejected,
        # add_routes via the parent path too, network ops and shutdown too.
        #
        # We log at ERROR level, not WARNING: this is not a "degradation"
        # but a complete disablement of functionality, and it must be
        # noticed immediately when investigating an incident.
        log.error(
            "parent_start_time is not available (old client, GetProcessTimes "
            "failure, or dev mode) — PID-reuse protection is UNAVAILABLE, "
            "so ALL parent-authorized commands will be DENIED: "
            "register_client, shutdown, add_routes (parent path), and "
            "network ops (arp_flush, ping_probe, adapter_restart). The "
            "helper will stay alive (monitoring parent for exit) but is "
            "effectively unusable for the VPN fallback. Restart the helper "
            "with a client that passes --parent-start-time to restore "
            "functionality."
        )

    state = VpnHelperState(
        parent_pid=parent_pid, parent_start_time=parent_start_time,
    )
    state.start_monitor()

    try:
        pipe_handle = _server_create_pipe_handle(first=True)
    except Exception as e:
        # looks like a permissions error, although the real cause is different.
        if is_helper_alive(timeout=2.0):
            log.info(
                "Another VPN helper instance is already running and responding — "
                "this process simply exits (PID=%s)", os.getpid()
            )
        else:
            log.error(
                "Failed to create the named pipe %s (%s). Some hung vpn.py "
                "process is probably still holding the pipe without "
                "responding to commands. In Task Manager, check the "
                "python.exe/pythonw.exe processes (the 'Command line' column will show "
                "'vpn.py --base-path') and terminate them manually, or "
                "reboot Windows to reliably clear "
                "the system named pipes.", PIPE_NAME, e
            )
        return

    log.info("Listening on pipe %s (parent_pid=%s)", PIPE_NAME, parent_pid)
    try:
        while not state._stop.is_set():
            try:
                _server_wait_for_client(pipe_handle)
            except Exception:
                if state._stop.is_set():
                    break
                log.exception("Error while waiting for a client on the named pipe")
                break
            try:
                should_stop = _handle_client(pipe_handle, state)
            finally:
                try:
                    _kernel32.DisconnectNamedPipe(pipe_handle)
                except Exception:
                    log.warning(
                        "DisconnectNamedPipe failed after handling the client — "
                        "the pipe may stay busy and not accept the next "
                        "clients (see the earlier error about a hung process)",
                        exc_info=True,
                    )
            if should_stop:
                log.info("Shutdown command received — exiting")
                break
    finally:
        state._stop.set()
        try:
            with state._lock:
                state._remove_routes_unlocked()
        except Exception:
            log.exception("Error in the final remove_routes() on server shutdown")
        pipe_close(pipe_handle)
    log.info("VPN helper stopped")


def main() -> None:
    """Entry point of the server role. Called only when this file is started
    as a separate process with --parent-pid (see _helper_launch_target in
    PART 1) — that is, already with administrator rights obtained via UAC.
    On an ordinary import of the file from the GUI this function is not
    called."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--parent-pid", type=int, default=None,
        help="GUI process PID: the helper exits when this process disappears",
    )
    parser.add_argument(
        "--parent-start-time", type=int, default=None,
        help="GUI process creation time (raw 64-bit FILETIME): together with "
             "--parent-pid forms a PID-reuse-resistant identity of the parent",
    )
    args = parser.parse_args()
    run_server(parent_pid=args.parent_pid, parent_start_time=args.parent_start_time)


if __name__ == "__main__":
    main()