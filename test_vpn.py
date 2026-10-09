"""
Tests for vpn.py — only cross-platform part.

vpn.py as a whole is a Windows-only program (ctypes/RAS API/winreg), but all
such code is hidden behind `if IS_WINDOWS:` at module and function level (see
docstring _load_vpn_module in conftest.py), so the module can be safely
imported on Linux. Tests here cover:

  - pure logic without network/processes (decoding PowerShell/route output,
    parsing routing tables, resolve_host_ips for literal IPv4);
  - functions with external effects (subprocess, PowerShell, files), where
    the external call is mocked via monkeypatch, and what is checked is the
    logic around it (return code handling, route cache, idempotency);
  - VpnHelperState — pure Python ownership/authorization/routes/
    SplitTunneling logic, without Windows API (PID monitoring, os._exit and
    process liveness checks in tests are replaced — see helper_state fixture);
  - input validators (profile name, IP, ifIndex), client state on disk,
    helper integrity check;
  - the contract "public function on non-Windows returns False/raises
    HelperError instead of crashing" — this is also part of module behavior
    (many calls come from a regular GUI process before anything Windows-only
    is needed).

None of the above opens real network connections or starts real
route.exe/powershell.exe.

Network probes (_local_tcp_probe/_local_http_probe/_local_probe_hosts) used to
live in vpn.py, now they are part of IPTV_scanner.pyw — their tests are in
test_iptv_scanner.py.
"""
import hashlib
import ipaddress
import json
import subprocess
import sys
import threading
import types

import pytest


# ---------------------------------------------------------------------------
# _decode_ps_output — decoding PowerShell output (to Windows console it
# writes UTF-16; parsing of route.exe text output was removed from the module).
# ---------------------------------------------------------------------------

def test_decode_ps_output_empty_bytes_returns_empty_string(vpn_mod):
    assert vpn_mod._decode_ps_output(b"") == ""


def test_decode_ps_output_utf16_le_bom(vpn_mod):
    raw = "привет".encode("utf-16-le")
    raw = b"\xff\xfe" + raw
    assert vpn_mod._decode_ps_output(raw) == "привет"


def test_decode_ps_output_utf16_be_bom(vpn_mod):
    raw = b"\xfe\xff" + "hello".encode("utf-16-be")
    assert vpn_mod._decode_ps_output(raw) == "hello"


def test_decode_ps_output_utf16_le_no_bom_heuristic(vpn_mod):
    # PowerShell -Command often writes UTF-16LE without BOM: the heuristic in
    # the code is a zero byte at positions 1 and 3 (typical for ASCII text in
    # UTF-16LE).
    raw = "ok42".encode("utf-16-le")
    assert not raw.startswith((b"\xff\xfe", b"\xfe\xff"))
    assert vpn_mod._decode_ps_output(raw) == "ok42"


def test_decode_ps_output_utf8_fallback(vpn_mod):
    raw = '{"a": 1}'.encode("utf-8")
    assert vpn_mod._decode_ps_output(raw) == '{"a": 1}'


def test_decode_ps_output_strips_whitespace(vpn_mod):
    raw = b"  {\"a\": 1}\r\n"
    assert vpn_mod._decode_ps_output(raw) == '{"a": 1}'


# ---------------------------------------------------------------------------
# resolve_host_ips
# ---------------------------------------------------------------------------

def test_resolve_host_ips_literal_ipv4_returned_as_is(vpn_mod):
    assert vpn_mod.resolve_host_ips("192.168.1.1") == ["192.168.1.1"]


def test_resolve_host_ips_empty_or_blank_returns_empty_list(vpn_mod):
    assert vpn_mod.resolve_host_ips("") == []
    assert vpn_mod.resolve_host_ips("   ") == []


def test_resolve_host_ips_hostname_dedup_preserves_order(vpn_mod, monkeypatch):
    def fake_getaddrinfo(host, port, family, socktype):
        assert host == "example.com"
        return [
            (family, socktype, 0, "", ("10.0.0.2", 0)),
            (family, socktype, 0, "", ("10.0.0.1", 0)),
            (family, socktype, 0, "", ("10.0.0.2", 0)),  # duplicate
        ]

    monkeypatch.setattr(vpn_mod.socket, "getaddrinfo", fake_getaddrinfo)
    assert vpn_mod.resolve_host_ips("example.com") == ["10.0.0.2", "10.0.0.1"]


def test_resolve_host_ips_resolution_failure_returns_empty_list(vpn_mod, monkeypatch):
    def fake_getaddrinfo(*a, **kw):
        raise OSError("no such host")

    monkeypatch.setattr(vpn_mod.socket, "getaddrinfo", fake_getaddrinfo)
    assert vpn_mod.resolve_host_ips("nonexistent.invalid") == []


# ---------------------------------------------------------------------------
# _no_window_kwargs
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows contract: on Windows real behavior is checked")
def test_no_window_kwargs_empty_on_non_windows(vpn_mod):
    # On Windows returns {"creationflags": ..., "startupinfo": ...};
    # subprocess.STARTUPINFO does not exist on non-Windows platforms.
    assert vpn_mod._no_window_kwargs() == {}


# ---------------------------------------------------------------------------
# run_powershell_json
# ---------------------------------------------------------------------------

class _FakeCompletedProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_run_powershell_json_parses_valid_json(vpn_mod, monkeypatch):
    monkeypatch.setattr(
        vpn_mod, "_run",
        lambda args, timeout: _FakeCompletedProcess(stdout=b'{"ok": true, "n": 3}'),
    )
    assert vpn_mod.run_powershell_json("whatever") == {"ok": True, "n": 3}


def test_run_powershell_json_empty_output_returns_none(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(stdout=b""))
    assert vpn_mod.run_powershell_json("whatever") is None


def test_run_powershell_json_invalid_json_returns_none_and_logs_warning(vpn_mod, monkeypatch, caplog):
    monkeypatch.setattr(
        vpn_mod, "_run",
        lambda args, timeout: _FakeCompletedProcess(stdout=b"not json at all"),
    )
    with caplog.at_level("WARNING"):
        assert vpn_mod.run_powershell_json("whatever") is None
    assert any("JSON" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# _active_ipv6_default_ifindexes / default route cache
#
# Previously, text output of `route print` was parsed here (depended on
# Windows locale). Now IPv6 default is taken from Get-NetRoute and cached for
# _DEFAULT_ROUTE_CACHE_TTL seconds: VpnHelperState.remove_default_route
# requests the list several times in a row, and each powershell.exe launch
# costs ~1 s.
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_route_cache(vpn_mod):
    vpn_mod._invalidate_default_route_cache()
    yield
    vpn_mod._invalidate_default_route_cache()


@pytest.fixture
def route_lookup(vpn_mod, monkeypatch, clean_route_cache):
    """Replaces _default_route_ifindexes and controllable clock; records calls."""
    state = types.SimpleNamespace(calls=[], result=[5, 12], now=[1000.0])

    def fake_lookup(ipv6=False, timeout=5.0):
        state.calls.append(ipv6)
        return list(state.result)

    monkeypatch.setattr(vpn_mod, "_default_route_ifindexes", fake_lookup)
    monkeypatch.setattr(vpn_mod.time, "monotonic", lambda: state.now[0])
    return state


def test_active_ipv6_default_ifindexes_uses_ipv6_lookup(vpn_mod, route_lookup):
    assert vpn_mod._active_ipv6_default_ifindexes() == [5, 12]
    assert route_lookup.calls == [True]


def test_default_route_cache_hit_within_ttl_and_refresh_after_expiry(vpn_mod, route_lookup):
    ttl = vpn_mod._DEFAULT_ROUTE_CACHE_TTL
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    route_lookup.now[0] += ttl / 2
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    assert route_lookup.calls == [True]                 # second call is from cache
    route_lookup.now[0] += ttl / 2 + 0.1
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    assert route_lookup.calls == [True, True]           # TTL expired — request again


def test_default_route_cache_is_separate_per_address_family(vpn_mod, route_lookup):
    vpn_mod._cached_default_route_ifindexes(ipv6=False)
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    assert route_lookup.calls == [False, True]


def test_default_route_cache_invalidate_one_family_keeps_the_other(vpn_mod, route_lookup):
    vpn_mod._cached_default_route_ifindexes(ipv6=False)
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    vpn_mod._invalidate_default_route_cache(ipv6=True)
    vpn_mod._cached_default_route_ifindexes(ipv6=False)   # still cached
    vpn_mod._cached_default_route_ifindexes(ipv6=True)    # invalidated
    assert route_lookup.calls == [False, True, True]


def test_default_route_cache_invalidate_all(vpn_mod, route_lookup):
    vpn_mod._cached_default_route_ifindexes(ipv6=False)
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    vpn_mod._invalidate_default_route_cache()
    vpn_mod._cached_default_route_ifindexes(ipv6=False)
    vpn_mod._cached_default_route_ifindexes(ipv6=True)
    assert route_lookup.calls == [False, True, False, True]


def test_default_route_cache_returns_copies(vpn_mod, route_lookup):
    """The caller may modify the returned list — the cache is not corrupted by this."""
    first = vpn_mod._cached_default_route_ifindexes(ipv6=True)
    first.append(999)
    assert vpn_mod._cached_default_route_ifindexes(ipv6=True) == [5, 12]


# ---------------------------------------------------------------------------
# _unicast_route_exists / count_alive_routes — check against a snapshot of the
# routing table (routes_snapshot), not against the text output of route.exe.
# The snapshot contains dwForwardDest in both byte orders.
# ---------------------------------------------------------------------------

def _be(ip):
    return int(ipaddress.IPv4Address(ip))


def _le(ip):
    return int.from_bytes(ipaddress.IPv4Address(ip).packed, "little")


@pytest.fixture
def windows_with_snapshot(vpn_mod, monkeypatch):
    """Emulates Windows + a given routing table snapshot."""
    holder = types.SimpleNamespace(snapshot=set())
    monkeypatch.setattr(vpn_mod, "IS_WINDOWS", True)
    monkeypatch.setattr(vpn_mod, "routes_snapshot", lambda: holder.snapshot)
    return holder


def test_unicast_route_exists_matches_big_endian_entry(vpn_mod, windows_with_snapshot):
    windows_with_snapshot.snapshot = {(_be("1.2.3.4"), 5)}
    assert vpn_mod._unicast_route_exists("1.2.3.4", 5) is True


def test_unicast_route_exists_matches_little_endian_entry(vpn_mod, windows_with_snapshot):
    windows_with_snapshot.snapshot = {(_le("1.2.3.4"), 5)}
    assert vpn_mod._unicast_route_exists("1.2.3.4", 5) is True


def test_unicast_route_exists_requires_same_if_index(vpn_mod, windows_with_snapshot):
    windows_with_snapshot.snapshot = {(_be("1.2.3.4"), 5)}
    assert vpn_mod._unicast_route_exists("1.2.3.4", 6) is False


def test_unicast_route_exists_unreadable_table_is_false(vpn_mod, windows_with_snapshot):
    windows_with_snapshot.snapshot = None
    assert vpn_mod._unicast_route_exists("1.2.3.4", 5) is False


@pytest.mark.parametrize("ip,if_index", [
    ("not-an-ip", 5),
    ("1.2.3.4; calc", 5),
    ("127.0.0.1", 5),
    ("1.2.3.4", "abc"),
    ("1.2.3.4", 0),
    ("1.2.3.4", -3),
    ("1.2.3.4", None),
])
def test_unicast_route_exists_rejects_invalid_input(vpn_mod, windows_with_snapshot, ip, if_index):
    windows_with_snapshot.snapshot = {(_be("1.2.3.4"), 5), (_le("1.2.3.4"), 5)}
    assert vpn_mod._unicast_route_exists(ip, if_index) is False


def test_unicast_route_exists_false_on_non_windows(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "IS_WINDOWS", False)
    monkeypatch.setattr(vpn_mod, "routes_snapshot", lambda: {(_be("1.2.3.4"), 5)})
    assert vpn_mod._unicast_route_exists("1.2.3.4", 5) is False


def test_count_alive_routes_unreadable_snapshot_means_unknown(vpn_mod):
    assert vpn_mod.count_alive_routes([("1.2.3.4", 5)], None) == (0, 0)


def test_count_alive_routes_counts_alive_and_total(vpn_mod):
    snapshot = {(_be("1.2.3.4"), 5), (_le("5.6.7.8"), 5)}
    routes = [("1.2.3.4", 5), ("5.6.7.8", 5), ("9.9.9.9", 5), ("1.2.3.4", 6)]
    assert vpn_mod.count_alive_routes(routes, snapshot) == (2, 4)


def test_count_alive_routes_skips_invalid_entries_from_total(vpn_mod):
    snapshot = {(_be("1.2.3.4"), 5)}
    routes = [("1.2.3.4", 5), ("garbage", 5), ("1.2.3.4", "abc"), (None, 5)]
    assert vpn_mod.count_alive_routes(routes, snapshot) == (1, 1)


def test_count_alive_routes_empty_routes(vpn_mod):
    assert vpn_mod.count_alive_routes([], set()) == (0, 0)


# ---------------------------------------------------------------------------
# _default_route_ifindexes
#
# For IPv4, the fast path (_ipv4_default_route_ifindexes_fast,
# GetIpForwardTable) works first, and only if it fails (None) — PowerShell
# Get-NetRoute. On Windows the fast path reads the REAL routing table of the
# machine, so tests must explicitly replace it: otherwise the result depends
# on the OS and on where pytest is run (on Linux the fast path returns None,
# on Windows — [13]).
# ---------------------------------------------------------------------------

@pytest.fixture
def no_fast_path(vpn_mod, monkeypatch):
    """Emulates a Win32 fast-path failure — the code falls back to PowerShell."""
    monkeypatch.setattr(vpn_mod, "_ipv4_default_route_ifindexes_fast", lambda: None)


def test_default_route_ifindexes_single_int_result(vpn_mod, monkeypatch, no_fast_path):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: 12)
    assert vpn_mod._default_route_ifindexes() == [12]


def test_default_route_ifindexes_list_result_filters_unparsable(vpn_mod, monkeypatch, no_fast_path):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: [5, "12", "abc", None])
    assert vpn_mod._default_route_ifindexes() == [5, 12]


# Contract: [] — "request completed, no default routes"; None — "state could
# not be determined". These cases MUST NOT be mixed: for None the calling code
# (remove_default_route, connect_and_route) must consider the state unknown,
# not "no routes".

def test_default_route_ifindexes_none_result_is_unknown(vpn_mod, monkeypatch, no_fast_path):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: None)
    assert vpn_mod._default_route_ifindexes() is None


def test_default_route_ifindexes_empty_list_means_no_routes(vpn_mod, monkeypatch, no_fast_path):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: [])
    assert vpn_mod._default_route_ifindexes() == []


def test_default_route_ifindexes_unexpected_type_is_unknown(vpn_mod, monkeypatch, no_fast_path):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: {"unexpected": "dict"})
    assert vpn_mod._default_route_ifindexes() is None


def test_default_route_ifindexes_exception_is_unknown(vpn_mod, monkeypatch, no_fast_path):
    def raise_it(cmd, timeout):
        raise RuntimeError("boom")

    monkeypatch.setattr(vpn_mod, "run_powershell_json", raise_it)
    assert vpn_mod._default_route_ifindexes() is None


# ---------------------------------------------------------------------------
# get_default_routes — snapshot of default routes (dicts if_index/gateway/metric).
# Same [] vs None contract as _default_route_ifindexes.
# ---------------------------------------------------------------------------

@pytest.fixture
def no_fast_routes(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_ipv4_default_routes_fast", lambda: None)


def test_get_default_routes_ipv4_uses_fast_path_without_powershell(vpn_mod, monkeypatch):
    rows = [{"if_index": 5, "gateway": "10.0.0.1", "metric": 25}]
    monkeypatch.setattr(vpn_mod, "_ipv4_default_routes_fast", lambda: rows)
    _forbid_powershell(vpn_mod, monkeypatch)
    assert vpn_mod.get_default_routes(ipv6=False) == rows


def test_get_default_routes_ipv6_never_touches_fast_path(vpn_mod, monkeypatch):
    def boom():
        raise AssertionError("fast path must not be used for IPv6")

    monkeypatch.setattr(vpn_mod, "_ipv4_default_routes_fast", boom)
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: [])
    assert vpn_mod.get_default_routes(ipv6=True) == []


def test_get_default_routes_powershell_dict_is_wrapped_and_normalized(vpn_mod, monkeypatch, no_fast_routes):
    monkeypatch.setattr(
        vpn_mod, "run_powershell_json",
        lambda cmd, timeout: {"InterfaceIndex": "7", "NextHop": " 192.168.1.1 ", "RouteMetric": 10},
    )
    assert vpn_mod.get_default_routes() == [{"if_index": 7, "gateway": "192.168.1.1", "metric": 10}]


def test_get_default_routes_empty_gateway_gets_unspecified_address(vpn_mod, monkeypatch, no_fast_routes):
    monkeypatch.setattr(
        vpn_mod, "run_powershell_json",
        lambda cmd, timeout: [{"InterfaceIndex": 3, "NextHop": "", "RouteMetric": None}],
    )
    assert vpn_mod.get_default_routes() == [{"if_index": 3, "gateway": "0.0.0.0", "metric": 0}]
    assert vpn_mod.get_default_routes(ipv6=True) == [{"if_index": 3, "gateway": "::", "metric": 0}]


def test_get_default_routes_skips_garbage_rows_and_dedups(vpn_mod, monkeypatch, no_fast_routes):
    row = {"InterfaceIndex": 4, "NextHop": "10.0.0.1", "RouteMetric": 5}
    monkeypatch.setattr(
        vpn_mod, "run_powershell_json",
        lambda cmd, timeout: [row, dict(row), "junk", {"InterfaceIndex": "abc"}, {"NextHop": "1.1.1.1"}],
    )
    assert vpn_mod.get_default_routes() == [{"if_index": 4, "gateway": "10.0.0.1", "metric": 5}]


def test_get_default_routes_empty_result_means_no_routes(vpn_mod, monkeypatch, no_fast_routes):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: [])
    assert vpn_mod.get_default_routes() == []


@pytest.mark.parametrize("bad", [None, 42, "text"])
def test_get_default_routes_unexpected_result_type_is_unknown(vpn_mod, monkeypatch, no_fast_routes, bad):
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: bad)
    assert vpn_mod.get_default_routes() is None


def test_get_default_routes_powershell_exception_is_unknown(vpn_mod, monkeypatch, no_fast_routes):
    def raise_it(cmd, timeout):
        raise RuntimeError("boom")

    monkeypatch.setattr(vpn_mod, "run_powershell_json", raise_it)
    assert vpn_mod.get_default_routes() is None


def _forbid_powershell(vpn_mod, monkeypatch):
    def boom(cmd, timeout):
        raise AssertionError("PowerShell must not be called")

    monkeypatch.setattr(vpn_mod, "run_powershell_json", boom)


def test_default_route_ifindexes_ipv4_uses_fast_path_without_powershell(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_ipv4_default_route_ifindexes_fast", lambda: [7, 9])
    _forbid_powershell(vpn_mod, monkeypatch)
    assert vpn_mod._default_route_ifindexes() == [7, 9]


def test_default_route_ifindexes_ipv4_fast_path_empty_list_is_authoritative(vpn_mod, monkeypatch):
    """[] from fast path = "no default routes", not a failure: PowerShell must
    not be used (that would be an extra second on every call)."""
    monkeypatch.setattr(vpn_mod, "_ipv4_default_route_ifindexes_fast", lambda: [])
    _forbid_powershell(vpn_mod, monkeypatch)
    assert vpn_mod._default_route_ifindexes() == []


def test_default_route_ifindexes_ipv6_never_touches_fast_path(vpn_mod, monkeypatch):
    def boom():
        raise AssertionError("fast path is only for IPv4")

    monkeypatch.setattr(vpn_mod, "_ipv4_default_route_ifindexes_fast", boom)
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: 4)
    assert vpn_mod._default_route_ifindexes(ipv6=True) == [4]


def test_default_route_ifindexes_powershell_command_matches_address_family(vpn_mod, monkeypatch, no_fast_path):
    seen = []
    monkeypatch.setattr(vpn_mod, "run_powershell_json", lambda cmd, timeout: seen.append(cmd) or None)
    vpn_mod._default_route_ifindexes(ipv6=False)
    vpn_mod._default_route_ifindexes(ipv6=True)
    assert "-AddressFamily IPv4" in seen[0] and "0.0.0.0/0" in seen[0]
    assert "-AddressFamily IPv6" in seen[1] and "::/0" in seen[1]


def test_ipv4_default_route_ifindexes_fast_maps_rows_and_propagates_failure(vpn_mod, monkeypatch):
    monkeypatch.setattr(
        vpn_mod, "_ipv4_default_routes_fast",
        lambda: [{"if_index": 3, "gateway": "10.0.0.1", "metric": 25},
                 {"if_index": 8, "gateway": "10.1.0.1", "metric": 50}],
    )
    assert vpn_mod._ipv4_default_route_ifindexes_fast() == [3, 8]
    monkeypatch.setattr(vpn_mod, "_ipv4_default_routes_fast", lambda: [])
    assert vpn_mod._ipv4_default_route_ifindexes_fast() == []
    monkeypatch.setattr(vpn_mod, "_ipv4_default_routes_fast", lambda: None)
    assert vpn_mod._ipv4_default_route_ifindexes_fast() is None


# ---------------------------------------------------------------------------
# _delete_default_route
# ---------------------------------------------------------------------------

def test_delete_default_route_v4_success(vpn_mod, monkeypatch):
    captured = {}

    def fake_run(args, timeout):
        captured["args"] = args
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod._delete_default_route(7, ipv6=False) is True
    assert captured["args"] == [
        vpn_mod.ROUTE_EXE, "delete", "0.0.0.0", "mask", "0.0.0.0", "if", "7",
    ]


def test_delete_default_route_v6_success_uses_dash6(vpn_mod, monkeypatch):
    captured = {}

    def fake_run(args, timeout):
        captured["args"] = args
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod._delete_default_route(7, ipv6=True) is True
    assert captured["args"] == [vpn_mod.ROUTE_EXE, "-6", "delete", "::/0", "if", "7"]


def test_delete_default_route_nonzero_returncode_is_false(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=1))
    assert vpn_mod._delete_default_route(7, ipv6=False) is False


def test_delete_default_route_timeout_is_false(vpn_mod, monkeypatch):
    def fake_run(args, timeout):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod._delete_default_route(7, ipv6=False) is False


# ---------------------------------------------------------------------------
# add_route / delete_route — handling route.exe return codes
# ---------------------------------------------------------------------------

def test_add_route_success_returncode_zero(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=0))
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is True


def test_add_route_nonzero_exit_but_route_present_is_success(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=1))
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: True)
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is True


def test_add_route_nonzero_exit_and_route_absent_is_false(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=1))
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: False)
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is False


def test_add_route_timeout_is_false(vpn_mod, monkeypatch):
    def fake_run(args, timeout):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is False


def test_delete_route_success_returncode_zero(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=0))
    assert vpn_mod.delete_route("1.2.3.4", 5, "10.0.0.1") is True


def test_delete_route_already_gone_is_idempotent_success(vpn_mod, monkeypatch):
    # route already disappeared together with the interface — not a cleanup error.
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=1))
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: False)
    assert vpn_mod.delete_route("1.2.3.4", 5, "10.0.0.1") is True


def test_delete_route_still_present_after_failed_delete_is_false(vpn_mod, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: _FakeCompletedProcess(returncode=1))
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: True)
    assert vpn_mod.delete_route("1.2.3.4", 5, "10.0.0.1") is False


def test_delete_route_timeout_is_false(vpn_mod, monkeypatch):
    def fake_run(args, timeout):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod.delete_route("1.2.3.4", 5, "10.0.0.1") is False


def test_add_route_builds_argv_list_for_route_exe(vpn_mod, monkeypatch):
    calls = []

    def fake_run(args, timeout):
        calls.append(list(args))
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is True
    assert calls[0] == [
        vpn_mod.ROUTE_EXE, "add", "1.2.3.4", "mask", "255.255.255.255",
        "10.0.0.1", "metric", "5", "if", "5",
    ]


def test_add_route_already_exists_is_decided_by_routing_table_not_by_message(vpn_mod, monkeypatch):
    """route.exe messages are localized, so "already exists" is determined
    only by the actual routing table."""
    proc = _FakeCompletedProcess(
        returncode=1, stdout=b"", stderr="Объект уже существует.".encode("utf-8"),
    )
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: proc)
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: True)
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is True


def test_add_route_english_already_exists_text_is_not_trusted(vpn_mod, monkeypatch):
    """The error text itself is not considered success: if the route is not in
    the table — this is a failure, whatever is written in stderr."""
    proc = _FakeCompletedProcess(returncode=1, stderr=b"The object already exists.")
    monkeypatch.setattr(vpn_mod, "_run", lambda args, timeout: proc)
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: False)
    assert vpn_mod.add_route("1.2.3.4", 5, "10.0.0.1") is False


@pytest.mark.parametrize("ip,gateway", [
    ("1.2.3.4; calc", "10.0.0.1"),      # injection into destination
    ("1.2.3.4", "10.0.0.1 && calc"),    # injection into gateway
    ("127.0.0.1", "10.0.0.1"),          # loopback
    ("224.0.0.1", "10.0.0.1"),          # multicast
    ("1.2.3.4", "0.0.0.0"),             # unspecified gateway
    ("1.2.3.4", "255.255.255.255"),     # broadcast gateway
    ("", "10.0.0.1"),
])
def test_add_and_delete_route_reject_invalid_addresses_without_running_anything(vpn_mod, monkeypatch, ip, gateway):
    def boom(*a, **kw):
        raise AssertionError("route.exe must not run for an invalid address")

    monkeypatch.setattr(vpn_mod, "_run", boom)
    assert vpn_mod.add_route(ip, 5, gateway) is False
    assert vpn_mod.delete_route(ip, 5, gateway) is False


def test_delete_route_builds_argv_list_for_route_exe(vpn_mod, monkeypatch):
    calls = []

    def fake_run(args, timeout):
        calls.append(list(args))
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(vpn_mod, "_run", fake_run)
    assert vpn_mod.delete_route("1.2.3.4", 5, "10.0.0.1") is True
    assert calls[0] == [
        vpn_mod.ROUTE_EXE, "delete", "1.2.3.4", "mask", "255.255.255.255",
        "10.0.0.1", "if", "5",
    ]


# ---------------------------------------------------------------------------
# HelperError / is_helper_alive / send_command / connect_and_route —
# "unavailable on non-Windows" contract
# ---------------------------------------------------------------------------

def test_helper_error_is_a_runtime_error(vpn_mod):
    err = vpn_mod.HelperError("boom")
    assert isinstance(err, RuntimeError)
    assert str(err) == "boom"


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows contract: on Windows real behavior is checked")
def test_is_helper_alive_false_on_non_windows(vpn_mod):
    assert vpn_mod.is_helper_alive() is False


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows contract: on Windows real behavior is checked")
def test_send_command_raises_helper_error_on_non_windows(vpn_mod):
    with pytest.raises(vpn_mod.HelperError):
        vpn_mod.send_command({"cmd": "ping"})


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows contract: on Windows real behavior is checked")
def test_connect_and_route_fails_cleanly_on_non_windows(vpn_mod, tmp_path):
    result = vpn_mod.connect_and_route(tmp_path, "SomeVPN", hosts=[("1.2.3.4", 443)])
    assert result["ok"] is False
    assert "Windows" in result["error"]
    assert result["resolved"] == {}


# ---------------------------------------------------------------------------
# _appdata_dir / _client_state_path / _write_client_state / _read_client_state /
# _clear_client_state / _clear_client_state_if_matches
#
# The state directory is now single and always %LOCALAPPDATA%\IPTV_Scanner
# (not base_path next to the program), so tests redirect LOCALAPPDATA to a
# temporary directory. The icacls call (_restrict_file_acl_current_user) is
# suppressed so the test does not start external processes even on Windows.
# ---------------------------------------------------------------------------

@pytest.fixture
def fresh_appdata_cache(vpn_mod):
    """_appdata_dir() is wrapped in lru_cache: without reset, the first computed
    directory "sticks" for the whole process and subsequent tests see someone
    else's path."""
    vpn_mod._appdata_dir.cache_clear()
    yield
    vpn_mod._appdata_dir.cache_clear()


@pytest.fixture
def state_dir(vpn_mod, tmp_path, monkeypatch, fresh_appdata_cache):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(vpn_mod, "_restrict_file_acl_current_user", lambda path: None)
    return tmp_path / vpn_mod.APP_DIR_NAME


def test_appdata_dir_is_created_under_localappdata(vpn_mod, state_dir):
    assert not state_dir.exists()
    assert vpn_mod._appdata_dir() == state_dir
    assert state_dir.is_dir()


def test_appdata_dir_falls_back_to_appdata(vpn_mod, tmp_path, monkeypatch, fresh_appdata_cache):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert vpn_mod._appdata_dir() == tmp_path / vpn_mod.APP_DIR_NAME


def test_client_state_path_is_inside_appdata_dir(vpn_mod, state_dir):
    assert vpn_mod._client_state_path() == state_dir / vpn_mod.CLIENT_STATE_FILE_NAME


def test_write_client_state_roundtrip(vpn_mod, state_dir):
    assert vpn_mod._write_client_state("MyVPN", all_user=True) is True
    path = vpn_mod._client_state_path()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["connection_name"] == "MyVPN"
    assert data["all_user"] is True
    assert data["pid"] == vpn_mod.os.getpid()
    assert data["registered"] is False
    assert data["split_tunnel_changed"] is False
    assert data["previous_split_tunneling"] is None
    assert data["if_index"] is None
    assert data["route_ips"] == []
    assert isinstance(data["written_ts"], float)
    # No .tmp leftover after a successful atomic replacement.
    assert not path.with_suffix(path.suffix + ".tmp").exists()
    assert vpn_mod._read_client_state() == data


def test_write_client_state_records_session_identity_fields(vpn_mod, state_dir):
    vpn_mod._write_client_state(
        "MyVPN", all_user=False, registered=True, if_index=37,
        route_ips=["1.2.3.4", "5.6.7.8"],
    )
    data = vpn_mod._read_client_state()
    assert data["registered"] is True
    assert data["if_index"] == 37
    assert data["route_ips"] == ["1.2.3.4", "5.6.7.8"]


def test_write_client_state_previous_split_tunneling_only_when_changed(vpn_mod, state_dir):
    vpn_mod._write_client_state("V", previous_split_tunneling=True, split_tunnel_changed=False)
    assert vpn_mod._read_client_state()["previous_split_tunneling"] is None
    vpn_mod._write_client_state("V", previous_split_tunneling=False, split_tunnel_changed=True)
    data = vpn_mod._read_client_state()
    assert data["split_tunnel_changed"] is True
    assert data["previous_split_tunneling"] is False


def test_write_client_state_failure_returns_false_and_leaves_no_tmp(vpn_mod, state_dir, monkeypatch):
    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(vpn_mod.os, "fsync", boom)
    assert vpn_mod._write_client_state("MyVPN") is False
    path = vpn_mod._client_state_path()
    assert not path.exists()
    assert not path.with_suffix(path.suffix + ".tmp").exists()


def test_write_client_state_overwrites_previous_file_atomically(vpn_mod, state_dir):
    vpn_mod._write_client_state("First")
    vpn_mod._write_client_state("Second")
    assert vpn_mod._read_client_state()["connection_name"] == "Second"


def test_read_client_state_missing_file_is_none(vpn_mod, state_dir):
    assert vpn_mod._read_client_state() is None


def test_read_client_state_corrupt_json_is_none(vpn_mod, state_dir):
    vpn_mod._appdata_dir()
    vpn_mod._client_state_path().write_text("{not json", encoding="utf-8")
    assert vpn_mod._read_client_state() is None


def test_read_client_state_non_dict_json_is_none(vpn_mod, state_dir):
    vpn_mod._appdata_dir()
    vpn_mod._client_state_path().write_text("[1, 2, 3]", encoding="utf-8")
    assert vpn_mod._read_client_state() is None


def test_clear_client_state_removes_file(vpn_mod, state_dir):
    vpn_mod._write_client_state("MyVPN")
    assert vpn_mod._client_state_path().exists()
    vpn_mod._clear_client_state()
    assert not vpn_mod._client_state_path().exists()


def test_clear_client_state_on_missing_file_does_not_raise(vpn_mod, state_dir):
    vpn_mod._clear_client_state()  # no file at all — must not raise


def test_clear_client_state_if_matches_removes_matching_session(vpn_mod, state_dir):
    vpn_mod._write_client_state("MyVPN", all_user=True)
    vpn_mod._clear_client_state_if_matches("MyVPN", True)
    assert vpn_mod._read_client_state() is None


def test_clear_client_state_if_matches_keeps_other_session_marker(vpn_mod, state_dir):
    """The marker of another session is the only crash-safety mechanism for it;
    it must not be deleted when disconnecting someone else's profile."""
    vpn_mod._write_client_state("vpn-name", all_user=False)
    vpn_mod._clear_client_state_if_matches("other", False)
    assert vpn_mod._read_client_state()["connection_name"] == "vpn-name"


def test_clear_client_state_if_matches_keeps_marker_when_scope_differs(vpn_mod, state_dir):
    vpn_mod._write_client_state("MyVPN", all_user=True)
    vpn_mod._clear_client_state_if_matches("MyVPN", False)
    assert vpn_mod._read_client_state() is not None


def test_clear_client_state_if_matches_none_scope_matches_none_scope(vpn_mod, state_dir):
    vpn_mod._write_client_state("MyVPN", all_user=None)
    vpn_mod._clear_client_state_if_matches("MyVPN", None)
    assert vpn_mod._read_client_state() is None


@pytest.mark.parametrize("name", [None, ""])
def test_clear_client_state_if_matches_without_name_does_nothing(vpn_mod, state_dir, name):
    vpn_mod._write_client_state("MyVPN")
    vpn_mod._clear_client_state_if_matches(name)
    assert vpn_mod._read_client_state() is not None


def test_clear_client_state_if_matches_without_file_does_not_raise(vpn_mod, state_dir):
    vpn_mod._clear_client_state_if_matches("MyVPN", None)


# ---------------------------------------------------------------------------
# VpnHelperState — pure Python ownership/routes logic (without Windows API;
# _monitor_loop itself is a no-op on non-Windows, see module docstring above).
#
# Helper trust model (UAC boundary): only parent_pid — the process that
# launched the helper — can register as owner, and only while it is alive.
# Therefore the fixture sets parent_pid and replaces everything that on a real
# machine (including a Windows developer machine) would access real processes:
#   * _process_alive — always False on non-Windows, but on Windows would ask
#     the OS about invented PIDs;
#   * _exit_helper — calls os._exit(0) and would kill pytest itself;
#   * start_monitor — on Windows would start a real observer thread.
# ---------------------------------------------------------------------------

_PARENT_PID = 4242
# FILETIME of the "parent" GUI process creation. The helper is fail-closed:
# without parent_start_time (PID reuse protection) parent authorization is
# rejected entirely, so the fixture must pass it.
_PARENT_START = 133_000_000_000_000_000
_OWNER_MSG = "The client is not the owner of the VPN session"


class _HelperExit(Exception):
    """Instead of os._exit(0) in tests: records that the helper decided to exit."""


@pytest.fixture
def helper_state(vpn_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_process_alive", lambda pid: True)
    monkeypatch.setattr(vpn_mod, "_process_same_user", lambda pid: True, raising=False)
    # parent start_time matches the one passed to the constructor — "the same"
    # process. Other PIDs do not need the timestamp (None).
    monkeypatch.setattr(
        vpn_mod, "_process_start_time",
        lambda pid: _PARENT_START if pid == _PARENT_PID else None,
    )
    state = vpn_mod.VpnHelperState(
        parent_pid=_PARENT_PID, parent_start_time=_PARENT_START,
    )
    state.start_monitor = lambda: None

    def fake_exit():
        raise _HelperExit()

    state._exit_helper = fake_exit
    return state


@pytest.fixture
def registered(helper_state):
    assert helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1") == {"ok": True}
    return helper_state


@pytest.fixture
def as_client(vpn_mod, monkeypatch):
    """Sets the client PID on behalf of which the pipe command arrived (thread-local)."""
    def _set(pid):
        monkeypatch.setattr(vpn_mod._client_context, "pid", pid, raising=False)
    return _set


@pytest.fixture
def owner_iface(vpn_mod, monkeypatch):
    """Result of searching for the owner's VPN adapter (_lookup_interface_by_name).

    add_routes distinguishes three lookup outcomes (see InterfaceLookupState):
    FOUND / MISSING ("definitely absent") / UNKNOWN ("failed to read the
    table"). For brevity, tests set holder.result = (ifIndex, ip);
    (None, None) means MISSING. To simulate UNKNOWN, set
    holder.state = vpn_mod.InterfaceLookupState.UNKNOWN.
    """
    holder = types.SimpleNamespace(result=(5, "10.0.0.2"), state=None)

    def _fake_lookup(name):
        if holder.state is not None:
            return holder.state, None, None
        if_index, ip = holder.result
        if if_index is None:
            return vpn_mod.InterfaceLookupState.MISSING, None, None
        return vpn_mod.InterfaceLookupState.FOUND, if_index, ip

    monkeypatch.setattr(vpn_mod, "_lookup_interface_by_name", _fake_lookup)
    return holder


# --- register_client ---------------------------------------------------------

def test_register_client_by_parent_succeeds(vpn_mod, helper_state):
    result = helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1", all_user=True)
    assert result == {"ok": True}
    assert helper_state.owner_pid == _PARENT_PID
    assert helper_state.owner_connection_name == "VPN1"
    assert helper_state.owner_all_user is True


def test_register_client_rejects_other_process_while_parent_alive(vpn_mod, helper_state):
    """Hijack attempt: parent is alive, but someone else is registering."""
    result = helper_state.register_client(pid=9999, connection_name="VPN1")
    assert result["ok"] is False
    assert "Registration unavailable" in result["error"]
    assert helper_state.owner_pid is None


def test_register_client_with_dead_parent_shuts_helper_down_and_cleans_up(vpn_mod, helper_state, monkeypatch):
    """An orphaned helper must neither accept registration nor stay alive:
    it removes routes and exits."""
    monkeypatch.setattr(vpn_mod, "_process_alive", lambda pid: False)
    deleted = []
    monkeypatch.setattr(
        vpn_mod, "delete_route",
        lambda ip, if_index, gateway: deleted.append(ip) or True,
    )
    helper_state.routes["1.2.3.4"] = (5, "10.0.0.1")
    with pytest.raises(_HelperExit):
        helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1")
    assert deleted == ["1.2.3.4"]
    assert helper_state.owner_pid is None


def test_register_client_without_parent_pid_is_refused_without_exit(vpn_mod, helper_state):
    helper_state.parent_pid = None
    result = helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1")
    assert result["ok"] is False
    assert helper_state.owner_pid is None


def test_register_client_second_different_owner_rejected(vpn_mod, registered):
    result = registered.register_client(pid=_PARENT_PID, connection_name="VPN2")
    assert result == {"ok": False, "error": "Another client already owns the VPN session"}
    assert registered.owner_connection_name == "VPN1"      # owner did not change


def test_register_client_different_scope_rejected(vpn_mod, registered):
    result = registered.register_client(pid=_PARENT_PID, connection_name="VPN1", all_user=True)
    assert result["ok"] is False


def test_register_client_same_owner_reregistering_is_idempotent(vpn_mod, registered):
    assert registered.register_client(pid=_PARENT_PID, connection_name="VPN1") == {"ok": True}


def test_register_client_pid_mismatch_with_pipe_pid_rejected(vpn_mod, helper_state):
    result = helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1", pipe_client_pid=999)
    assert result["ok"] is False
    assert "does not match" in result["error"]
    assert helper_state.owner_pid is None


def test_register_client_pid_matching_pipe_pid_accepted(vpn_mod, helper_state):
    result = helper_state.register_client(
        pid=_PARENT_PID, connection_name="VPN1", pipe_client_pid=_PARENT_PID
    )
    assert result == {"ok": True}


def test_register_client_other_user_process_rejected(vpn_mod, helper_state, monkeypatch):
    monkeypatch.setattr(vpn_mod, "IS_WINDOWS", True)
    monkeypatch.setattr(vpn_mod, "_process_same_user", lambda pid: False, raising=False)
    result = helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1")
    assert result == {"ok": False, "error": "The process belongs to another user"}
    assert helper_state.owner_pid is None


def test_register_client_refused_while_split_tunnel_pending_for_other_profile(vpn_mod, helper_state):
    helper_state.split_tunnel_connection_name = "Other"
    helper_state.split_tunnel_all_user = None
    result = helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1")
    assert result["ok"] is False
    assert "restore_split_tunnel" in result["error"]
    assert helper_state.owner_pid is None


def test_register_client_allowed_when_split_tunnel_pending_for_same_profile(vpn_mod, helper_state):
    helper_state.split_tunnel_connection_name = "VPN1"
    helper_state.split_tunnel_all_user = None
    assert helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1") == {"ok": True}


# --- unregister_client -------------------------------------------------------

def test_unregister_client_not_owner_rejected(vpn_mod, registered):
    result = registered.unregister_client(client_pid=9999)
    assert result == {"ok": False, "error": _OWNER_MSG}
    assert registered.owner_pid == _PARENT_PID


def test_unregister_client_without_pid_rejected_when_owned(vpn_mod, registered):
    assert registered.unregister_client(client_pid=None)["ok"] is False


def test_unregister_client_owner_clears_state(vpn_mod, registered):
    assert registered.unregister_client(client_pid=_PARENT_PID) == {"ok": True}
    assert registered.owner_pid is None
    assert registered.owner_connection_name is None
    assert registered.owner_all_user is None


def test_unregister_client_when_nobody_registered_is_ok(vpn_mod, helper_state):
    assert helper_state.unregister_client(client_pid=None) == {"ok": True}


# --- authorization predicates ------------------------------------------------

def test_authorized_client_requires_matching_owner(vpn_mod, helper_state):
    assert helper_state._authorized_client(_PARENT_PID) is False   # no owner yet
    helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1")
    assert helper_state._authorized_client(_PARENT_PID) is True
    assert helper_state._authorized_client(9999) is False
    assert helper_state._authorized_client(None) is False


def test_register_authorized_only_for_live_parent(vpn_mod, helper_state, monkeypatch):
    with helper_state._lock:
        assert helper_state._register_authorized_unlocked(_PARENT_PID) is True
        assert helper_state._register_authorized_unlocked(9999) is False
        assert helper_state._register_authorized_unlocked(None) is False
    monkeypatch.setattr(vpn_mod, "_process_alive", lambda pid: False)
    with helper_state._lock:
        assert helper_state._register_authorized_unlocked(_PARENT_PID) is False   # parent dead
    helper_state.parent_pid = None
    with helper_state._lock:
        assert helper_state._register_authorized_unlocked(_PARENT_PID) is False


def test_routes_authorized_owner_or_parent_when_no_owner(vpn_mod, helper_state):
    with helper_state._lock:
        # No owner: routes can be changed only by the GUI that launched the helper.
        assert helper_state._routes_authorized_unlocked(_PARENT_PID) is True
        assert helper_state._routes_authorized_unlocked(9999) is False
        assert helper_state._routes_authorized_unlocked(None) is False
        # Owner exists: only the owner.
        helper_state.owner_pid = 5000
        assert helper_state._routes_authorized_unlocked(5000) is True
        assert helper_state._routes_authorized_unlocked(_PARENT_PID) is False


def test_shutdown_authorized_owner_or_parent_when_no_owner(vpn_mod, helper_state):
    with helper_state._lock:
        assert helper_state._shutdown_authorized_unlocked(_PARENT_PID) is True
        assert helper_state._shutdown_authorized_unlocked(9999) is False   # another process of the same user
        assert helper_state._shutdown_authorized_unlocked(None) is False
        helper_state.owner_pid = 5000
        assert helper_state._shutdown_authorized_unlocked(5000) is True
        assert helper_state._shutdown_authorized_unlocked(_PARENT_PID) is False


def test_network_ops_authorized_owner_and_strangers(vpn_mod, helper_state):
    with helper_state._lock:
        helper_state.owner_pid = 5000
        assert helper_state._network_ops_authorized_unlocked(5000) is True
        assert helper_state._network_ops_authorized_unlocked(9999) is False
        assert helper_state._network_ops_authorized_unlocked(None) is False


def test_network_ops_only_owner_allowed_when_owner_registered(vpn_mod, helper_state):
    """Contract after aligning the docstring with the code: while an owner is
    registered, network operations are allowed ONLY to them. Parent is not
    separately allowed — after register_client() owner_pid and parent_pid point
    to the same process, so the "owner vs parent" distinction is illusory in
    this state."""
    with helper_state._lock:
        helper_state.owner_pid = 5000
        assert helper_state._network_ops_authorized_unlocked(5000) is True
        assert helper_state._network_ops_authorized_unlocked(_PARENT_PID) is False


def test_check_network_ops_allows_or_returns_ready_refusal(vpn_mod, helper_state):
    assert helper_state.check_network_ops(_PARENT_PID, "arp_flush") is None
    assert helper_state.check_network_ops(9999, "arp_flush") == {
        "ok": False, "error": "arp_flush: client is not authorized",
    }
    assert helper_state.check_network_ops(None, "arp_flush")["ok"] is False


# --- status ------------------------------------------------------------------

def test_status_reports_owner_and_routes(vpn_mod, helper_state):
    helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1", all_user=False)
    helper_state.routes["1.2.3.4"] = (5, "10.0.0.1")
    status = helper_state.status()
    assert status == {
        "ok": True,
        "routes": ["1.2.3.4"],
        "owner_pid": _PARENT_PID,
        "owner_connection_name": "VPN1",
        "owner_all_user": False,
    }


def test_status_of_fresh_helper_has_no_owner(vpn_mod, helper_state):
    status = helper_state.status()
    assert status["owner_pid"] is None and status["routes"] == []


# --- release_and_disconnect --------------------------------------------------

@pytest.fixture
def ras(vpn_mod, monkeypatch):
    """Replaces external effects of release_and_disconnect."""
    rec = types.SimpleNamespace(
        disconnect_calls=[], disconnect_result=True, disconnect_exc=None,
        delete_result=True, deleted=[], split_calls=[],
    )

    def fake_disconnect(name, timeout=20.0, all_user=None):
        rec.disconnect_calls.append((name, all_user))
        if rec.disconnect_exc:
            raise rec.disconnect_exc
        return rec.disconnect_result

    def fake_delete(ip, if_index, gateway):
        rec.deleted.append(ip)
        return rec.delete_result

    def fake_set_split(name, enabled, all_user=None, timeout=12.0):
        rec.split_calls.append((name, enabled, all_user))
        return True, ""

    monkeypatch.setattr(vpn_mod, "rasdial_disconnect", fake_disconnect)
    monkeypatch.setattr(vpn_mod, "delete_route", fake_delete)
    monkeypatch.setattr(vpn_mod, "set_vpn_split_tunneling", fake_set_split)
    return rec


def test_release_and_disconnect_not_owner_rejected(vpn_mod, registered, ras):
    result = registered.release_and_disconnect(client_pid=9999)
    assert result == {"ok": False, "owned": False, "error": _OWNER_MSG}
    assert registered.owner_pid == _PARENT_PID
    assert ras.disconnect_calls == []


def test_release_and_disconnect_owner_clears_routes_ownership_and_disconnects(vpn_mod, helper_state, ras):
    helper_state.register_client(pid=_PARENT_PID, connection_name="VPN1", all_user=True)
    helper_state.routes["1.2.3.4"] = (5, "10.0.0.1")

    result = helper_state.release_and_disconnect(client_pid=_PARENT_PID)

    assert result == {
        "ok": True, "owned": True, "connection_name": "VPN1", "all_user": True,
        "routes_removed": True, "vpn_disconnected": True,
    }
    assert ras.disconnect_calls == [("VPN1", True)]
    assert ras.deleted == ["1.2.3.4"]
    assert helper_state.owner_pid is None
    assert helper_state.owner_connection_name is None
    assert helper_state.routes == {}


def test_release_and_disconnect_reports_failed_disconnect_but_still_releases(vpn_mod, registered, ras):
    ras.disconnect_result = False
    result = registered.release_and_disconnect(client_pid=_PARENT_PID)
    assert result["ok"] is False
    assert result["vpn_disconnected"] is False
    assert result["owned"] is True
    assert registered.owner_pid is None            # ownership is released either way


def test_release_and_disconnect_survives_rasdial_exception(vpn_mod, registered, ras):
    ras.disconnect_exc = RuntimeError("rasdial exploded")
    result = registered.release_and_disconnect(client_pid=_PARENT_PID)
    assert result["ok"] is False
    assert result["vpn_disconnected"] is False
    assert registered.owner_pid is None


def test_release_and_disconnect_route_removal_failure_is_reported_but_vpn_still_disconnected(vpn_mod, registered, ras):
    registered.routes["1.2.3.4"] = (5, "10.0.0.1")
    ras.delete_result = False
    result = registered.release_and_disconnect(client_pid=_PARENT_PID)
    assert result["routes_removed"] is False
    assert result["vpn_disconnected"] is True
    assert result["ok"] is False
    assert ras.disconnect_calls == [("VPN1", None)]


def test_release_and_disconnect_restores_split_tunneling_we_changed(vpn_mod, registered, ras):
    registered.saved_split_tunneling = False
    registered.split_tunnel_connection_name = "VPN1"
    registered.split_tunnel_all_user = None
    registered.release_and_disconnect(client_pid=_PARENT_PID)
    assert ras.split_calls == [("VPN1", False, None)]
    assert registered.saved_split_tunneling is None
    assert registered.split_tunnel_connection_name is None


# --- add_routes --------------------------------------------------------------

def test_add_routes_unauthorized_client_rejected(vpn_mod, registered, as_client):
    as_client(9999)                                  # not the owner
    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])
    assert result == {"ok": False, "error": _OWNER_MSG, "added": []}


def test_add_routes_without_client_context_rejected(vpn_mod, registered, as_client):
    as_client(None)
    assert registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])["ok"] is False


def test_add_routes_too_many_routes_rejected(vpn_mod, registered, as_client):
    as_client(_PARENT_PID)
    routes = [("1.2.3.4", 5, "10.0.0.1")] * (vpn_mod.MAX_ROUTES_PER_REQUEST + 1)
    result = registered.add_routes(routes)
    assert result["ok"] is False and result["added"] == []
    assert "Too many routes" in result["error"]


def test_add_routes_new_route_added(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    as_client(_PARENT_PID)
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, if_index, gateway: True)

    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])

    assert result == {"ok": True, "error": None, "added": ["1.2.3.4"]}
    assert registered.routes["1.2.3.4"] == (5, "10.0.0.1")


def test_add_routes_rejects_if_index_not_matching_vpn_session(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    as_client(_PARENT_PID)
    owner_iface.result = (5, "10.0.0.2")
    monkeypatch.setattr(
        vpn_mod, "add_route",
        lambda *a: (_ for _ in ()).throw(AssertionError("add_route must not be called")),
    )
    result = registered.add_routes([("1.2.3.4", 9, "10.0.0.1")])
    assert result["ok"] is False
    assert result["added"] == []
    assert "does not match the current VPN session" in result["error"]


def test_add_routes_rejects_everything_when_vpn_interface_undetermined(vpn_mod, registered, as_client, owner_iface):
    as_client(_PARENT_PID)
    owner_iface.result = (None, None)
    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])
    assert result["ok"] is False and result["added"] == []
    assert vpn_mod.IFACE_UNDETERMINED_MARKER in result["error"]


def test_add_routes_invalid_entries_reported_while_valid_ones_still_added(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    as_client(_PARENT_PID)
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, if_index, gateway: True)
    result = registered.add_routes([
        ("1.2.3.4; calc", 5, "10.0.0.1"),     # injection into destination
        ("2.2.2.2", 5, "0.0.0.0"),            # invalid gateway
        ("3.3.3.3", "abc", "10.0.0.1"),       # invalid if_index
        ("4.4.4.4", 5, "10.0.0.1"),           # valid
    ])
    assert result["ok"] is True                # something was added
    assert result["added"] == ["4.4.4.4"]
    for bad in ("1.2.3.4; calc", "2.2.2.2", "3.3.3.3"):
        assert bad in result["error"]
    assert set(registered.routes) == {"4.4.4.4"}


def test_add_routes_all_invalid_is_not_ok(vpn_mod, registered, as_client, owner_iface):
    as_client(_PARENT_PID)
    result = registered.add_routes([("garbage", 5, "10.0.0.1")])
    assert result["ok"] is False and result["added"] == []


def test_add_routes_existing_same_route_verified_not_readded(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    as_client(_PARENT_PID)
    registered.routes["1.2.3.4"] = (5, "10.0.0.1")

    add_calls = []
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, if_index, gateway: add_calls.append(ip) or True)
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: True)

    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])

    assert result == {"ok": True, "error": None, "added": ["1.2.3.4"]}
    assert add_calls == []            # route is physically present — not re-added


def test_add_routes_cached_route_missing_from_table_is_reinstalled(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    """Windows sometimes loses individual routes by itself, without interface
    change: an entry in the helper cache does not prove that the route actually
    works."""
    as_client(_PARENT_PID)
    registered.routes["1.2.3.4"] = (5, "10.0.0.1")
    deleted, added = [], []
    monkeypatch.setattr(vpn_mod, "_unicast_route_exists", lambda ip, if_index, timeout=5.0: False)
    monkeypatch.setattr(vpn_mod, "delete_route", lambda ip, i, g: deleted.append(ip) or True)
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, i, g: added.append(ip) or True)

    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])

    assert result == {"ok": True, "error": None, "added": ["1.2.3.4"]}
    assert deleted == ["1.2.3.4"] and added == ["1.2.3.4"]


def test_add_routes_stale_interface_reinstalls_route(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    # The tunnel was re-established with a new ifIndex/gateway after sleep —
    # the old entry for the same IP must be deleted and added again, not left
    # as is (see VpnHelperState.add_routes docstring about the post-sleep bug).
    as_client(_PARENT_PID)
    owner_iface.result = (9, "10.0.0.2")                 # current VPN adapter ifIndex
    registered.routes["1.2.3.4"] = (5, "10.0.0.1")       # old ifIndex/gateway

    deleted, added = [], []
    monkeypatch.setattr(
        vpn_mod, "delete_route",
        lambda ip, if_index, gateway: deleted.append((ip, if_index, gateway)) or True,
    )
    monkeypatch.setattr(
        vpn_mod, "add_route",
        lambda ip, if_index, gateway: added.append((ip, if_index, gateway)) or True,
    )

    result = registered.add_routes([("1.2.3.4", 9, "10.0.0.2")])  # new ifIndex/gateway

    assert result == {"ok": True, "error": None, "added": ["1.2.3.4"]}
    assert deleted == [("1.2.3.4", 5, "10.0.0.1")]
    assert added == [("1.2.3.4", 9, "10.0.0.2")]
    assert registered.routes["1.2.3.4"] == (9, "10.0.0.2")


def test_add_routes_failure_deleting_stale_route_does_not_abort(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    as_client(_PARENT_PID)
    owner_iface.result = (9, "10.0.0.2")
    registered.routes["1.2.3.4"] = (5, "10.0.0.1")

    def failing_delete(ip, if_index, gateway):
        raise OSError("route.exe died")

    monkeypatch.setattr(vpn_mod, "delete_route", failing_delete)
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, i, g: True)
    result = registered.add_routes([("1.2.3.4", 9, "10.0.0.2")])
    assert result["added"] == ["1.2.3.4"]
    assert registered.routes["1.2.3.4"] == (9, "10.0.0.2")


def test_add_routes_failure_reported_in_errors(vpn_mod, registered, as_client, owner_iface, monkeypatch):
    as_client(_PARENT_PID)
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, if_index, gateway: False)

    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])

    assert result["ok"] is False
    assert result["added"] == []
    assert "1.2.3.4" in result["error"]
    assert "1.2.3.4" not in registered.routes


def test_add_routes_by_parent_without_owner_checks_adapter_existence(vpn_mod, helper_state, as_client, monkeypatch):
    """Path "VPN already raised by the user": there is no owner, the profile
    name is unknown to the helper — if_index is at least checked against the
    list of existing adapters."""
    as_client(_PARENT_PID)
    monkeypatch.setattr(vpn_mod, "_known_if_indexes", lambda timeout=5.0: {5})
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, i, g: True)
    result = helper_state.add_routes([("1.2.3.4", 5, "10.0.0.1"), ("5.6.7.8", 99, "10.0.0.1")])
    assert result["added"] == ["1.2.3.4"]
    assert "5.6.7.8" in result["error"] and "existing adapter" in result["error"]


def test_add_routes_by_parent_unknown_adapter_list_does_not_reject(vpn_mod, helper_state, as_client, monkeypatch):
    """None = "I don't know" (GetAdaptersAddresses error) — requests are not rejected."""
    as_client(_PARENT_PID)
    monkeypatch.setattr(vpn_mod, "_known_if_indexes", lambda timeout=5.0: None)
    monkeypatch.setattr(vpn_mod, "add_route", lambda ip, i, g: True)
    result = helper_state.add_routes([("1.2.3.4", 99, "10.0.0.1")])
    assert result == {"ok": True, "error": None, "added": ["1.2.3.4"]}


# --- remove_routes -----------------------------------------------------------

def test_remove_routes_unauthorized_client_rejected(vpn_mod, registered):
    result = registered.remove_routes(client_pid=9999)
    assert result == {"ok": False, "error": _OWNER_MSG}


def test_remove_routes_success_clears_all(vpn_mod, registered, monkeypatch):
    registered.routes["1.2.3.4"] = (5, "10.0.0.1")
    registered.routes["5.6.7.8"] = (5, "10.0.0.1")
    monkeypatch.setattr(vpn_mod, "delete_route", lambda ip, if_index, gateway: True)

    result = registered.remove_routes(client_pid=_PARENT_PID)

    assert result == {"ok": True, "error": None}
    assert registered.routes == {}


def test_remove_routes_partial_failure_keeps_failed_entries(vpn_mod, registered, monkeypatch):
    registered.routes["9.9.9.1"] = (5, "10.0.0.1")
    registered.routes["9.9.9.2"] = (5, "10.0.0.1")
    monkeypatch.setattr(vpn_mod, "delete_route", lambda ip, if_index, gateway: ip == "9.9.9.1")

    result = registered.remove_routes(client_pid=_PARENT_PID)

    assert result == {"ok": False, "error": "9.9.9.2: failed to remove route"}
    assert "9.9.9.1" not in registered.routes
    assert "9.9.9.2" in registered.routes


def test_remove_routes_by_parent_when_no_owner(vpn_mod, helper_state, monkeypatch):
    helper_state.routes["1.2.3.4"] = (5, "10.0.0.1")
    monkeypatch.setattr(vpn_mod, "delete_route", lambda ip, if_index, gateway: True)
    assert helper_state.remove_routes(client_pid=_PARENT_PID) == {"ok": True, "error": None}


# --- prepare_split_tunnel / restore_split_tunnel -----------------------------

@pytest.fixture
def split(vpn_mod, monkeypatch):
    rec = types.SimpleNamespace(current=False, set_result=(True, ""), set_calls=[])
    monkeypatch.setattr(
        vpn_mod, "get_vpn_split_tunneling",
        lambda name, all_user=None, timeout=8.0: rec.current,
    )

    def fake_set(name, enabled, all_user=None, timeout=12.0):
        rec.set_calls.append((name, enabled, all_user))
        # Realistic model: a successful write changes the profile's current
        # value. This matters — _restore_split_tunneling_unlocked compares the
        # current value with applied_split_tunneling and does NOT overwrite the
        # profile if it was "already changed by someone else".
        if rec.set_result[0]:
            rec.current = enabled
        return rec.set_result

    monkeypatch.setattr(vpn_mod, "set_vpn_split_tunneling", fake_set)
    return rec


def test_prepare_split_tunnel_enables_and_remembers_previous_value(vpn_mod, helper_state, split):
    split.current = False
    result = helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    assert result == {"ok": True, "already": False, "previous": False}
    assert split.set_calls == [("VPN1", True, None)]
    assert helper_state.saved_split_tunneling is False
    assert helper_state.split_tunnel_connection_name == "VPN1"


def test_prepare_split_tunnel_already_enabled_changes_nothing(vpn_mod, helper_state, split):
    split.current = True
    result = helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    assert result == {"ok": True, "already": True, "previous": True}
    assert split.set_calls == []


def test_prepare_split_tunnel_set_failure_is_reported_and_leaves_no_saved_state(vpn_mod, helper_state, split):
    split.current = False
    split.set_result = (False, "access denied")
    result = helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    assert result["ok"] is False
    assert "access denied" in result["error"]
    assert helper_state.saved_split_tunneling is None
    assert helper_state.split_tunnel_connection_name is None


def test_prepare_split_tunnel_unauthorized_client_rejected(vpn_mod, helper_state, split):
    result = helper_state.prepare_split_tunnel("VPN1", None, 9999)
    assert result == {"ok": False, "error": "prepare_split_tunnel: client is not authorized"}
    assert split.set_calls == []


def test_prepare_split_tunnel_rejects_invalid_profile_name(vpn_mod, helper_state, split):
    # CR/LF in the name are invalid (special characters like ' are now allowed
    # and safely quoted via _ps_quote, see test_ps_quote_*).
    result = helper_state.prepare_split_tunnel("vpn\ncalc", None, _PARENT_PID)
    assert result["ok"] is False
    assert "Invalid VPN/interface name" in result["error"]
    assert split.set_calls == []


def test_prepare_split_tunnel_rejects_profile_other_than_registered_session(vpn_mod, registered, split):
    result = registered.prepare_split_tunnel("SomeOtherVPN", None, _PARENT_PID)
    assert result["ok"] is False
    assert "does not match" in result["error"]
    assert split.set_calls == []


def test_prepare_split_tunnel_refuses_second_profile_while_first_pending(vpn_mod, helper_state, split):
    split.current = False
    assert helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)["ok"] is True
    result = helper_state.prepare_split_tunnel("VPN2", None, _PARENT_PID)
    assert result["ok"] is False
    assert "already pending" in result["error"]
    assert split.set_calls == [("VPN1", True, None)]      # second profile untouched


def test_restore_split_tunnel_restores_previous_value(vpn_mod, helper_state, split):
    split.current = False
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    split.set_calls.clear()
    assert helper_state.restore_split_tunnel(_PARENT_PID) == {"ok": True, "restored": True}
    assert split.set_calls == [("VPN1", False, None)]
    assert helper_state.saved_split_tunneling is None


def _call_failing_fast_on_deadlock(fn, *args, timeout=3.0):
    """Calls fn in a thread: a deadlock turns into a fast test failure instead
    of hanging the whole run (helper._lock is not reentrant)."""
    box = {}

    def target():
        box["result"] = fn(*args)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), f"{fn.__name__}{args}: deadlock (call did not finish in {timeout} s)"
    return box["result"]


def test_restore_split_tunnel_registered_owner_is_authorized(vpn_mod, helper_state, split):
    """The session owner (not matching parent_pid) is still authorized."""
    split.current = False
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    helper_state.owner_pid = 5000                       # owner differs from parent
    helper_state.owner_connection_name = "VPN1"
    helper_state.owner_all_user = None
    split.set_calls.clear()
    result = _call_failing_fast_on_deadlock(helper_state.restore_split_tunnel, 5000)
    assert result == {"ok": True, "restored": True}
    assert split.set_calls == [("VPN1", False, None)]


def test_restore_split_tunnel_nothing_saved_is_noop_for_anyone(vpn_mod, helper_state, split):
    """REGRESSION: for a client that did not pass the first checks, the call
    re-acquired self._lock (via _authorized_client) and hung forever, blocking
    the entire elevated helper."""
    result = _call_failing_fast_on_deadlock(helper_state.restore_split_tunnel, 9999)
    assert result == {"ok": True, "restored": False}
    assert split.set_calls == []


def test_restore_split_tunnel_unauthorized_client_cannot_undo_pending_change(vpn_mod, helper_state, split):
    split.current = False
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    split.set_calls.clear()
    result = _call_failing_fast_on_deadlock(helper_state.restore_split_tunnel, 9999)
    assert result == {"ok": False, "error": "restore_split_tunnel: client is not authorized"}
    assert helper_state.saved_split_tunneling is False           # state untouched


# ---------------------------------------------------------------------------
# Input validators. They are exactly what separates user/network input from
# substitution into PowerShell commands and route.exe arguments.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "MyVPN", "My VPN (work)", "VPN-1.2+x#", "Рабочий VPN", "a" * 256, "VPN\xa0name",
    # PowerShell/cmd special characters are NOT rejected by the validator: the
    # name is substituted only via _ps_quote() (single-quoted literal, where
    # $ ` | ; & < { } " are ordinary characters), and passed to rasdial as an
    # argument list without a shell. The safety of these names is checked by
    # the _ps_quote tests below.
    "vpn'; Remove-Item C:\\; '", 'vpn"x', "vpn$x", "vpn`x", "vpn|x", "vpn;x",
    "vpn&x", "vpn<x", "vpn{x}",
])
def test_validate_vpn_name_accepts_legitimate_names(vpn_mod, name):
    assert vpn_mod._validate_vpn_name(name) == name


def test_validate_vpn_name_strips_surrounding_whitespace(vpn_mod):
    assert vpn_mod._validate_vpn_name("  MyVPN \t") == "MyVPN"


@pytest.mark.parametrize("name", [
    "", "   ", None, 123, b"vpn", "a" * 257,
    "vpn\nx", "vpn\rx", "vpn\x00x", "vpn\x1bx", "vpn\x7fx", "vpn\tx",
])
def test_validate_vpn_name_rejects_empty_nonstring_and_control_chars(vpn_mod, name):
    """We reject empty/non-string/too long and control characters (primarily
    CR/LF — they break a single-line PowerShell command)."""
    with pytest.raises(ValueError):
        vpn_mod._validate_vpn_name(name)


def test_ps_quote_wraps_plain_value(vpn_mod):
    assert vpn_mod._ps_quote("MyVPN") == "'MyVPN'"


def test_ps_quote_doubles_ascii_single_quote(vpn_mod):
    assert vpn_mod._ps_quote("it's") == "'it''s'"


@pytest.mark.parametrize("quote", ["\u2018", "\u2019", "\u201a", "\u201b"])
def test_ps_quote_doubles_typographic_single_quotes(vpn_mod, quote):
    """REGRESSION (security): PowerShell treats U+2018/2019/201A/201B as single
    quotes just like ASCII ', so a single such quote inside a name would close
    the string and allow appending an arbitrary command."""
    assert vpn_mod._ps_quote(f"x{quote}; calc; {quote}") == f"'x{quote}{quote}; calc; {quote}{quote}'"


@pytest.mark.parametrize("name", [
    "vpn'; Remove-Item C:\\; '", "x\u2019; calc; \u2018", "a'b\u201ac",
])
def test_ps_quote_result_has_no_unpaired_single_quote(vpn_mod, name):
    """Inside the literal (between the outer quotes) any quote must be paired —
    a single one would mean exiting the string."""
    quote_chars = "'\u2018\u2019\u201a\u201b"
    quoted = vpn_mod._ps_quote(vpn_mod._validate_vpn_name(name))
    assert quoted[0] == "'" and quoted[-1] == "'"
    inner = quoted[1:-1]
    i = 0
    while i < len(inner):
        if inner[i] in quote_chars:
            assert i + 1 < len(inner) and inner[i + 1] in quote_chars, quoted
            i += 2
        else:
            i += 1


@pytest.mark.parametrize("value", ["1.2.3.4", "10.0.0.1", "192.168.1.1", "8.8.8.8"])
def test_is_valid_route_ip_accepts_ordinary_unicast(vpn_mod, value):
    assert vpn_mod._is_valid_route_ip(value) is True


@pytest.mark.parametrize("value", [
    "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1",
    "255.255.255.255", "256.1.1.1", "1.2.3", "abc", "",
    "1.2.3.4; calc", "1.2.3.4\n", " 1.2.3.4", "1.2.3.4/32", "1.2.3.04",
    None, 12345, b"1.2.3.4",
])
def test_is_valid_route_ip_rejects_special_and_malformed(vpn_mod, value):
    assert vpn_mod._is_valid_route_ip(value) is False


@pytest.mark.parametrize("value", [
    "10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.0.1",
])
def test_is_valid_route_ip_accepts_private_ranges(vpn_mod, value):
    """Private addresses MUST be accepted: the VPN tunnel gateway is almost
    always from RFC 1918 (previously this was controlled by the allow_private
    parameter, now it is gone — the function takes no flags)."""
    assert vpn_mod._is_valid_route_ip(value) is True


def test_is_valid_route_ip_takes_no_flags(vpn_mod):
    """Signature contract: the only argument is value."""
    with pytest.raises(TypeError):
        vpn_mod._is_valid_route_ip("8.8.8.8", allow_private=False)


@pytest.mark.parametrize("value", [1, "12", 0x7FFFFFFF])
def test_is_valid_if_index_accepts_positive_ints(vpn_mod, value):
    assert vpn_mod._is_valid_if_index(value) is True


@pytest.mark.parametrize("value", [0, -1, "abc", "12abc", None, 0x80000000, "", []])
def test_is_valid_if_index_rejects_others(vpn_mod, value):
    assert vpn_mod._is_valid_if_index(value) is False


@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", True),
    ("192.168.1.1", True),
    ("0.0.0.0", False),
    ("0.1.2.3", False),
    ("169.254.10.10", False),
    ("255.255.255.255", False),
    ("", False),
])
def test_is_usable_unicast_ipv4(vpn_mod, ip, expected):
    assert vpn_mod._is_usable_unicast_ipv4(ip) is expected


# ---------------------------------------------------------------------------
# VPN profile scope cache (_get_cached_scope / _set_cached_scope)
# ---------------------------------------------------------------------------

@pytest.fixture
def scope_cache(vpn_mod, monkeypatch):
    vpn_mod._scope_cache.clear()
    now = [500.0]
    monkeypatch.setattr(vpn_mod.time, "monotonic", lambda: now[0])
    yield now
    vpn_mod._scope_cache.clear()


def test_scope_cache_miss_is_none(vpn_mod, scope_cache):
    assert vpn_mod._get_cached_scope("MyVPN") is None


@pytest.mark.parametrize("scope", [True, False])
def test_scope_cache_hit_distinguishes_false_from_missing(vpn_mod, scope_cache, scope):
    vpn_mod._set_cached_scope("MyVPN", scope)
    assert vpn_mod._get_cached_scope("MyVPN") is scope


def test_scope_cache_entry_expires_after_ttl(vpn_mod, scope_cache):
    vpn_mod._set_cached_scope("MyVPN", True)
    scope_cache[0] += vpn_mod._SCOPE_CACHE_TTL - 0.1
    assert vpn_mod._get_cached_scope("MyVPN") is True
    scope_cache[0] += 0.2
    assert vpn_mod._get_cached_scope("MyVPN") is None


def test_scope_cache_is_per_profile_name(vpn_mod, scope_cache):
    vpn_mod._set_cached_scope("A", True)
    assert vpn_mod._get_cached_scope("B") is None


# ---------------------------------------------------------------------------
# file_sha256 / verify_helper_integrity — protection against vpn.exe / vpn.py
# substitution
# ---------------------------------------------------------------------------

def test_file_sha256_matches_hashlib_for_multi_block_file(vpn_mod, tmp_path):
    payload = bytes(range(256)) * 400                    # 102,400 bytes > one read block
    f = tmp_path / "blob.bin"
    f.write_bytes(payload)
    assert vpn_mod.file_sha256(f) == hashlib.sha256(payload).hexdigest()


def test_file_sha256_empty_file(vpn_mod, tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert vpn_mod.file_sha256(f) == hashlib.sha256(b"").hexdigest()


@pytest.fixture
def frozen(monkeypatch):
    """verify_helper_integrity checks the hash only in a frozen build (vpn.exe):
    in dev mode the hash in the source is from the exe, and comparing vpn.py
    with it is meaningless (see the function docstring)."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)


@pytest.fixture
def helper_file(vpn_mod, tmp_path, monkeypatch, frozen):
    f = tmp_path / "vpn_helper.bin"
    f.write_bytes(b"helper-binary")
    monkeypatch.setattr(vpn_mod, "_helper_integrity_target", lambda base_path: f)
    return f


def test_verify_helper_integrity_disabled_when_hash_not_configured(vpn_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(vpn_mod, "EXPECTED_VPN_HELPER_SHA256", "")
    assert vpn_mod.verify_helper_integrity(tmp_path) == (True, "")


def test_verify_helper_integrity_ok_when_hash_matches_case_insensitively(vpn_mod, tmp_path, helper_file, monkeypatch):
    digest = hashlib.sha256(b"helper-binary").hexdigest()
    monkeypatch.setattr(vpn_mod, "EXPECTED_VPN_HELPER_SHA256", "  " + digest.upper() + " ")
    assert vpn_mod.verify_helper_integrity(tmp_path) == (True, "")


def test_verify_helper_integrity_detects_tampering(vpn_mod, tmp_path, helper_file, monkeypatch):
    monkeypatch.setattr(vpn_mod, "EXPECTED_VPN_HELPER_SHA256", "0" * 64)
    ok, reason = vpn_mod.verify_helper_integrity(tmp_path)
    assert ok is False
    assert "hash mismatch" in reason
    assert hashlib.sha256(b"helper-binary").hexdigest() in reason


def test_verify_helper_integrity_skipped_in_dev_mode(vpn_mod, tmp_path, helper_file, monkeypatch):
    """Not frozen: the hash does not match, but the check is intentionally skipped."""
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(vpn_mod, "EXPECTED_VPN_HELPER_SHA256", "0" * 64)
    assert vpn_mod.verify_helper_integrity(tmp_path) == (True, "")


def test_verify_helper_integrity_read_error_is_reported(vpn_mod, tmp_path, helper_file, monkeypatch):
    monkeypatch.setattr(vpn_mod, "EXPECTED_VPN_HELPER_SHA256", "0" * 64)

    def _boom(path):
        raise PermissionError("denied")

    monkeypatch.setattr(vpn_mod, "file_sha256", _boom)
    ok, reason = vpn_mod.verify_helper_integrity(tmp_path)
    assert ok is False
    assert "failed to read" in reason


def test_helper_integrity_target_is_exe_when_frozen(vpn_mod, tmp_path, frozen):
    assert vpn_mod._helper_integrity_target(tmp_path) == tmp_path / "vpn.exe"


def test_helper_integrity_target_is_this_file_in_dev_mode(vpn_mod, tmp_path, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    target = vpn_mod._helper_integrity_target(tmp_path)
    assert target.name == "vpn.py"


def test_verify_helper_integrity_missing_file(vpn_mod, tmp_path, monkeypatch, frozen):
    monkeypatch.setattr(vpn_mod, "EXPECTED_VPN_HELPER_SHA256", "0" * 64)
    monkeypatch.setattr(vpn_mod, "_helper_integrity_target", lambda base_path: tmp_path / "missing.exe")
    ok, reason = vpn_mod.verify_helper_integrity(tmp_path)
    assert ok is False
    assert "not found" in reason


# ---------------------------------------------------------------------------
# Parent authorization: fail-closed on parent_start_time (PID reuse protection).
# Without a process creation timestamp the helper cannot distinguish the real
# GUI from a foreign process to which Windows assigned the same PID after the
# GUI died, so ALL parent paths are rejected.
# ---------------------------------------------------------------------------

@pytest.fixture
def helper_state_no_start_time(vpn_mod, monkeypatch):
    """Helper launched by an "old client" — without --parent-start-time."""
    monkeypatch.setattr(vpn_mod, "_process_alive", lambda pid: True)
    monkeypatch.setattr(vpn_mod, "_process_same_user", lambda pid: True, raising=False)
    monkeypatch.setattr(vpn_mod, "_process_start_time", lambda pid: _PARENT_START)
    state = vpn_mod.VpnHelperState(parent_pid=_PARENT_PID)
    state.start_monitor = lambda: None

    def fake_exit():
        raise _HelperExit()

    state._exit_helper = fake_exit
    return state


def test_helper_state_constructor_signature(vpn_mod):
    """Regression: previously the first positional argument was the state directory."""
    state = vpn_mod.VpnHelperState(4242, 123)
    assert state.parent_pid == 4242
    assert state.parent_start_time == 123
    assert vpn_mod.VpnHelperState().parent_pid is None


def test_helper_state_ignores_non_int_parent_start_time(vpn_mod):
    assert vpn_mod.VpnHelperState(1, "123").parent_start_time is None
    assert vpn_mod.VpnHelperState(1, None).parent_start_time is None


def test_parent_authorized_true_when_alive_and_start_time_matches(vpn_mod, helper_state):
    assert helper_state._parent_authorized() is True


def test_parent_authorized_false_when_pid_reused_by_other_process(vpn_mod, helper_state, monkeypatch):
    """The PID is the same and "alive", but the process creation time is
    different — this is not our GUI."""
    monkeypatch.setattr(vpn_mod, "_process_start_time", lambda pid: _PARENT_START + 1)
    assert helper_state._parent_alive() is False
    assert helper_state._parent_authorized() is False


def test_parent_authorized_false_when_start_time_unreadable(vpn_mod, helper_state, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_process_start_time", lambda pid: None)
    assert helper_state._parent_authorized() is False


def test_parent_authorized_false_when_parent_dead(vpn_mod, helper_state, monkeypatch):
    monkeypatch.setattr(vpn_mod, "_process_alive", lambda pid: False)
    assert helper_state._parent_authorized() is False


def test_parent_alive_without_start_time_only_checks_liveness(vpn_mod, helper_state_no_start_time):
    """_parent_alive is intentionally looser than _parent_authorized: the helper
    must not kill itself just because it could not read the timestamp."""
    assert helper_state_no_start_time._parent_alive() is True
    assert helper_state_no_start_time._parent_authorized() is False


def test_no_start_time_denies_register_with_actionable_error(vpn_mod, helper_state_no_start_time):
    result = helper_state_no_start_time.register_client(pid=_PARENT_PID, connection_name="VPN1")
    assert result["ok"] is False
    assert "parent-start-time" in result["error"]
    assert helper_state_no_start_time.owner_pid is None


def test_no_start_time_denies_all_parent_paths(vpn_mod, helper_state_no_start_time):
    st = helper_state_no_start_time
    with st._lock:
        assert st._register_authorized_unlocked(_PARENT_PID) is False
        assert st._routes_authorized_unlocked(_PARENT_PID) is False
        assert st._shutdown_authorized_unlocked(_PARENT_PID) is False
        assert st._network_ops_authorized_unlocked(_PARENT_PID) is False


def test_no_start_time_check_network_ops_explains_reason_in_log(vpn_mod, helper_state_no_start_time, caplog):
    with caplog.at_level("WARNING", logger="vpn_helper"):
        result = helper_state_no_start_time.check_network_ops(_PARENT_PID, "arp_flush")
    assert result == {"ok": False, "error": "arp_flush: client is not authorized"}
    assert "parent-start-time" in caplog.text


def test_pid_reuse_after_registration_does_not_affect_owner(vpn_mod, registered, monkeypatch):
    """An already registered owner is authorized by owner_pid, not by the
    parent timestamp: changing the parent's start_time does not affect them."""
    monkeypatch.setattr(vpn_mod, "_process_start_time", lambda pid: _PARENT_START + 1)
    with registered._lock:
        assert registered._routes_authorized_unlocked(_PARENT_PID) is True


# --- add_routes: three outcomes of VPN adapter lookup ------------------------

def test_add_routes_adapter_missing_reports_not_present(vpn_mod, registered, as_client, owner_iface):
    as_client(_PARENT_PID)
    owner_iface.result = (None, None)
    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])
    assert result["ok"] is False and result["added"] == []
    assert vpn_mod.IFACE_UNDETERMINED_MARKER in result["error"]
    assert "not present" in result["error"]


def test_add_routes_adapter_state_unknown_is_distinguished_from_missing(vpn_mod, registered, as_client, owner_iface):
    """UNKNOWN ("failed to read the table") is a separate wording:
    "adapter absent" and "I don't know" must not be merged into one signal."""
    as_client(_PARENT_PID)
    owner_iface.state = vpn_mod.InterfaceLookupState.UNKNOWN
    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])
    assert result["ok"] is False and result["added"] == []
    assert vpn_mod.IFACE_UNDETERMINED_MARKER in result["error"]
    assert "state unknown" in result["error"]
    assert "not present" not in result["error"]


def test_add_routes_found_but_no_ifindex_is_rejected(vpn_mod, registered, as_client, monkeypatch):
    as_client(_PARENT_PID)
    monkeypatch.setattr(
        vpn_mod, "_lookup_interface_by_name",
        lambda name: (vpn_mod.InterfaceLookupState.FOUND, None, "10.0.0.2"),
    )
    result = registered.add_routes([("1.2.3.4", 5, "10.0.0.1")])
    assert result["ok"] is False and result["added"] == []
    assert "no IfIndex" in result["error"]


def test_explain_lookup_failure_messages(vpn_mod):
    S = vpn_mod.InterfaceLookupState
    f = vpn_mod._explain_lookup_failure
    assert "not present" in f("V", S.MISSING, None, None)
    assert "state unknown" in f("V", S.UNKNOWN, None, None)
    assert "no IfIndex" in f("V", S.FOUND, None, None)
    assert "IPv4 address is not assigned" in f("V", S.FOUND, 7, None, expect_ipv4=True)


# --- SplitTunneling: do not overwrite someone else's profile changes ---------

def test_restore_split_tunnel_does_not_overwrite_change_made_by_someone_else(vpn_mod, helper_state, split):
    split.current = False
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)     # we set True
    assert helper_state.applied_split_tunneling is True
    split.current = False                                            # then the profile was changed externally
    split.set_calls.clear()

    result = helper_state.restore_split_tunnel(_PARENT_PID)

    assert result == {"ok": True, "restored": True}
    assert split.set_calls == []                                     # do not touch someone else's value
    assert helper_state.saved_split_tunneling is None                # but our state is cleared
    assert helper_state.split_tunnel_connection_name is None


def test_restore_split_tunnel_unknown_current_state_keeps_state_for_retry(vpn_mod, helper_state, split):
    split.current = False
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    split.current = None                                             # PowerShell failed
    split.set_calls.clear()
    helper_state.restore_split_tunnel(_PARENT_PID)
    assert split.set_calls == []                                     # do not write blindly
    assert helper_state.saved_split_tunneling is False               # state is preserved
    assert helper_state.split_tunnel_connection_name == "VPN1"
    # retry when reading works again and the value is ours
    split.current = True
    helper_state.restore_split_tunnel(_PARENT_PID)
    assert split.set_calls == [("VPN1", False, None)]
    assert helper_state.saved_split_tunneling is None


def test_prepare_split_tunnel_records_applied_value(vpn_mod, helper_state, split):
    split.current = False
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    assert helper_state.applied_split_tunneling is True


def test_prepare_split_tunnel_already_enabled_leaves_applied_none(vpn_mod, helper_state, split):
    """The profile was already True — we did not change anything, applied stays None."""
    split.current = True
    helper_state.prepare_split_tunnel("VPN1", None, _PARENT_PID)
    assert helper_state.applied_split_tunneling is None