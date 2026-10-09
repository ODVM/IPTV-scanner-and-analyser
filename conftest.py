"""
Shared fixtures for IPTV_scanner.pyw tests.

The scanner file has a .pyw extension, so a regular `import` will not work —
we load it via importlib with an explicit SourceFileLoader.
"""
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader

import pytest

MODULE_PATH = os.path.join(os.path.dirname(__file__), "IPTV_scanner.pyw")
VPN_MODULE_PATH = os.path.join(os.path.dirname(__file__), "vpn.py")


def _load_scanner_module():
    loader = SourceFileLoader("iptv_scanner_mod", MODULE_PATH)
    spec = importlib.util.spec_from_loader("iptv_scanner_mod", loader)
    module = importlib.util.module_from_spec(spec)
    # Required for dataclass with `from __future__ import annotations`: during
    # field resolution it looks up its module in sys.modules by __module__.
    sys.modules["iptv_scanner_mod"] = module
    loader.exec_module(module)
    return module


# The module is heavy (it creates a top-level GUI class, but does NOT build a window —
# tk.Tk() is created only in ScannerGUI.__init__, which the tests do not call),
# so we load it once per session.
@pytest.fixture(scope="session")
def scanner_mod():
    return _load_scanner_module()


def _load_vpn_module():
    """vpn.py is imported as a regular .py module (not .pyw), but we still
    load it via SourceFileLoader rather than a regular `import vpn` — this way
    the tests do not depend on the pytest working directory actually containing
    vpn.py on sys.path.

    On non-Windows platforms (including in CI), all Windows-only code inside
    the module is hidden behind `if IS_WINDOWS:` at the module/function level
    (ctypes.WinDLL, winreg, etc.), so importing the module itself is safe on
    Linux too — the tests cover only the cross-platform part (parsing,
    decoding, network probes, pure VpnHelperState logic) plus the contract
    that "on non-Windows the function returns False / raises HelperError",
    which is also part of the module's public behavior.
    """
    loader = SourceFileLoader("iptv_scanner_vpn_mod", VPN_MODULE_PATH)
    spec = importlib.util.spec_from_loader("iptv_scanner_vpn_mod", loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules["iptv_scanner_vpn_mod"] = module
    loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def vpn_mod():
    return _load_vpn_module()


def build_ts_packet(
    scanner_mod,
    pid: int,
    payload: bytes,
    payload_unit_start: bool = True,
    cc: int = 0,
    scrambling: int = 0,
    discontinuity: bool = False,
) -> bytes:
    """Builds a synthetic 188-byte TS packet with the given PID and payload.

    If discontinuity=True, adds an adaptation field with
    discontinuity_indicator=1 before the payload (adaptation_field_control=11).
    """
    TS_PACKET_SIZE = scanner_mod.TS_PACKET_SIZE
    header = bytearray(4)
    header[0] = 0x47
    header[1] = (0x40 if payload_unit_start else 0x00) | ((pid >> 8) & 0x1F)
    header[2] = pid & 0xFF

    if discontinuity:
        # adaptation_field_control = 11 (adaptation field + payload)
        af = bytearray()
        af.append(1)  # adaptation_field_length (flags only, 1 byte)
        af.append(0x80)  # discontinuity_indicator = 1, other flags 0
        header[3] = (scrambling << 6) | 0x30 | (cc & 0x0F)
        body = bytes(af) + payload
    else:
        header[3] = (scrambling << 6) | 0x10 | (cc & 0x0F)  # payload only
        body = payload

    pad_len = TS_PACKET_SIZE - 4 - len(body)
    if pad_len < 0:
        raise ValueError("payload слишком большой для одного TS-пакета")
    packet = bytes(header) + body + b"\xFF" * pad_len
    assert len(packet) == TS_PACKET_SIZE
    return packet


def build_null_packet(scanner_mod) -> bytes:
    return build_ts_packet(scanner_mod, pid=0x1FFF, payload=b"\x00" * 184)


def build_pat_section(scanner_mod, programs, transport_stream_id: int = 1) -> bytes:
    """programs: list of (program_number, pmt_pid)."""
    body = bytearray()
    body += transport_stream_id.to_bytes(2, "big")
    body += bytes([0xC1])  # reserved(2)=11, version=00000, current_next=1
    body += bytes([0x00])  # section_number
    body += bytes([0x00])  # last_section_number
    for prog_num, pmt_pid in programs:
        body += prog_num.to_bytes(2, "big")
        body += (0xE000 | pmt_pid).to_bytes(2, "big")
    section_length = len(body) + 4  # + CRC32
    header = bytes([0x00]) + (0xB000 | section_length).to_bytes(2, "big")
    full = bytearray(header) + body
    crc = scanner_mod._mpeg2_crc32(bytes(full))
    return bytes(full) + crc.to_bytes(4, "big")


def build_pmt_section(
    scanner_mod, streams, pcr_pid: int = 0x0100, program_number: int = 1
) -> bytes:
    """streams: list of (stream_type, elementary_pid) or
    (stream_type, elementary_pid, es_info_bytes) — the third element is a ready-made
    ES_info descriptor loop (for example, b"\\x6A\\x00" is an AC-3 descriptor)."""
    body = bytearray()
    body += program_number.to_bytes(2, "big")
    body += bytes([0xC1])
    body += bytes([0x00])  # section_number
    body += bytes([0x00])  # last_section_number
    body += (0xE000 | pcr_pid).to_bytes(2, "big")
    body += (0xF000 | 0).to_bytes(2, "big")  # program_info_length = 0
    for entry in streams:
        stream_type, pid = entry[0], entry[1]
        es_info = entry[2] if len(entry) > 2 else b""
        body.append(stream_type)
        body += (0xE000 | pid).to_bytes(2, "big")
        body += (0xF000 | len(es_info)).to_bytes(2, "big")  # ES info length
        body += es_info
    section_length = len(body) + 4
    header = bytes([0x02]) + (0xB000 | section_length).to_bytes(2, "big")
    full = bytearray(header) + body
    crc = scanner_mod._mpeg2_crc32(bytes(full))
    return bytes(full) + crc.to_bytes(4, "big")


def build_psi_packet(scanner_mod, pid: int, section: bytes, cc: int = 0) -> bytes:
    """Packs a complete PSI section into a single TS packet (pointer_field=0)."""
    payload = bytes([0x00]) + section  # pointer_field = 0
    return build_ts_packet(scanner_mod, pid=pid, payload=payload, payload_unit_start=True, cc=cc)


def build_h264_nal_payload(nal_types) -> bytes:
    """PES-like payload with several Annex-B NAL units in a row.
    Not a full PES (no valid header) — this is sufficient because
    analyze_start_codes searches for the 000001 start code throughout the payload
    regardless of the PES structure."""
    out = bytearray()
    for nal_type in nal_types:
        out += b"\x00\x00\x01"
        out.append(nal_type & 0x1F)  # nal_unit_header (H.264): forbidden(0)+ref(00)+type
        out += b"\x00\x00\x00"  # a bit of NAL "body" so as not to confuse with the next start code
    return bytes(out)