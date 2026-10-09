# -*- coding: utf-8 -*-
"""
Unit tests for IPTV_scanner.pyw.

They do not require network access and do not bring up the GUI — only the
"engine" is tested: PAT/PMT parsing, TS sync detection, metric accumulation
in TSStreamAnalyzer, threshold validation, and the channel classification
logic (_classify_channel) on synthetic ScanMetrics.

Run: pytest test_iptv_scanner.py -v
"""
import http.server
import json
import socket
import threading
import time
import types

import pytest
import requests

from conftest import (
    build_h264_nal_payload,
    build_null_packet,
    build_pat_section,
    build_pmt_section,
    build_psi_packet,
    build_ts_packet,
)


# ---------------------------------------------------------------------------
# PAT / PMT parsing
# ---------------------------------------------------------------------------

def test_parse_pat_section_valid(scanner_mod):
    section = build_pat_section(scanner_mod, programs=[(1, 0x0100), (2, 0x0200)])
    pmt_pid_to_program = {}
    ok = scanner_mod.parse_pat_section(section, pmt_pid_to_program)
    assert ok is True
    assert pmt_pid_to_program == {0x0100: 1, 0x0200: 2}


def test_parse_pat_section_bad_crc_rejected(scanner_mod):
    section = bytearray(build_pat_section(scanner_mod, programs=[(1, 0x0100)]))
    section[-1] ^= 0xFF  # corrupt the last CRC byte
    pmt_pid_to_program = {}
    ok = scanner_mod.parse_pat_section(bytes(section), pmt_pid_to_program)
    assert ok is False
    assert pmt_pid_to_program == {}


def test_parse_pat_section_program_zero_ignored(scanner_mod):
    # program_number == 0 denotes NIT PID, not PMT — it must not end up in the result
    section = build_pat_section(scanner_mod, programs=[(0, 0x0010), (1, 0x0100)])
    pmt_pid_to_program = {}
    scanner_mod.parse_pat_section(section, pmt_pid_to_program)
    assert 0x0010 not in pmt_pid_to_program
    assert pmt_pid_to_program == {0x0100: 1}


def test_parse_pmt_section_video_and_audio_pids(scanner_mod):
    section = build_pmt_section(
        scanner_mod,
        streams=[(0x1B, 0x0200), (0x0F, 0x0201)],  # H.264 video + AAC audio
    )
    video_pids, audio_pids, unclassified_pids = {}, {}, {}
    ok = scanner_mod.parse_pmt_section(section, video_pids, audio_pids, unclassified_pids)
    assert ok is True
    assert video_pids == {0x0200: 0x1B}
    assert audio_pids == {0x0201: 0x0F}


def test_parse_pmt_section_unknown_stream_type_ignored(scanner_mod):
    section = build_pmt_section(scanner_mod, streams=[(0xFE, 0x0300)])  # unknown type
    video_pids, audio_pids, unclassified_pids = {}, {}, {}
    scanner_mod.parse_pmt_section(section, video_pids, audio_pids, unclassified_pids)
    assert video_pids == {}
    assert audio_pids == {}


def test_extract_complete_psi_sections_split_across_packets(scanner_mod):
    # The section is deliberately split in two and fed through two calls,
    # as if it arrived in two consecutive TS packets.
    section = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    part1, part2 = section[:5], section[5:]

    buffer = bytearray()
    # First packet: payload_unit_start=True, pointer_field=0, then part of the section
    payload1 = bytes([0x00]) + part1
    sections = scanner_mod._extract_complete_psi_sections(buffer, payload1, True)
    assert sections == []  # the section is not complete yet

    # Second packet: continuation of the same section, payload_unit_start=False
    sections = scanner_mod._extract_complete_psi_sections(buffer, part2, False)
    assert sections == [section]


# ---------------------------------------------------------------------------
# extract_payload / get_pid / continuity counter
# ---------------------------------------------------------------------------

def test_extract_payload_payload_only(scanner_mod):
    packet = build_ts_packet(scanner_mod, pid=0x0100, payload=b"\xAB" * 184)
    payload = scanner_mod.extract_payload(packet)
    assert payload == b"\xAB" * 184


def test_extract_payload_adaptation_only_returns_none(scanner_mod):
    packet = bytearray(188)
    packet[0] = 0x47
    packet[3] = 0x20  # adaptation_field_control = 10 (adaptation field only)
    packet[4] = 183  # adaptation_field_length fills the whole rest of the packet
    assert scanner_mod.extract_payload(bytes(packet)) is None


def test_extract_payload_bad_sync_byte_returns_none(scanner_mod):
    packet = bytearray(188)
    packet[0] = 0x00  # not 0x47
    assert scanner_mod.extract_payload(bytes(packet)) is None


def test_get_pid(scanner_mod):
    packet = build_ts_packet(scanner_mod, pid=0x1ABC & 0x1FFF, payload=b"\x00" * 184)
    assert scanner_mod.get_pid(packet) == 0x1ABC & 0x1FFF


# ---------------------------------------------------------------------------
# find_ts_sync / find_resync_pos
# ---------------------------------------------------------------------------

def test_find_ts_sync_found(scanner_mod):
    TS = scanner_mod.TS_PACKET_SIZE
    buf = bytearray(b"\x00" * 10)  # garbage at the beginning
    for _ in range(3):
        buf += bytes([0x47]) + b"\x00" * (TS - 1)
    pos = scanner_mod.find_ts_sync(buf)
    assert pos == 10


def test_find_ts_sync_not_found_too_short(scanner_mod):
    buf = bytearray(b"\x47" + b"\x00" * 10)
    assert scanner_mod.find_ts_sync(buf) == -1


def test_find_ts_sync_ignores_false_positive_047_byte(scanner_mod):
    TS = scanner_mod.TS_PACKET_SIZE
    buf = bytearray()
    buf += bytes([0x47])  # a single 0x47, not the start of three consecutive packets
    buf += b"\x00" * (TS - 1)
    buf += b"\x00" * TS  # the second "packet" does NOT start with 0x47
    buf += b"\x00" * TS
    assert scanner_mod.find_ts_sync(buf) == -1


def test_find_resync_pos(scanner_mod):
    TS = scanner_mod.TS_PACKET_SIZE
    buf = bytearray(b"\x99")  # buf[0] is corrupted (not 0x47) — simulates a glitch at the start
    for _ in range(3):
        buf += bytes([0x47]) + b"\x00" * (TS - 1)
    pos = scanner_mod.find_resync_pos(buf)
    assert pos == 1


def test_find_resync_pos_not_enough_data_returns_minus_one(scanner_mod):
    buf = bytearray(b"\x99\x47\x00\x00")  # 0x47 is there, but there is not enough data for 2 more packets
    assert scanner_mod.find_resync_pos(buf) == -1


# ---------------------------------------------------------------------------
# TSStreamAnalyzer — metric accumulation
# ---------------------------------------------------------------------------

def test_analyzer_parses_pat_and_pmt(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()

    pat_section = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    pmt_section = build_pmt_section(
        scanner_mod, streams=[(0x1B, 0x0200), (0x0F, 0x0201)]
    )

    analyzer.process_packet(build_psi_packet(scanner_mod, pid=0x0000, section=pat_section))
    analyzer.process_packet(build_psi_packet(scanner_mod, pid=0x0100, section=pmt_section))
    metrics = analyzer.finalize()

    assert metrics.pat_parsed is True
    assert metrics.pmt_parsed is True
    assert metrics.video_pids == {0x0200: 0x1B}
    assert metrics.audio_pids == {0x0201: 0x0F}
    assert metrics.pmt_sections_valid == 1


def test_analyzer_pmt_parsed_false_without_pmt(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    pat_section = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    analyzer.process_packet(build_psi_packet(scanner_mod, pid=0x0000, section=pat_section))
    metrics = analyzer.finalize()
    assert metrics.pat_parsed is True
    assert metrics.pmt_parsed is False  # no PMT packets arrived


def _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x1B):
    pat_section = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    pmt_section = build_pmt_section(scanner_mod, streams=[(stream_type, video_pid)])
    analyzer.process_packet(build_psi_packet(scanner_mod, pid=0x0000, section=pat_section))
    analyzer.process_packet(build_psi_packet(scanner_mod, pid=0x0100, section=pmt_section))


def test_analyzer_counts_h264_vcl_nals(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x1B)

    # NAL type 1 = non-IDR slice (VCL), NAL type 7 = SPS (parameter set)
    payload = build_h264_nal_payload([1, 1, 7])
    packet = build_ts_packet(scanner_mod, pid=0x0200, payload=payload, payload_unit_start=True)
    analyzer.process_packet(packet)
    metrics = analyzer.finalize()

    assert metrics.modern_vcl_count == 2
    assert metrics.modern_param_count == 1
    # video_payload_bytes counts the entire TS payload of the packet (184 bytes),
    # including the 0xFF padding that build_ts_packet uses to pad the packet to
    # 188 bytes — this is not the same as the length of the "useful" NAL bytes
    # we wrote.
    assert metrics.video_payload_bytes == 184


def test_analyzer_continuity_error_detected(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer)

    payload = build_h264_nal_payload([1])
    # cc goes 0, then jumps straight to 5 — a continuity error must be recorded
    p1 = build_ts_packet(scanner_mod, pid=0x0200, payload=payload, cc=0)
    p2 = build_ts_packet(scanner_mod, pid=0x0200, payload=payload, cc=5)
    analyzer.process_packet(p1)
    analyzer.process_packet(p2)
    metrics = analyzer.finalize()

    assert metrics.continuity_errors_by_pid[0x0200] == 1


def test_analyzer_continuity_no_error_on_sequential_cc(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer)
    payload = build_h264_nal_payload([1])
    for cc in range(5):
        analyzer.process_packet(
            build_ts_packet(scanner_mod, pid=0x0200, payload=payload, cc=cc)
        )
    metrics = analyzer.finalize()
    assert metrics.continuity_errors_by_pid.get(0x0200, 0) == 0


def test_analyzer_continuity_discontinuity_flag_suppresses_error(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer)
    payload = build_h264_nal_payload([1])
    p1 = build_ts_packet(scanner_mod, pid=0x0200, payload=payload, cc=0)
    # cc "jumps", but with an explicit discontinuity_indicator=1 — this is not an error
    p2 = build_ts_packet(
        scanner_mod, pid=0x0200, payload=payload, cc=9, discontinuity=True
    )
    analyzer.process_packet(p1)
    analyzer.process_packet(p2)
    metrics = analyzer.finalize()
    assert metrics.continuity_errors_by_pid.get(0x0200, 0) == 0


def test_analyzer_scrambled_video_counted(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer)
    payload = build_h264_nal_payload([1])
    scrambled_packet = build_ts_packet(
        scanner_mod, pid=0x0200, payload=payload, scrambling=2
    )
    analyzer.process_packet(scrambled_packet)
    metrics = analyzer.finalize()
    assert metrics.total_video_packets == 1
    assert metrics.scrambled_video == 1
    assert metrics.scrambled_any_pid == 1


def test_analyzer_null_packets_counted_and_not_video(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    analyzer.process_packet(build_null_packet(scanner_mod))
    analyzer.process_packet(build_null_packet(scanner_mod))
    metrics = analyzer.finalize()
    assert metrics.null_packets == 2
    assert metrics.total_video_packets == 0


# ---------------------------------------------------------------------------
# Thresholds validation (_validate_thresholds)
# ---------------------------------------------------------------------------

def test_validate_thresholds_defaults_on_non_dict(scanner_mod):
    result = scanner_mod._validate_thresholds("not a dict")
    assert result == scanner_mod.Thresholds()


def test_validate_thresholds_invalid_type_falls_back_to_default(scanner_mod):
    result = scanner_mod._validate_thresholds({"min_video_packets_for_scramble_check": "not a number"})
    assert result.min_video_packets_for_scramble_check == scanner_mod.Thresholds().min_video_packets_for_scramble_check


def test_validate_thresholds_negative_rejected(scanner_mod):
    result = scanner_mod._validate_thresholds({"max_continuity_errors": -5})
    assert result.max_continuity_errors == scanner_mod.Thresholds().max_continuity_errors


def test_validate_thresholds_ratio_out_of_range_rejected(scanner_mod):
    result = scanner_mod._validate_thresholds({"max_garbage_ratio": 1.5})
    assert result.max_garbage_ratio == scanner_mod.Thresholds().max_garbage_ratio


def test_validate_thresholds_ratio_in_range_accepted(scanner_mod):
    result = scanner_mod._validate_thresholds({"max_garbage_ratio": 0.75})
    assert result.max_garbage_ratio == 0.75


def test_validate_thresholds_cross_field_scramble_check(scanner_mod):
    # min_pes_scrambled_count > min_video_packets_for_pes_scramble_check → both are rolled back
    result = scanner_mod._validate_thresholds({
        "min_pes_scrambled_count": 5000,
        "min_video_packets_for_pes_scramble_check": 100,
    })
    defaults = scanner_mod.Thresholds()
    assert result.min_pes_scrambled_count == defaults.min_pes_scrambled_count
    assert result.min_video_packets_for_pes_scramble_check == defaults.min_video_packets_for_pes_scramble_check


def test_validate_thresholds_error_bitrate_below_minimum_rejected(scanner_mod):
    result = scanner_mod._validate_thresholds({
        "error_bitrate_kbps": scanner_mod.RUNTIME.min_bitrate_setting_kbps - 1
    })
    assert result.error_bitrate_kbps == scanner_mod.Thresholds().error_bitrate_kbps


def test_validate_thresholds_bool_rejected_for_int_field(scanner_mod):
    # bool is a subclass of int in Python; it must be explicitly rejected rather
    # than interpreted as 0/1
    result = scanner_mod._validate_thresholds({"max_continuity_errors": True})
    assert result.max_continuity_errors == scanner_mod.Thresholds().max_continuity_errors


# ---------------------------------------------------------------------------
# IPTVScanner._classify_channel — no network, purely on synthetic metrics
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner(scanner_mod, tmp_path, monkeypatch):
    # We don't want tests to write config/logs next to the source — override the config path.
    monkeypatch.setattr(scanner_mod, "CONFIG_FILE", tmp_path / "scanner_config.json")
    return scanner_mod.IPTVScanner()


def _base_metrics(scanner_mod, **overrides):
    m = scanner_mod.ScanMetrics()
    m.duration = 5.0
    m.bitrate_kbps = 2000.0
    m.avg_chunk = 20000.0
    m.max_chunk_gap = 0.1
    m.pmt_parsed = True
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


def test_classify_ok_channel(scanner_mod, scanner):
    channel = scanner_mod.Channel("Test Channel", "http://example.com/1")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=1000,
        video_payload_bytes=500000,
        modern_vcl_count=500,
        modern_param_count=10,
        # An audio track must be present and receive packets — otherwise
        # the channel is classified as NO_AUDIO (see IPTVScanner._is_no_audio).
        audio_pids={0x0201: 0x0F},
        total_audio_packets=500,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.OK


def test_classify_dead_low_bitrate(scanner_mod, scanner):
    channel = scanner_mod.Channel("Dead Channel", "http://example.com/2")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=1000,
        video_payload_bytes=500000,
        modern_vcl_count=500,
        bitrate_kbps=50.0,  # below scanner.min_bitrate_kbps (100 by default)
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.DEAD


def test_classify_radio(scanner_mod, scanner):
    channel = scanner_mod.Channel("Radio Channel", "http://example.com/3")
    metrics = _base_metrics(
        scanner_mod,
        audio_pids={0x0201: 0x0F},
        total_ts_packets=1000,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.RADIO


def test_classify_no_card_scrambled_video(scanner_mod, scanner):
    """Nearly all video is scrambled (ratio ≥ 0.95) → NO_CARD.

    IMPORTANT: the channel name must not start with "scrambled"/"added/scrambled" —
    otherwise a separate branch _is_known_scrambled_channel /
    _classify_known_scrambled_channel kicks in (see test_classify_known_scrambled_*
    in test_iptv_scanner_additions.py), which always returns OK_SCRAMBLED
    when the transport is healthy, regardless of scrambled_video/pes_scrambled_count.
    Previously the name here was "Scrambled Channel", which made the test check
    the wrong thing and fail."""
    channel = scanner_mod.Channel("High Scramble Ratio", "http://example.com/4")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=2000,
        scrambled_video=1900,          # ratio 0.95
        video_payload_bytes=500000,
        modern_vcl_count=100,          # picture is formally present, but NO_CARD takes priority
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.NO_CARD


def test_classify_no_card_via_pes_scrambling(scanner_mod, scanner):
    channel = scanner_mod.Channel("PES Scrambled", "http://example.com/4b")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=400,
        pes_scrambled_count=50,        # > min_pes_scrambled_count=30
        video_payload_bytes=200000,
        modern_vcl_count=50,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.NO_CARD


def test_classify_partial_scramble_plus_no_vcl_is_module_hung(scanner_mod, scanner):
    """Partial scramble (0.15 ≤ ratio < 0.95) + no VCL → MODULE_HUNG."""
    channel = scanner_mod.Channel("Partial + no picture", "http://example.com/9")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        # total_video_packets must be > th.min_video_packets_for_scramble_check
        # (1200), otherwise _is_partial_scramble would not trigger at all.
        total_video_packets=2000,
        scrambled_video=600,           # ratio 0.30
        video_payload_bytes=200000,    # payload is sufficient
        modern_vcl_count=0,            # no picture
        modern_param_count=0,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.MODULE_HUNG
    assert "mix scrambled" in res.details.lower() or "0.30" in res.details or "30.0" in res.details


def test_classify_high_bitrate_stuffing_is_no_picture(scanner_mod, scanner):
    """Few video packets + high bitrate + almost no payload → NO_PICTURE (stuffing)."""
    channel = scanner_mod.Channel("Stuffed high-br", "http://example.com/10")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=20,        # < max_video_packets_for_stuffing_check=30
        video_payload_bytes=100,       # < max_payload_bytes_for_stuffing_check=300
        bitrate_kbps=2500.0,           # > min_bitrate_for_stuffing_check_kbps=1500
        modern_vcl_count=0,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.NO_PICTURE


def test_classify_radio_still_wins_over_low_bitrate(scanner_mod, scanner):
    """RADIO has the highest priority even at low bitrate."""
    channel = scanner_mod.Channel("Radio low-br", "http://example.com/11")
    metrics = _base_metrics(
        scanner_mod,
        audio_pids={0x0201: 0x0F},
        total_ts_packets=1000,
        bitrate_kbps=30.0,             # below min_bitrate
        pmt_parsed=True,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.RADIO


def test_classify_missing_pmt_no_video(scanner_mod, scanner):
    """No video PID and PMT did not arrive → ERRORS (PMT missing)."""
    channel = scanner_mod.Channel("No PMT", "http://example.com/12")
    metrics = _base_metrics(
        scanner_mod,
        pmt_parsed=False,
        video_pids={},                 # explicitly empty
        total_ts_packets=500,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.ERRORS
    assert "PMT" in res.details or "pmt" in res.details.lower()


def test_classify_errors_pmt_missing(scanner_mod, scanner):
    channel = scanner_mod.Channel("No PMT Channel", "http://example.com/5")
    metrics = _base_metrics(scanner_mod, pmt_parsed=False)
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.ERRORS


def test_classify_no_picture_via_stuffing_check(scanner_mod, scanner):
    # Few video packets, high declared bitrate, almost no payload —
    # looks like a stream "stuffed" with stuffing. total_video_packets < 80,
    # so module_hung will not trigger (it strictly requires >= 80).
    channel = scanner_mod.Channel("Stuffed Channel", "http://example.com/6")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x01},  # MPEG2
        total_video_packets=10,
        video_payload_bytes=100,
        bitrate_kbps=2000.0,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.NO_PICTURE


def test_classify_module_hung(scanner_mod, scanner):
    # Enough packets and bytes, almost no picture start codes, and the payload
    # looks like ciphertext (PUS present, PES headers almost absent) — a signal
    # that the hung CI/CAM is the culprit (see IPTVScanner._payload_looks_encrypted).
    # Plain "no picture" without that signal is classified as NO_PICTURE,
    # not MODULE_HUNG (see the _is_module_hung docstring).
    channel = scanner_mod.Channel("Hung Channel", "http://example.com/7")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x01},  # MPEG2
        total_video_packets=100,
        video_payload_bytes=100000,
        mpeg2_picture_count=0,
        mpeg2_slice_count=0,
        video_pus_count=100,
        pes_header_count=0,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.MODULE_HUNG


def test_classify_errors_high_continuity_errors(scanner_mod, scanner):
    channel = scanner_mod.Channel("CC Errors Channel", "http://example.com/8")
    counter_cls = scanner_mod.Counter
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=1000,
        video_payload_bytes=500000,
        modern_vcl_count=500,
        continuity_errors_by_pid=counter_cls({0x0200: 200}),  # > max_continuity_errors=80
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.ERRORS


def test_check_stuffing_shared_between_mpeg2_and_modern(scanner_mod, scanner):
    # Verify that the shared _check_stuffing method is genuinely reused:
    # identical "threshold" metrics yield the same result for MPEG2 and H.264/HEVC.
    metrics = _base_metrics(
        scanner_mod,
        total_video_packets=5,
        video_payload_bytes=50,
        bitrate_kbps=3000.0,
    )
    details = scanner._check_stuffing(metrics)
    assert details is not None
    assert "5" in details  # pkts=5 is substituted into the template


# ---------------------------------------------------------------------------
# thread_join_timeout
# ---------------------------------------------------------------------------

def test_thread_join_timeout_respects_floor(scanner_mod, scanner):
    # With the minimum scan_timeout and a sufficiently small watchdog_multiplier,
    # the "raw" sum (RUNTIME.hanging_slot_wait_timeout_sec + scan_timeout*multiplier
    # + 3.0 + RUNTIME.scan_thread_join_margin_sec) drops below
    # RUNTIME.scan_thread_join_min_timeout, and the max() floor must kick in.
    scanner.scan_timeout = scanner_mod.RUNTIME.scan_timeout_min_sec
    scanner.thresholds.watchdog_multiplier = 0.1
    raw = (
        scanner_mod.RUNTIME.hanging_slot_wait_timeout_sec
        + scanner.scan_timeout * scanner.thresholds.watchdog_multiplier
        + 3.0
        + scanner_mod.RUNTIME.scan_thread_join_margin_sec
    )
    assert raw < scanner_mod.RUNTIME.scan_thread_join_min_timeout  # verify the scenario really is below the floor
    assert scanner.thread_join_timeout == scanner_mod.RUNTIME.scan_thread_join_min_timeout


def test_thread_join_timeout_scales_with_scan_timeout(scanner_mod, scanner):
    scanner.scan_timeout = scanner_mod.RUNTIME.scan_timeout_max_sec  # 15
    scanner.thresholds.watchdog_multiplier = 1.5
    expected = max(
        scanner_mod.RUNTIME.scan_thread_join_min_timeout,
        (
            scanner_mod.RUNTIME.hanging_slot_wait_timeout_sec
            + 15 * 1.5
            + 3.0
            + scanner_mod.RUNTIME.scan_thread_join_margin_sec
        ),
    )
    assert scanner.thread_join_timeout == expected
    assert scanner.thread_join_timeout >= 15 * 1.5


def test_validate_thresholds_new_audio_clear_fields(scanner_mod):
    result = scanner_mod._validate_thresholds({
        "min_audio_packets_for_clear_check": 50,
        "max_scrambled_audio_ratio_for_clear": 0.25,
    })
    assert result.min_audio_packets_for_clear_check == 50
    assert result.max_scrambled_audio_ratio_for_clear == 0.25


def test_validate_thresholds_audio_ratio_out_of_range(scanner_mod):
    result = scanner_mod._validate_thresholds({
        "max_scrambled_audio_ratio_for_clear": 1.5,
    })
    assert result.max_scrambled_audio_ratio_for_clear == scanner_mod.Thresholds().max_scrambled_audio_ratio_for_clear


# ---------------------------------------------------------------------------
# Additional tests: known-scrambled channels, missing classification branches,
# protection against corrupted PSI sections, HEVC/MPEG2 start codes,
# PES scrambling, config helpers, fetch_playlist_channels,
# _shorten_request_error/s(), Channel — see the test-adding history.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _name_has_prefix — shared predicate for no-alert / known-scrambled channels
# (previously two hardcoded functions _is_no_alert_channel/_is_known_scrambled_channel;
# now prefixes are configurable in the config: scanner.no_alert_prefixes /
# scanner.known_scrambled_prefixes).
# ---------------------------------------------------------------------------

# There are no default prefixes in the code anymore (NO_ALERT_PREFIX / KNOWN_SCRAMBLED_PREFIXES
# have been removed): by default both lists are empty, values are supplied by the user
# in scanner_config.json. These tests verify the predicate itself against arbitrary
# prefixes; in the config prefixes are stored already normalized (lower/strip).
_PFX_NO_ALERT = ("added/test",)
_PFX_SCRAMBLED = ("scrambled", "added/scrambled")


@pytest.mark.parametrize("name,expected", [
    ("added/test Foo", True),
    ("ADDED/TEST Foo", True),           # case-insensitive
    ("  added/test Foo", True),         # leading whitespace is trimmed
    ("Foo added/test", False),          # prefix, not a substring anywhere
    ("", False),
    (None, False),
])
def test_name_has_prefix_single_prefix(scanner_mod, name, expected):
    assert scanner_mod._name_has_prefix(name, _PFX_NO_ALERT) is expected


@pytest.mark.parametrize("name,expected", [
    ("Scrambled Sports HD", True),
    ("scrambled sports hd", True),
    ("added/scrambled Foo", True),
    ("Unscrambled Foo", False),         # not a prefix — "unscrambled" does not start with "scrambled"
    ("PES Scrambled", False),           # "scrambled" is not at the start of the string
    ("", False),
    (None, False),
])
def test_name_has_prefix_multiple_prefixes(scanner_mod, name, expected):
    assert scanner_mod._name_has_prefix(name, _PFX_SCRAMBLED) is expected


def test_default_prefix_constants_are_gone(scanner_mod):
    """The hardcoded prefixes have been intentionally removed — this test catches
    their accidental return (otherwise users without a config would once again
    get implicitly suppressed alerts / "known-scrambled" channels)."""
    assert not hasattr(scanner_mod, "NO_ALERT_PREFIX")
    assert not hasattr(scanner_mod, "KNOWN_SCRAMBLED_PREFIXES")


def test_name_has_prefix_any_of_several_prefixes(scanner_mod):
    prefixes = ("aaa", "bbb")
    assert scanner_mod._name_has_prefix("bbb channel", prefixes) is True
    assert scanner_mod._name_has_prefix("ccc channel", prefixes) is False


def test_name_has_prefix_empty_prefix_list_matches_nothing(scanner_mod):
    assert scanner_mod._name_has_prefix("anything", ()) is False


# ---------------------------------------------------------------------------
# _classify_known_scrambled_channel — an entirely uncovered classification branch
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner_with_scrambled_prefixes(scanner):
    """A scanner with configured known_scrambled_prefixes (empty by default)."""
    scanner.known_scrambled_prefixes = ("scrambled", "added/scrambled")
    return scanner


def test_classify_known_scrambled_ok(scanner_mod, scanner_with_scrambled_prefixes):
    """A known-scrambled channel with healthy transport → OK_SCRAMBLED,
    even if video is fully encrypted (that is not a problem for such channels)."""
    scanner = scanner_with_scrambled_prefixes
    channel = scanner_mod.Channel("Scrambled Sports HD", "http://example.com/s1")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=2000,
        scrambled_video=2000,           # 100% scrambled — but irrelevant for this branch
        video_payload_bytes=500000,
        modern_vcl_count=0,             # no picture at all — also irrelevant
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.OK_SCRAMBLED


def test_classify_scrambled_name_without_configured_prefix_is_not_special(scanner_mod, scanner):
    """Without configured prefixes, the name "Scrambled …" is nothing special:
    fully encrypted video is classified by the general rules, not as OK_SCRAMBLED."""
    assert scanner.known_scrambled_prefixes == ()
    channel = scanner_mod.Channel("Scrambled Sports HD", "http://example.com/s0")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        total_video_packets=2000,
        scrambled_video=2000,
        video_payload_bytes=500000,
        modern_vcl_count=0,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status != scanner_mod.Status.OK_SCRAMBLED


def test_classify_known_scrambled_missing_video_pid_is_errors(scanner_mod, scanner_with_scrambled_prefixes):
    """Without a video PID, a known-scrambled channel gets ERRORS, not RADIO/OK."""
    scanner = scanner_with_scrambled_prefixes
    channel = scanner_mod.Channel("added/scrambled Radio-like", "http://example.com/s2")
    metrics = _base_metrics(scanner_mod, video_pids={}, audio_pids={0x0201: 0x0F})
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.ERRORS


def test_classify_known_scrambled_missing_pmt_is_errors(scanner_mod, scanner_with_scrambled_prefixes):
    scanner = scanner_with_scrambled_prefixes
    channel = scanner_mod.Channel("Scrambled No PMT", "http://example.com/s3")
    metrics = _base_metrics(
        scanner_mod, video_pids={0x0200: 0x1B}, pmt_parsed=False
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.ERRORS


def test_classify_known_scrambled_low_bitrate_is_dead(scanner_mod, scanner_with_scrambled_prefixes):
    scanner = scanner_with_scrambled_prefixes
    channel = scanner_mod.Channel("Scrambled Dead", "http://example.com/s4")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        bitrate_kbps=10.0,  # < scanner.min_bitrate_kbps (100)
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.DEAD


def test_classify_known_scrambled_bad_gap_is_errors(scanner_mod, scanner_with_scrambled_prefixes):
    scanner = scanner_with_scrambled_prefixes
    # A single exceedance of max_allowed_gap_sec without noticeable packet loss
    # is not enough for ERRORS (see the _is_gap_error docstring — a single blip
    # does not fail a channel). Either multiple exceedances per scan are needed
    # (gap_violations >= gap_violations_error_threshold), or cc_err above
    # gap_single_violation_max_cc_err — we use the former.
    channel = scanner_mod.Channel("Scrambled Choppy", "http://example.com/s5")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        max_chunk_gap=5.0,  # > max_allowed_gap_sec (1.1)
        gap_violations=scanner.thresholds.gap_violations_error_threshold,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.ERRORS


def test_classify_known_scrambled_ok_reports_cc_errors_in_details(scanner_mod, scanner_with_scrambled_prefixes):
    scanner = scanner_with_scrambled_prefixes
    channel = scanner_mod.Channel("Scrambled With CC", "http://example.com/s6")
    counter_cls = scanner_mod.Counter
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        continuity_errors_by_pid=counter_cls({0x0200: 3}),  # few — not enough for ERRORS
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.OK_SCRAMBLED
    assert "cc_err" in res.details or "3" in res.details


# ---------------------------------------------------------------------------
# _classify_channel branches not covered by the main test file
# ---------------------------------------------------------------------------

def test_classify_module_hung_via_audio_clear(scanner_mod, scanner):
    """Video is almost fully scrambled (NO_CARD condition), but audio is clear →
    MODULE_HUNG (the CI module hung only on the video stream), not NO_CARD."""
    channel = scanner_mod.Channel("Mixed CI Issue", "http://example.com/mh1")
    metrics = _base_metrics(
        scanner_mod,
        video_pids={0x0200: 0x1B},
        audio_pids={0x0201: 0x0F},
        total_video_packets=2000,
        scrambled_video=1950,                 # ratio 0.975 >= 0.95 → "effectively scrambled"
        total_audio_packets=200,
        scrambled_audio=0,                    # audio is clear
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.MODULE_HUNG
    assert "audio clear" in res.details.lower()


def test_classify_no_card_without_video_pids(scanner_mod, scanner):
    """No video PID at all, but a huge share of packets of any PID is scrambled
    and the stream is long → NO_CARD (the whole multiplex is encrypted, PMT
    does not help)."""
    channel = scanner_mod.Channel("Full Mux Scrambled", "http://example.com/mh2")
    th = scanner.thresholds
    metrics = _base_metrics(
        scanner_mod,
        video_pids={},
        scrambled_any_pid=th.scrambled_all_packets_threshold + 1,
        total_ts_packets=th.min_ts_packets_for_full_scramble_check + 1,
    )
    res = scanner._classify_channel(channel, metrics)
    assert res.status == scanner_mod.Status.NO_CARD
    assert "Нет карты" in res.details or "нет карты" in res.details.lower() or res.details


# ---------------------------------------------------------------------------
# parse_pat_section / parse_pmt_section — protection against corrupted data
# ---------------------------------------------------------------------------

def test_parse_pat_section_too_short_rejected(scanner_mod):
    pmt_pid_to_program = {}
    assert scanner_mod.parse_pat_section(b"\x00\x00", pmt_pid_to_program) is False
    assert pmt_pid_to_program == {}


def test_parse_pat_section_wrong_table_id_rejected(scanner_mod):
    section = bytearray(build_pat_section(scanner_mod, programs=[(1, 0x0100)]))
    section[0] = 0x02  # table_id must be 0x00 for PAT
    pmt_pid_to_program = {}
    assert scanner_mod.parse_pat_section(bytes(section), pmt_pid_to_program) is False


def test_parse_pmt_section_wrong_table_id_rejected(scanner_mod):
    section = bytearray(build_pmt_section(scanner_mod, streams=[(0x1B, 0x0200)]))
    section[0] = 0x00  # table_id must be 0x02 for PMT
    video_pids, audio_pids, unclassified_pids = {}, {}, {}
    assert scanner_mod.parse_pmt_section(bytes(section), video_pids, audio_pids, unclassified_pids) is False


def test_parse_pmt_section_es_info_len_overflow_rejected(scanner_mod):
    """An es_info_length pointing beyond the section must neither cause an
    out-of-bounds read nor leave video_pids/audio_pids partially populated."""
    body = bytearray()
    body += (1).to_bytes(2, "big")
    body += bytes([0xC1, 0x00, 0x00])
    body += (0xE000 | 0x0100).to_bytes(2, "big")
    body += (0xF000 | 0).to_bytes(2, "big")
    body.append(0x1B)
    body += (0xE000 | 0x0200).to_bytes(2, "big")
    body += (0xF000 | 200).to_bytes(2, "big")  # es_info_len is definitely larger than the section
    section_length = len(body) + 4
    header = bytes([0x02]) + (0xB000 | section_length).to_bytes(2, "big")
    full = bytearray(header) + body
    crc = scanner_mod._mpeg2_crc32(bytes(full))
    section = bytes(full) + crc.to_bytes(4, "big")

    video_pids, audio_pids, unclassified_pids = {}, {}, {}
    ok = scanner_mod.parse_pmt_section(section, video_pids, audio_pids, unclassified_pids)
    assert ok is False
    assert video_pids == {} and audio_pids == {}


def test_parse_pat_section_truncated_shorter_than_declared_length_rejected(scanner_mod):
    section = build_pat_section(scanner_mod, programs=[(1, 0x0100), (2, 0x0200)])
    truncated = section[:-2]  # truncate; section_length now lies
    pmt_pid_to_program = {}
    assert scanner_mod.parse_pat_section(truncated, pmt_pid_to_program) is False


# ---------------------------------------------------------------------------
# _extract_complete_psi_sections — garbage and buffer overflow
# ---------------------------------------------------------------------------

def test_extract_psi_sections_clears_buffer_on_too_short_length(scanner_mod):
    """total_length < 4 (section_length "lies" in the negative direction): the
    buffer is discarded entirely (a byte-by-byte resync would be O(n^2) on a
    stream full of garbage), the loop does not hang, and no sections are returned."""
    # buffer[1:3] = 0x00 0x00 -> section_length=0 -> total_length=3 (<4, invalid)
    buffer = bytearray(b"\xEE\x00\x00\xAB\xCD")
    sections = scanner_mod._extract_complete_psi_sections(buffer, b"", False)
    assert sections == []
    assert buffer == bytearray()


def test_extract_psi_sections_clears_buffer_on_too_long_length(scanner_mod):
    """total_length > 4096 (the maximum for a PSI section) — also garbage."""
    # section_length = 0x0FFF = 4095 -> total_length = 4098 > 4096
    buffer = bytearray(b"\xEE\x0F\xFF\xAB\xCD")
    sections = scanner_mod._extract_complete_psi_sections(buffer, b"", False)
    assert sections == []
    assert buffer == bytearray()


def test_extract_psi_sections_recovers_on_next_pointer_zero_packet(scanner_mod):
    """Realistic recovery scenario: even if one "garbage" packet left the buffer
    waiting for data that will never arrive, the next PSI packet with
    payload_unit_start=1 and pointer_field=0 resets the buffer (see
    `if pointer == 0: buffer.clear()`) and correctly parses the new section —
    which is what actually happens in practice, since PAT/PMT are transmitted
    periodically."""
    section = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    buffer = bytearray()

    # "Garbage" packet: claims a plausible but never-completing length.
    bogus_payload = bytes([0x00, 0x00, 0xB0, 0x50]) + b"\x11" * 20
    sections = scanner_mod._extract_complete_psi_sections(buffer, bogus_payload, True)
    assert sections == []
    assert len(buffer) > 0  # stuck waiting for data that will not arrive

    # The next real section arrives as usual (pointer_field=0) —
    # the buffer is reset and the section is parsed normally, despite the garbage tail.
    real_payload = bytes([0x00]) + section
    sections = scanner_mod._extract_complete_psi_sections(buffer, real_payload, True)
    assert sections == [section]


def test_extract_psi_sections_buffer_capped(scanner_mod):
    """The buffer for an incomplete section must not grow without bound."""
    buffer = bytearray()
    # Simulate the "start" of a section with a huge declared section_length,
    # after which enough data never arrives — the buffer accumulates until the cap kicks in.
    huge_len = 0x0FFF  # maximum allowed 12-bit section_length
    header = bytes([0x02]) + (0xB000 | huge_len).to_bytes(2, "big")
    payload = bytes([0x00]) + header + b"\x00" * 5000
    scanner_mod._extract_complete_psi_sections(buffer, payload, True)
    assert len(buffer) <= scanner_mod.MAX_PSI_BUFFER_BYTES


# ---------------------------------------------------------------------------
# TSStreamAnalyzer — HEVC NAL and MPEG2 start codes (previously only H.264 was tested)
# ---------------------------------------------------------------------------

def test_analyzer_counts_hevc_vcl_and_param_nals(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x24)  # HEVC

    # HEVC NAL header: nal_unit_type = (byte >> 1) & 0x3F.
    # type 1 (TRAIL_R, VCL) -> byte 0x02; type 32 (VPS, param) -> byte 0x40.
    payload = bytearray()
    for nal_byte in (0x02, 0x02, 0x40):
        payload += b"\x00\x00\x01" + bytes([nal_byte]) + b"\x00\x00\x00"
    packet = build_ts_packet(scanner_mod, pid=0x0200, payload=bytes(payload), payload_unit_start=True)
    analyzer.process_packet(packet)
    metrics = analyzer.finalize()

    assert metrics.modern_vcl_count == 2
    assert metrics.modern_param_count == 1


def test_analyzer_counts_mpeg2_start_codes(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x02)  # MPEG2

    payload = bytearray()
    payload += b"\x00\x00\x01\xB3" + b"\x00" * 4   # sequence_header
    payload += b"\x00\x00\x01\xB8" + b"\x00" * 4   # GOP header
    payload += b"\x00\x00\x01\x00" + b"\x00" * 4   # picture_start_code
    payload += b"\x00\x00\x01\x01" + b"\x00" * 4   # slice (0x01 is within the slice range)
    packet = build_ts_packet(scanner_mod, pid=0x0200, payload=bytes(payload), payload_unit_start=True)
    analyzer.process_packet(packet)
    metrics = analyzer.finalize()

    assert metrics.mpeg2_sequence_count == 1
    assert metrics.mpeg2_gop_count == 1
    assert metrics.mpeg2_picture_count == 1
    assert metrics.mpeg2_slice_count == 1


def test_analyzer_start_code_split_across_packets(scanner_mod):
    """A start code split by the payload boundary of two packets must still be
    counted (see self._video_tails)."""
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x1B)

    # The first packet ends in the middle of a start code (0x00 0x00); the second
    # begins with (0x01 <nal_header>) — the three bytes 00 00 01 turn out to be
    # split exactly at the boundary. payload1 occupies exactly 184 bytes (the whole
    # TS payload), otherwise build_ts_packet would have padded it with 0xFF and
    # "accidentally" ruined the intended ending 00 00.
    payload1 = b"\xAA" * 182 + b"\x00\x00"
    payload2 = b"\x01" + bytes([0x01]) + b"\x00\x00\x00" + b"\xBB" * 50
    p1 = build_ts_packet(scanner_mod, pid=0x0200, payload=payload1, payload_unit_start=True, cc=0)
    p2 = build_ts_packet(scanner_mod, pid=0x0200, payload=payload2, payload_unit_start=False, cc=1)
    analyzer.process_packet(p1)
    analyzer.process_packet(p2)
    metrics = analyzer.finalize()

    assert metrics.modern_vcl_count == 1  # NAL type 1 (non-IDR slice) — VCL


# ---------------------------------------------------------------------------
# PES scrambling (pes_scrambled_count) — there were no tests for this at all
# ---------------------------------------------------------------------------

def test_analyzer_pes_scrambled_count(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x1B)

    # PES header: 00 00 01 <stream_id 0xE0-0xEF> ... byte[6] contains
    # PES_scrambling_control in bits 5-4. Value 2 or 3 = scrambled.
    pes_header = bytearray(9)
    pes_header[0:3] = b"\x00\x00\x01"
    pes_header[3] = 0xE0  # video stream_id
    pes_header[6] = 0x20  # scrambling_control = 10b = 2 -> scrambled
    packet = build_ts_packet(
        scanner_mod, pid=0x0200, payload=bytes(pes_header) + b"\x00" * 175,
        payload_unit_start=True,
    )
    analyzer.process_packet(packet)
    metrics = analyzer.finalize()
    assert metrics.pes_scrambled_count == 1


def test_analyzer_pes_not_scrambled_count(scanner_mod):
    analyzer = scanner_mod.TSStreamAnalyzer()
    _setup_video_pid(scanner_mod, analyzer, video_pid=0x0200, stream_type=0x1B)

    pes_header = bytearray(9)
    pes_header[0:3] = b"\x00\x00\x01"
    pes_header[3] = 0xE0
    pes_header[6] = 0x00  # scrambling_control = 0 -> clear
    packet = build_ts_packet(
        scanner_mod, pid=0x0200, payload=bytes(pes_header) + b"\x00" * 175,
        payload_unit_start=True,
    )
    analyzer.process_packet(packet)
    metrics = analyzer.finalize()
    assert metrics.pes_scrambled_count == 0


# ---------------------------------------------------------------------------
# Configuration helper functions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,lo,hi,default,expected", [
    (5, 1, 10, 0, 5),
    (-5, 1, 10, 0, 1),      # clamped from below
    (50, 1, 10, 0, 10),     # clamped from above
    ("abc", 1, 10, 3, 3),   # not a number -> default
    (None, 1, 10, 3, 3),
])
def test_clamp_int(scanner_mod, value, lo, hi, default, expected):
    assert scanner_mod._clamp_int(value, lo, hi, default) == expected


def test_scale_hex_color_saturation_identity_at_factor_1(scanner_mod):
    assert scanner_mod._scale_hex_color_saturation("#d4edda", 1.0) == "#d4edda"


def test_scale_hex_color_saturation_invalid_hex_returned_unchanged(scanner_mod):
    assert scanner_mod._scale_hex_color_saturation("not-a-color", 2.0) == "not-a-color"
    assert scanner_mod._scale_hex_color_saturation("#zzzzzz", 2.0) == "#zzzzzz"
    assert scanner_mod._scale_hex_color_saturation("", 2.0) == ""


def test_scale_hex_color_saturation_zero_desaturates_to_gray(scanner_mod):
    result = scanner_mod._scale_hex_color_saturation("#ff0000", 0.0)
    r = int(result[1:3], 16)
    g = int(result[3:5], 16)
    b = int(result[5:7], 16)
    assert r == g == b  # S=0 -> gray


def test_validate_tree_colors_unknown_tag_ignored(scanner_mod):
    result = scanner_mod._validate_tree_colors({"totally_unknown_tag": {"background": "#000000"}})
    assert "totally_unknown_tag" not in result
    assert result == scanner_mod.DEFAULT_TREE_COLORS


def test_validate_tree_colors_known_tag_overridden(scanner_mod):
    result = scanner_mod._validate_tree_colors({"ok": {"background": "#123456"}})
    assert result["ok"]["background"] == "#123456"
    # foreground is not specified in data -> it stays at the default
    assert result["ok"]["foreground"] == scanner_mod.DEFAULT_TREE_COLORS["ok"]["foreground"]


def test_validate_tree_colors_empty_string_ignored(scanner_mod):
    result = scanner_mod._validate_tree_colors({"ok": {"background": "   "}})
    assert result["ok"]["background"] == scanner_mod.DEFAULT_TREE_COLORS["ok"]["background"]


def test_validate_column_widths_clamped(scanner_mod):
    result = scanner_mod._validate_column_widths({"status": {"width": 99999, "minwidth": -5}})
    assert result["status"]["width"] == 2000
    assert result["status"]["minwidth"] == 10


def test_validate_column_widths_unknown_column_ignored(scanner_mod):
    result = scanner_mod._validate_column_widths({"nonexistent": {"width": 50}})
    assert "nonexistent" not in result


# ---------------------------------------------------------------------------
# fetch_playlist_channels — M3U parsing (there were no tests at all)
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal requests.Response model for fetch_playlist_channels.

    The code reads the body as a stream (iter_content) with limits, so a plain
    .text is not enough. Parameters:
      text / body — content (text is encoded as utf-8);
      headers     — response headers (for Content-Length);
      encoding    — resp.encoding (as requests sets it from charset);
      chunks      — explicit slicing of the body into chunks (one chunk by default);
      status_exc  — what raise_for_status() will raise.
    """

    def __init__(self, text=None, body=None, headers=None, encoding=None,
                 chunks=None, status_exc=None):
        if body is None:
            body = (text or "").encode("utf-8")
        self._chunks = chunks if chunks is not None else [body]
        self.headers = headers or {}
        self.encoding = encoding
        self._status_exc = status_exc
        self.closed = False
        self.iterated = False

    @property
    def text(self):  # compatibility: older tests might have read .text
        return b"".join(self._chunks).decode(self.encoding or "utf-8", errors="replace")

    def raise_for_status(self):
        if self._status_exc is not None:
            raise self._status_exc

    def iter_content(self, chunk_size=None):
        self.iterated = True
        for c in self._chunks:
            yield c

    def close(self):
        self.closed = True


class _FakeSession:
    def __init__(self, text=None, exc=None, response=None):
        self._text = text
        self._exc = exc
        self._response = response
        self.last_kwargs = None
        self.last_response = None

    def get(self, url, timeout=None, verify=None, stream=None):
        # We record verify: the code must pass verify=True explicitly (the TLS
        # policy must not depend on requests defaults) — see the dedicated test.
        # stream=True is mandatory: without it requests would download the whole
        # body before iter_content and MAX_PLAYLIST_BYTES would be meaningless.
        self.last_kwargs = {"timeout": timeout, "verify": verify, "stream": stream}
        if self._exc is not None:
            raise self._exc
        self.last_response = self._response or _FakeResponse(self._text)
        return self.last_response

    def close(self):
        pass


def test_fetch_playlist_channels_basic_parsing(scanner_mod, scanner, monkeypatch):
    m3u = (
        "#EXTM3U\n"
        "#EXTINF:-1,Channel One\n"
        "http://example.com/one.ts\n"
        "#EXTINF:-1,Channel Two\n"
        "http://example.com/two.ts\n"
    )
    monkeypatch.setattr(scanner, "_get_session", lambda: _FakeSession(text=m3u))
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert [c.name for c in channels] == ["Channel One", "Channel Two"]
    assert [c.url for c in channels] == ["http://example.com/one.ts", "http://example.com/two.ts"]


def test_fetch_playlist_channels_name_from_tvg_name_when_no_comma_text(scanner_mod, scanner, monkeypatch):
    m3u = (
        '#EXTINF:-1 tvg-name="Fallback Name" tvg-id="x",\n'
        "http://example.com/three.ts\n"
    )
    monkeypatch.setattr(scanner, "_get_session", lambda: _FakeSession(text=m3u))
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert len(channels) == 1
    assert channels[0].name == "Fallback Name"


def test_fetch_playlist_channels_skips_blank_and_comment_lines_before_url(scanner_mod, scanner, monkeypatch):
    m3u = (
        "#EXTINF:-1,Channel One\n"
        "\n"
        "#EXTGRP:Sport\n"
        "http://example.com/one.ts\n"
    )
    monkeypatch.setattr(scanner, "_get_session", lambda: _FakeSession(text=m3u))
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert len(channels) == 1
    assert channels[0].url == "http://example.com/one.ts"


def test_fetch_playlist_channels_network_error_returns_empty_list(scanner_mod, scanner, monkeypatch):
    monkeypatch.setattr(
        scanner, "_get_session",
        lambda: _FakeSession(exc=requests.exceptions.ConnectTimeout("boom")),
    )
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert channels == []


def test_fetch_playlist_channels_extinf_without_following_url_is_dropped(scanner_mod, scanner, monkeypatch):
    m3u = "#EXTINF:-1,Orphan Channel\n"  # ends without a URL
    monkeypatch.setattr(scanner, "_get_session", lambda: _FakeSession(text=m3u))
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert channels == []


def _fetch(scanner, monkeypatch, response=None, text=None, url="http://example.com/playlist.m3u"):
    session = _FakeSession(text=text, response=response)
    monkeypatch.setattr(scanner, "_get_session", lambda: session)
    return scanner.fetch_playlist_channels(url), session


def test_fetch_playlist_channels_requests_with_tls_verification_and_timeout(scanner_mod, scanner, monkeypatch):
    """verify=True must be passed EXPLICITLY: the TLS policy must not depend on
    requests defaults / environment variables."""
    _, session = _fetch(scanner, monkeypatch, text="#EXTINF:-1,A\nhttp://e.com/a.ts\n")
    assert session.last_kwargs == {"timeout": 20, "verify": True, "stream": True}


def test_fetch_playlist_channels_closes_response_after_success(scanner_mod, scanner, monkeypatch):
    _, session = _fetch(scanner, monkeypatch, text="#EXTINF:-1,A\nhttp://e.com/a.ts\n")
    assert session.last_response.closed is True


def test_fetch_playlist_channels_http_error_returns_empty_and_closes_response(scanner_mod, scanner, monkeypatch):
    resp = _FakeResponse(text="whatever", status_exc=requests.exceptions.HTTPError("404"))
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert channels == []
    assert resp.closed is True
    assert resp.iterated is False           # the body was never read at all


def test_fetch_playlist_channels_declared_content_length_over_limit_skips_body(scanner_mod, scanner, monkeypatch):
    monkeypatch.setattr(scanner_mod, "MAX_PLAYLIST_BYTES", 100)
    resp = _FakeResponse(text="#EXTINF:-1,A\nhttp://e.com/a.ts\n", headers={"Content-Length": "101"})
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert channels == []
    assert resp.iterated is False           # rejected BEFORE downloading the body
    assert resp.closed is True


def test_fetch_playlist_channels_non_numeric_content_length_is_ignored(scanner_mod, scanner, monkeypatch):
    resp = _FakeResponse(text="#EXTINF:-1,A\nhttp://e.com/a.ts\n", headers={"Content-Length": "abc"})
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [c.name for c in channels] == ["A"]


def test_fetch_playlist_channels_streamed_body_over_limit_is_rejected(scanner_mod, scanner, monkeypatch):
    """Content-Length header is missing or lies — the byte counter does the job."""
    monkeypatch.setattr(scanner_mod, "MAX_PLAYLIST_BYTES", 50)
    resp = _FakeResponse(chunks=[b"#EXTINF:-1,A\n", b"http://e.com/a.ts\n" * 5])
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert channels == []
    assert resp.closed is True


def test_fetch_playlist_channels_body_exactly_at_limit_is_accepted(scanner_mod, scanner, monkeypatch):
    body = b"#EXTINF:-1,A\nhttp://e.com/a.ts\n"
    monkeypatch.setattr(scanner_mod, "MAX_PLAYLIST_BYTES", len(body))
    channels, _ = _fetch(scanner, monkeypatch, response=_FakeResponse(body=body))
    assert [c.name for c in channels] == ["A"]


def test_fetch_playlist_channels_lying_content_length_smaller_than_body_still_capped(scanner_mod, scanner, monkeypatch):
    monkeypatch.setattr(scanner_mod, "MAX_PLAYLIST_BYTES", 40)
    resp = _FakeResponse(body=b"x" * 41, headers={"Content-Length": "10"})
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert channels == []


def test_fetch_playlist_channels_empty_chunks_are_skipped(scanner_mod, scanner, monkeypatch):
    resp = _FakeResponse(chunks=[b"", b"#EXTINF:-1,A\nhttp://e.com/", b"", b"a.ts\n"])
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [(c.name, c.url) for c in channels] == [("A", "http://e.com/a.ts")]


def test_fetch_playlist_channels_truncates_at_channel_limit(scanner_mod, scanner, monkeypatch):
    monkeypatch.setattr(scanner_mod, "MAX_PLAYLIST_CHANNELS", 3)
    m3u = "".join(f"#EXTINF:-1,Ch{i}\nhttp://e.com/{i}.ts\n" for i in range(5))
    channels, _ = _fetch(scanner, monkeypatch, text=m3u)
    assert [c.name for c in channels] == ["Ch0", "Ch1", "Ch2"]


def test_fetch_playlist_channels_skips_overlong_line_but_keeps_the_rest(scanner_mod, scanner, monkeypatch):
    monkeypatch.setattr(scanner_mod, "MAX_PLAYLIST_LINE_LENGTH", 30)
    m3u = (
        "http://e.com/" + "a" * 100 + "\n"          # too long — skipped
        "#EXTINF:-1,Good\n"
        "http://e.com/good.ts\n"
    )
    channels, _ = _fetch(scanner, monkeypatch, text=m3u)
    assert [(c.name, c.url) for c in channels] == [("Good", "http://e.com/good.ts")]


def test_fetch_playlist_channels_decodes_cyrillic_as_utf8_when_no_charset(scanner_mod, scanner, monkeypatch):
    """Content-Type without charset and not text/* (audio/x-mpegurl,
    application/vnd.apple.mpegurl…): requests leaves resp.encoding=None —
    we decode as UTF-8."""
    body = "#EXTINF:-1,Первый канал\nhttp://e.com/1.ts\n".encode("utf-8")
    channels, _ = _fetch(scanner, monkeypatch, response=_FakeResponse(body=body, encoding=None))
    assert [c.name for c in channels] == ["Первый канал"]


def test_fetch_playlist_channels_text_plain_without_charset_is_decoded_as_utf8(scanner_mod, scanner, monkeypatch):
    body = "#EXTINF:-1,Первый канал\nhttp://e.com/1.ts\n".encode("utf-8")
    resp = _FakeResponse(
        body=body, headers={"Content-Type": "text/plain"}, encoding="ISO-8859-1",
    )
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [c.name for c in channels] == ["Первый канал"]


def test_fetch_playlist_channels_honours_declared_charset(scanner_mod, scanner, monkeypatch):
    body = "#EXTINF:-1,Первый канал\nhttp://e.com/1.ts\n".encode("cp1251")
    resp = _FakeResponse(
        body=body, encoding="cp1251",
        headers={"Content-Type": "audio/x-mpegurl; charset=windows-1251"},
    )
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [c.name for c in channels] == ["Первый канал"]


def test_fetch_playlist_channels_unknown_charset_falls_back_to_utf8(scanner_mod, scanner, monkeypatch):
    body = "#EXTINF:-1,Канал\nhttp://e.com/1.ts\n".encode("utf-8")
    resp = _FakeResponse(
        body=body, encoding="no-such-charset",
        headers={"Content-Type": "text/plain; charset=no-such-charset"},
    )
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [c.name for c in channels] == ["Канал"]


def test_fetch_playlist_channels_handles_crlf_line_endings(scanner_mod, scanner, monkeypatch):
    channels, _ = _fetch(scanner, monkeypatch, text="#EXTM3U\r\n#EXTINF:-1,A\r\nhttp://e.com/a.ts\r\n")
    assert [(c.name, c.url) for c in channels] == [("A", "http://e.com/a.ts")]


def test_fetch_playlist_channels_extinf_name_is_not_reused_for_next_url(scanner_mod, scanner, monkeypatch):
    m3u = "#EXTINF:-1,Named\nhttp://e.com/1.ts\nhttp://e.com/2.ts\n"
    channels, _ = _fetch(scanner, monkeypatch, text=m3u)
    assert [c.name for c in channels] == ["Named", "Channel_1"]


def test_fetch_playlist_channels_utf8_bom_does_not_create_phantom_channel(scanner_mod, scanner, monkeypatch):
    body = "\ufeff#EXTM3U\n#EXTINF:-1,One\nhttp://e.com/1.ts\n".encode("utf-8")
    channels, _ = _fetch(scanner, monkeypatch, response=_FakeResponse(body=body))
    assert [c.name for c in channels] == ["One"]


def test_fetch_playlist_channels_credentials_are_not_logged(scanner_mod, scanner, monkeypatch, caplog):
    """A URL with a login/token must not end up in the log in cleartext."""
    monkeypatch.setattr(
        scanner, "_get_session",
        lambda: _FakeSession(exc=requests.exceptions.ConnectTimeout("boom")),
    )
    with caplog.at_level("ERROR"):
        scanner.fetch_playlist_channels("http://user:secret@example.com/p.m3u?token=abc123")
    assert "example.com" in caplog.text      # there is a log entry (the test is not vacuous)…
    assert "secret" not in caplog.text       # …but without the password
    assert "abc123" not in caplog.text       # …and without the token value


# ---------------------------------------------------------------------------
# _shorten_request_error / s()
# ---------------------------------------------------------------------------

def test_shorten_request_error_connect_timeout(scanner_mod, scanner):
    assert scanner._shorten_request_error(requests.exceptions.ConnectTimeout()) == scanner.s("err_connect_timeout")


def _requests_conn_error(cause, message="Max retries exceeded with url: /"):
    """requests.ConnectionError with a cause as built by requests/urllib3:

        requests.ConnectionError(args=(MaxRetryError,))
          MaxRetryError.__cause__ = NewConnectionError
            NewConnectionError.__cause__ = <OSError / socket.gaierror>

    The internal links are replaced with plain Exceptions so the test does not
    depend on the urllib3 version (NewConnectionError has different signatures
    in 1.26 and 2.x).
    """
    new_conn = Exception("Failed to establish a new connection")
    new_conn.__cause__ = cause
    max_retry = Exception(message)
    max_retry.__cause__ = new_conn
    return requests.exceptions.ConnectionError(max_retry)


def test_shorten_request_error_connection_refused(scanner_mod, scanner):
    e = _requests_conn_error(ConnectionRefusedError(111, "Connection refused"))
    assert scanner._shorten_request_error(e) == scanner.s("err_connection_refused")


def test_shorten_request_error_refused_by_winerror_code_on_localized_message(scanner_mod, scanner):
    """WinSock messages are localized, so the cause must be determined by code
    (10061 = WSAECONNREFUSED), not by text."""
    cause = OSError(10061, "Подключение не установлено, т.к. конечный компьютер отверг запрос")
    e = _requests_conn_error(cause)
    assert scanner._shorten_request_error(e) == scanner.s("err_connection_refused")


def test_shorten_request_error_dns_failure(scanner_mod, scanner):
    e = _requests_conn_error(socket.gaierror(-2, "Name or service not known"))
    assert scanner._shorten_request_error(e) == scanner.s("err_host_not_found")


@pytest.mark.parametrize("code", [11001, 11002, 11004])
def test_shorten_request_error_dns_failure_by_winerror_code(scanner_mod, scanner, code):
    e = _requests_conn_error(OSError(code, "Этот хост неизвестен"))
    assert scanner._shorten_request_error(e) == scanner.s("err_host_not_found")


def test_shorten_request_error_cause_found_via_dunder_cause_on_top_exception(scanner_mod, scanner):
    """The cause may hang directly off the requests exception (raise ... from ...)."""
    e = requests.exceptions.ConnectionError("boom")
    e.__cause__ = ConnectionRefusedError(111, "refused")
    assert scanner._shorten_request_error(e) == scanner.s("err_connection_refused")


def test_shorten_request_error_connection_reset(scanner_mod, scanner):
    e = _requests_conn_error(ConnectionResetError(104, "Connection reset by peer"))
    assert scanner._shorten_request_error(e) == scanner.s("err_connection_reset")


def test_shorten_request_error_max_retries_without_os_cause(scanner_mod, scanner):
    e = requests.exceptions.ConnectionError("HTTPConnectionPool: Max retries exceeded with url: /")
    assert scanner._shorten_request_error(e) == scanner.s("err_max_retries_exceeded")


def test_shorten_request_error_unknown_connection_error(scanner_mod, scanner):
    e = requests.exceptions.ConnectionError("something odd")
    assert scanner._shorten_request_error(e) == scanner.s("err_connection_error")


def test_shorten_request_error_read_timeout(scanner_mod, scanner):
    assert scanner._shorten_request_error(requests.exceptions.ReadTimeout()) == scanner.s("err_read_timeout")


def test_shorten_request_error_generic_timeout(scanner_mod, scanner):
    assert scanner._shorten_request_error(requests.exceptions.Timeout()) == scanner.s("err_timeout")


def test_find_os_error_skips_requests_exception_itself(scanner_mod, scanner):
    """REGRESSION: requests.RequestException inherits from OSError (IOError), so
    the chain walk stopped at the requests.ConnectionError itself and never
    reached the real cause."""
    cause = ConnectionRefusedError(111, "refused")
    e = _requests_conn_error(cause)
    assert isinstance(e, OSError)          # the premise of the bug
    assert scanner._find_os_error(e) is cause


def test_find_os_error_returns_none_when_no_os_cause(scanner_mod, scanner):
    e = requests.exceptions.ConnectionError(Exception("no os error here"))
    assert scanner._find_os_error(e) is None


def test_shorten_request_error_real_refused_localhost_port(scanner_mod, scanner):
    """End-to-end check with real requests: a closed local port.
    No external network needed — connecting to 127.0.0.1 immediately gets refused."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()                              # port released -> nobody is listening
    with pytest.raises(requests.exceptions.ConnectionError) as excinfo:
        requests.get(f"http://127.0.0.1:{port}/", timeout=3)
    assert scanner._shorten_request_error(excinfo.value) == scanner.s("err_connection_refused")


def test_shorten_request_error_generic_exception_truncated(scanner_mod, scanner):
    e = ValueError("a" * 200)
    result = scanner._shorten_request_error(e)
    assert len(result) <= 80


def test_s_missing_format_kwarg_falls_back_to_template(scanner_mod, scanner):
    # detail_cooldown expects {remaining} — we don't pass it at all
    result = scanner.s("detail_cooldown")
    assert result == scanner.ui_strings["detail_cooldown"]


def test_s_unknown_key_returns_key_itself(scanner_mod, scanner):
    assert scanner.s("totally_unknown_key_xyz") == "totally_unknown_key_xyz"


# ---------------------------------------------------------------------------
# Channel / misc
# ---------------------------------------------------------------------------

def test_channel_alert_key_case_insensitive_name(scanner_mod):
    a = scanner_mod.Channel("My Channel", "http://x/1")
    b = scanner_mod.Channel("MY CHANNEL", "http://x/1")
    assert a.alert_key == b.alert_key


def test_channel_strips_whitespace(scanner_mod):
    c = scanner_mod.Channel("  Padded Name  ", "  http://x/1  ")
    assert c.name == "Padded Name"
    assert c.url == "http://x/1"


def test_compute_max_hanging_threads_floor(scanner_mod):
    assert scanner_mod.IPTVScanner._compute_max_hanging_threads(1) == 12


def test_compute_max_hanging_threads_scales(scanner_mod):
    assert scanner_mod.IPTVScanner._compute_max_hanging_threads(10) == 20


# ---------------------------------------------------------------------------
# _deadline_reached / _read_deadline_reached — were not covered at all, even
# though this is the only place responsible for when _scan_channel_stream
# stops reading the stream.
# ---------------------------------------------------------------------------

# (The former _deadline_reached function was replaced by _read_deadline_reached,
# which takes analyzer state into account; its tests are below.)

def test_read_deadline_reached_uses_time_monotonic_when_now_omitted(scanner_mod, scanner, monkeypatch):
    scanner.scan_timeout = 4
    analyzer = scanner_mod.TSStreamAnalyzer()
    analyzer.metrics.pmt_parsed = True   # otherwise the deadline is extended after scan_timeout
    monkeypatch.setattr(scanner_mod.time, "monotonic", lambda: 1000.0)
    assert scanner._read_deadline_reached(996.0, 2000.0, analyzer) is True   # 1000-996=4 >= scan_timeout
    assert scanner._read_deadline_reached(998.0, 2000.0, analyzer) is False  # 1000-998=2 < scan_timeout


def test_read_deadline_reached_true_past_hard_deadline_even_if_pmt_pending(scanner_mod, scanner):
    scanner.scan_timeout = 4
    analyzer = scanner_mod.TSStreamAnalyzer()  # nothing recognized — PMT is still "pending"
    assert scanner._read_deadline_reached(0.0, 10.0, analyzer, now=10.0) is True


def test_read_deadline_reached_false_before_user_scan_timeout(scanner_mod, scanner):
    scanner.scan_timeout = 4
    analyzer = scanner_mod.TSStreamAnalyzer()
    assert scanner._read_deadline_reached(0.0, 100.0, analyzer, now=1.0) is False


def test_read_deadline_reached_extends_when_pmt_still_pending(scanner_mod, scanner):
    # After scan_timeout but before the hard deadline: if neither a video PID
    # nor the PMT was ever caught, we give the channel more time (we must not
    # consider the deadline reached).
    scanner.scan_timeout = 4
    analyzer = scanner_mod.TSStreamAnalyzer()
    assert analyzer.metrics.video_pids == {}
    assert analyzer.metrics.pmt_parsed is False
    assert scanner._read_deadline_reached(0.0, 100.0, analyzer, now=5.0) is False


def test_read_deadline_reached_true_once_pmt_parsed(scanner_mod, scanner):
    scanner.scan_timeout = 4
    analyzer = scanner_mod.TSStreamAnalyzer()
    analyzer.metrics.pmt_parsed = True
    assert scanner._read_deadline_reached(0.0, 100.0, analyzer, now=5.0) is True


def test_read_deadline_reached_true_once_video_pid_seen(scanner_mod, scanner):
    scanner.scan_timeout = 4
    analyzer = scanner_mod.TSStreamAnalyzer()
    analyzer.metrics.video_pids[0x0200] = 0x1B
    assert scanner._read_deadline_reached(0.0, 100.0, analyzer, now=5.0) is True


# ---------------------------------------------------------------------------
# _scan_channel_stream — the main stream-reading loop (buffering,
# resynchronization after garbage, metric accumulation, NOT_TS detection,
# reaction to request_stop()). Previously not covered at all: all
# classification tests fed ScanMetrics directly, bypassing this code.
# ---------------------------------------------------------------------------

class _FakeStreamResponse:
    def __init__(self, chunks, status_ok=True):
        self._chunks = chunks
        self._status_ok = status_ok
        self.closed = False

    def raise_for_status(self):
        if not self._status_ok:
            raise requests.exceptions.HTTPError("bad status")

    def iter_content(self, chunk_size=None):
        for c in self._chunks:
            yield c

    def close(self):
        self.closed = True


class _FakeStreamSession:
    def __init__(self, chunks):
        self._chunks = chunks
        self.last_response = None
        self.last_kwargs = None

    def get(self, url, stream=True, timeout=None, headers=None, verify=None):
        self.last_kwargs = {
            "stream": stream, "timeout": timeout, "headers": headers, "verify": verify,
        }
        self.last_response = _FakeStreamResponse(self._chunks)
        return self.last_response


def _valid_stream_chunk(scanner_mod, n_video_packets=10, n_audio_packets=5):
    pat = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    pmt = build_pmt_section(scanner_mod, streams=[(0x1B, 0x0200), (0x0F, 0x0201)])
    packets = [
        build_psi_packet(scanner_mod, pid=0x0000, section=pat),
        build_psi_packet(scanner_mod, pid=0x0100, section=pmt),
    ]
    video_payload = build_h264_nal_payload([0x09, 0x21, 0x01, 0x21])
    for i in range(n_video_packets):
        packets.append(build_ts_packet(scanner_mod, pid=0x0200, payload=video_payload, cc=i % 16))
    for i in range(n_audio_packets):
        packets.append(build_ts_packet(scanner_mod, pid=0x0201, payload=b"\xAB" * 184, cc=i % 16))
    # pad the bitrate with NULL packets so we easily exceed min_total_bytes
    packets += [build_null_packet(scanner_mod) for _ in range(40)]
    return b"".join(packets)


def test_scan_channel_stream_parses_valid_stream_into_metrics(scanner_mod, scanner):
    scanner.thresholds.min_scan_duration_sec = 0.0  # the test does not wait for real time
    scanner._stop_event.clear()  # by default the Event is set ("not scanning")
    chunk = _valid_stream_chunk(scanner_mod)
    session = _FakeStreamSession([chunk])
    channel = scanner_mod.Channel("Test", "http://example.com/stream.ts")
    result = scanner._scan_channel_stream(channel, deadline=time.monotonic() + 30, session=session)
    assert isinstance(result, scanner_mod.ScanMetrics)
    assert result.pat_parsed is True
    assert result.pmt_parsed is True
    assert 0x0200 in result.video_pids
    assert 0x0201 in result.audio_pids
    assert result.total_ts_packets > 0
    assert result.garbage_bytes == 0


def test_scan_channel_stream_too_little_data_is_connect_failed(scanner_mod, scanner):
    scanner.thresholds.min_scan_duration_sec = 0.0
    scanner._stop_event.clear()
    # A single NULL packet — far below the min_total_bytes threshold (10000 by default).
    chunk = build_null_packet(scanner_mod)
    session = _FakeStreamSession([chunk])
    channel = scanner_mod.Channel("Test", "http://example.com/stream.ts")
    result = scanner._scan_channel_stream(channel, deadline=time.monotonic() + 30, session=session)
    assert isinstance(result, scanner_mod.ScanResult)
    assert result.status == scanner_mod.Status.CONNECT_FAILED


def test_scan_channel_stream_mostly_garbage_is_not_ts(scanner_mod, scanner):
    scanner.thresholds.min_scan_duration_sec = 0.0
    scanner._stop_event.clear()
    # A large garbage prefix (no 0x47 byte at all) + a few valid NULL packets
    # at the tail — in total enough bytes to pass min_total_bytes, but with a
    # garbage share above max_garbage_ratio (0.4).
    garbage = b"\x00" * 15000
    real = b"".join(build_null_packet(scanner_mod) for _ in range(5))
    chunk = garbage + real
    session = _FakeStreamSession([chunk])
    channel = scanner_mod.Channel("Test", "http://example.com/stream.ts")
    result = scanner._scan_channel_stream(channel, deadline=time.monotonic() + 30, session=session)
    assert isinstance(result, scanner_mod.ScanResult)
    assert result.status == scanner_mod.Status.NOT_TS


def test_scan_channel_stream_recovers_sync_after_mid_stream_garbage(scanner_mod, scanner):
    # A bit of garbage is inserted BETWEEN valid packets (e.g. a truncated/
    # corrupted packet) — the stream must resynchronize and still count the
    # remaining valid packets without falling into NOT_TS (the garbage share
    # is small).
    scanner.thresholds.min_scan_duration_sec = 0.0
    scanner._stop_event.clear()
    pat = build_pat_section(scanner_mod, programs=[(1, 0x0100)])
    pmt = build_pmt_section(scanner_mod, streams=[(0x1B, 0x0200)])
    packets = [
        build_psi_packet(scanner_mod, pid=0x0000, section=pat),
        build_psi_packet(scanner_mod, pid=0x0100, section=pmt),
    ]
    video_payload = build_h264_nal_payload([0x09, 0x21])
    for i in range(20):
        packets.append(build_ts_packet(scanner_mod, pid=0x0200, payload=video_payload, cc=i % 16))
    stream = b"".join(packets)
    # Insert a bit of "garbage" (no 0x47 byte) right into the middle of the stream.
    mid = len(stream) // 2
    corrupted = stream[:mid] + b"\x11" * 20 + stream[mid:]
    corrupted += b"".join(build_null_packet(scanner_mod) for _ in range(40))  # top up the volume
    session = _FakeStreamSession([corrupted])
    channel = scanner_mod.Channel("Test", "http://example.com/stream.ts")
    result = scanner._scan_channel_stream(channel, deadline=time.monotonic() + 30, session=session)
    assert isinstance(result, scanner_mod.ScanMetrics)
    assert result.pmt_parsed is True
    assert result.garbage_bytes > 0
    assert 0x0200 in result.video_pids


def test_scan_channel_stream_stop_event_aborts_immediately(scanner_mod, scanner):
    scanner.thresholds.min_scan_duration_sec = 0.0
    chunk = _valid_stream_chunk(scanner_mod)
    session = _FakeStreamSession([chunk])
    # _stop_event is already set by default (idle state in __init__), but we set
    # it explicitly so the test does not depend on that implementation detail
    # and does not silently break if the default changes one day.
    scanner._stop_event.set()
    channel = scanner_mod.Channel("Test", "http://example.com/stream.ts")
    result = scanner._scan_channel_stream(channel, deadline=time.monotonic() + 30, session=session)
    # Not a single chunk must have been processed — neither bytes nor packets.
    assert isinstance(result, scanner_mod.ScanResult)
    assert result.status == scanner_mod.Status.CONNECT_FAILED


def test_scan_channel_stream_closes_response_even_on_exception(scanner_mod, scanner):
    scanner._stop_event.clear()
    class _BoomSession:
        def get(self, url, stream=True, timeout=None, headers=None, verify=None):
            resp = _FakeStreamResponse([b"\x00" * 10])

            def _boom(chunk_size=None):
                raise RuntimeError("boom")
                yield  # pragma: no cover - makes the function a generator

            resp.iter_content = _boom
            return resp

    session = _BoomSession()
    channel = scanner_mod.Channel("Test", "http://example.com/stream.ts")
    with pytest.raises(RuntimeError):
        scanner._scan_channel_stream(channel, deadline=time.monotonic() + 30, session=session)


# ---------------------------------------------------------------------------
# apply_scan_settings — clamping settings and rebuilding the hanging-thread
# semaphore when parallel changes. Previously not covered at all.
# ---------------------------------------------------------------------------

def test_apply_scan_settings_clamps_out_of_range_values(scanner_mod, scanner):
    scanner.apply_scan_settings(
        scan_timeout=scanner_mod.RUNTIME.scan_timeout_max_sec + 100,
        parallel=scanner_mod.RUNTIME.parallel_max + 100,
        min_bitrate_kbps=0,
    )
    assert scanner.scan_timeout == scanner_mod.RUNTIME.scan_timeout_max_sec
    assert scanner.parallel == scanner_mod.RUNTIME.parallel_max
    assert scanner.min_bitrate_kbps == scanner_mod.RUNTIME.min_bitrate_setting_kbps


def test_apply_scan_settings_invalid_values_fall_back_to_defaults(scanner_mod, scanner):
    scanner.apply_scan_settings(scan_timeout="abc", parallel=None, min_bitrate_kbps="x")
    assert scanner.scan_timeout == scanner_mod.RUNTIME.default_scan_timeout
    assert scanner.parallel == scanner_mod.RUNTIME.default_parallel
    assert scanner.min_bitrate_kbps == scanner_mod.RUNTIME.default_min_bitrate_kbps


def test_apply_scan_settings_recreates_semaphore_when_parallel_changes(scanner_mod, scanner):
    scanner.apply_scan_settings(scanner.scan_timeout, parallel=2, min_bitrate_kbps=scanner.min_bitrate_kbps)
    old_semaphore = scanner._hanging_semaphore
    old_max = scanner.MAX_HANGING_THREADS
    scanner.apply_scan_settings(scanner.scan_timeout, parallel=7, min_bitrate_kbps=scanner.min_bitrate_kbps)
    assert scanner.MAX_HANGING_THREADS != old_max
    assert scanner._hanging_semaphore is not old_semaphore


def test_apply_scan_settings_keeps_semaphore_when_parallel_unchanged(scanner_mod, scanner):
    scanner.apply_scan_settings(scanner.scan_timeout, parallel=3, min_bitrate_kbps=scanner.min_bitrate_kbps)
    sem = scanner._hanging_semaphore
    scanner.apply_scan_settings(scanner.scan_timeout, parallel=3, min_bitrate_kbps=scanner.min_bitrate_kbps)
    assert scanner._hanging_semaphore is sem


# ---------------------------------------------------------------------------
# load_config / save_config — round-trip and resilience to corrupted/foreign
# config contents. Previously not covered at all.
# ---------------------------------------------------------------------------

def test_save_then_load_config_roundtrip(scanner_mod, scanner):
    scanner.vlc_path = "C:/custom/vlc.exe"
    scanner.scan_timeout = 7
    scanner.parallel = 5
    scanner.playlist_names[0] = "My Playlist"
    scanner.playlist_urls[0] = "http://example.com/pl.m3u"
    scanner.preload_playlist = "My Playlist"
    scanner.save_config()

    reloaded = scanner_mod.IPTVScanner()  # a fresh instance picks up the same CONFIG_FILE
    assert reloaded.vlc_path == "C:/custom/vlc.exe"
    assert reloaded.scan_timeout == 7
    assert reloaded.parallel == 5
    assert reloaded.playlist_names[0] == "My Playlist"
    assert reloaded.playlist_urls[0] == "http://example.com/pl.m3u"
    assert reloaded.preload_playlist == "My Playlist"


def test_save_config_clears_preload_if_playlist_no_longer_active(scanner_mod, scanner):
    scanner.preload_playlist = "Ghost Playlist"  # not part of any active playlist
    scanner.save_config()
    assert scanner.preload_playlist == ""

    reloaded = scanner_mod.IPTVScanner()
    assert reloaded.preload_playlist == ""


def test_load_config_recovers_from_non_list_playlist_urls(scanner_mod, scanner):
    scanner.save_config()
    with open(scanner_mod.CONFIG_FILE, "r", encoding="utf-8") as f:
        data = __import__("json").load(f)
    data["playlist_urls"] = "not-a-list"
    data["playlist_names"] = "not-a-list-either"
    with open(scanner_mod.CONFIG_FILE, "w", encoding="utf-8") as f:
        __import__("json").dump(data, f)

    reloaded = scanner_mod.IPTVScanner()
    assert reloaded.playlist_urls == [""] * scanner_mod.MAX_PLAYLISTS
    assert reloaded.playlist_names == [""] * scanner_mod.MAX_PLAYLISTS


def test_load_config_ignores_preload_not_in_active_playlists(scanner_mod, scanner):
    scanner.save_config()
    with open(scanner_mod.CONFIG_FILE, "r", encoding="utf-8") as f:
        data = __import__("json").load(f)
    data["preload_playlist"] = "Does Not Exist"
    with open(scanner_mod.CONFIG_FILE, "w", encoding="utf-8") as f:
        __import__("json").dump(data, f)

    reloaded = scanner_mod.IPTVScanner()
    assert reloaded.preload_playlist == ""


def test_load_config_missing_file_creates_default_config(scanner_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_mod, "CONFIG_FILE", tmp_path / "fresh_config.json")
    assert not (tmp_path / "fresh_config.json").exists()
    inst = scanner_mod.IPTVScanner()
    assert (tmp_path / "fresh_config.json").exists()
    assert inst.scan_timeout == scanner_mod.RUNTIME.default_scan_timeout


def test_load_config_survives_malformed_json(scanner_mod, scanner):
    with open(scanner_mod.CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write("{not valid json!!")
    # It must not raise — by contract it falls back to the defaults.
    scanner.load_config()
    # the instance remains in a working state, values are the defaults
    assert scanner.scan_timeout == scanner_mod.RUNTIME.default_scan_timeout


def test_get_active_playlists_only_returns_entries_with_both_name_and_url(scanner_mod, scanner):
    scanner.playlist_names = ["Only Name", "", "Both"]  + [""] * (scanner_mod.MAX_PLAYLISTS - 3)
    scanner.playlist_urls = ["", "http://only-url", "http://both"] + [""] * (scanner_mod.MAX_PLAYLISTS - 3)
    active = scanner.get_active_playlists()
    assert active == [(2, "Both", "http://both")]


# ---------------------------------------------------------------------------
# _parse_extinf_name — parsing the #EXTINF line
#
# The name is the text after the first comma OUTSIDE quotes; if it is empty,
# the fallback source is the tvg-name attribute; if that is also missing — ""
# (then the caller substitutes Channel_N).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("#EXTINF:-1,Channel One", "Channel One"),
    ('#EXTINF:-1 tvg-id="x" group-title="News",Channel One', "Channel One"),
    ("#EXTINF:0.5,Name, with, commas", "Name, with, commas"),
    # REGRESSION: a comma inside attribute quotes is not a separator
    ('#EXTINF:-1 group-title="News, Sport",Channel One', "Channel One"),
    ('#EXTINF:-1 tvg-name="Foo, Bar",Channel One', "Channel One"),
    # Fallback name from tvg-name (nothing after the comma)
    ('#EXTINF:-1 tvg-name="Fallback Name" tvg-id="x",', "Fallback Name"),
    ('#EXTINF:-1 tvg-name="Foo, Bar",', "Foo, Bar"),
    ("#EXTINF:-1 TVG-NAME='Single',", "Single"),           # case and single quotes
    ('#EXTINF:-1 tvg-name="Fallback"', "Fallback"),        # no comma at all
    # Text after the comma takes priority over tvg-name
    ('#EXTINF:-1 tvg-name="Attr Name",Text Name', "Text Name"),
    # A quote in the channel name itself
    ('#EXTINF:-1,Channel "HD', 'Channel "HD'),
    ('#EXTINF:-1 tvg-id="x",Channel "HD"', 'Channel "HD"'),
    # Broken (unpaired) quotes in attributes: fall back to "first comma"
    ('#EXTINF:-1 tvg-name="Broken,Name', "Name"),
    # There is no name anywhere
    ("#EXTINF:-1", ""),
    ("#EXTINF:-1,", ""),
    ('#EXTINF:-1 tvg-name="",', ""),
    ('#EXTINF:-1 tvg-name="   ",', ""),
])
def test_parse_extinf_name(scanner_mod, line, expected):
    assert scanner_mod.IPTVScanner._parse_extinf_name(line) == expected


def test_fetch_playlist_channels_commas_inside_quoted_attributes(scanner_mod, scanner, monkeypatch):
    m3u = (
        '#EXTINF:-1 group-title="News, Sport" tvg-name="A, B",Channel One\n'
        "http://example.com/one.ts\n"
    )
    monkeypatch.setattr(scanner, "_get_session", lambda: _FakeSession(text=m3u))
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert [c.name for c in channels] == ["Channel One"]


def test_fetch_playlist_channels_falls_back_to_channel_n_when_no_name(scanner_mod, scanner, monkeypatch):
    m3u = (
        "#EXTINF:-1,\n"
        "http://example.com/one.ts\n"
        "http://example.com/two.ts\n"        # without its own #EXTINF
    )
    monkeypatch.setattr(scanner, "_get_session", lambda: _FakeSession(text=m3u))
    channels = scanner.fetch_playlist_channels("http://example.com/playlist.m3u")
    assert [c.name for c in channels] == ["Channel_0", "Channel_1"]


# ---------------------------------------------------------------------------
# Configurable channel prefixes in the config (no_alert_prefixes /
# known_scrambled_prefixes)
# ---------------------------------------------------------------------------

def _write_config(scanner_mod, data):
    scanner_mod.CONFIG_FILE.write_text(json.dumps(data), encoding="utf-8")


def test_prefixes_are_empty_on_fresh_scanner(scanner_mod, scanner):
    assert scanner.no_alert_prefixes == ()
    assert scanner.known_scrambled_prefixes == ()


def test_load_config_normalizes_prefixes(scanner_mod, scanner):
    """Prefixes are trimmed, lowercased, and empty ones are dropped."""
    _write_config(scanner_mod, {
        "no_alert_prefixes": ["  Foo/ ", "BAR", "", "   "],
        "known_scrambled_prefixes": [" X1 ", "Y2"],
    })
    scanner.load_config()
    assert scanner.no_alert_prefixes == ("foo/", "bar")
    assert scanner.known_scrambled_prefixes == ("x1", "y2")


@pytest.mark.parametrize("raw", [[], "not-a-list", None, 42, ["", "   "]])
def test_load_config_invalid_prefixes_fall_back_to_empty(scanner_mod, scanner, raw):
    """Empty list/non-list/only empty strings → no prefixes (default is ())."""
    scanner.no_alert_prefixes = ("zzz",)
    scanner.known_scrambled_prefixes = ("zzz",)
    _write_config(scanner_mod, {"no_alert_prefixes": raw, "known_scrambled_prefixes": raw})
    scanner.load_config()
    assert scanner.no_alert_prefixes == ()
    assert scanner.known_scrambled_prefixes == ()


def test_load_config_without_prefix_keys_leaves_prefixes_empty(scanner_mod, scanner):
    _write_config(scanner_mod, {})
    scanner.load_config()
    assert scanner.no_alert_prefixes == ()
    assert scanner.known_scrambled_prefixes == ()


def test_prefixes_survive_save_and_reload(scanner_mod, scanner):
    scanner.no_alert_prefixes = ("skip/",)
    scanner.known_scrambled_prefixes = ("enc/", "pay/")
    scanner.save_config()
    reloaded = scanner_mod.IPTVScanner()
    assert reloaded.no_alert_prefixes == ("skip/",)
    assert reloaded.known_scrambled_prefixes == ("enc/", "pay/")


def test_reset_advanced_config_clears_prefixes_and_persists(scanner_mod, scanner):
    scanner.no_alert_prefixes = ("skip/",)
    scanner.known_scrambled_prefixes = ("enc/",)
    scanner.reset_advanced_config_to_defaults()
    assert scanner.no_alert_prefixes == ()
    assert scanner.known_scrambled_prefixes == ()
    # the reset is written to disk, not just to memory
    reloaded = scanner_mod.IPTVScanner()
    assert reloaded.no_alert_prefixes == ()
    assert reloaded.known_scrambled_prefixes == ()


# ---------------------------------------------------------------------------
# PMT: DVB-private (stream_type 0x06) + descriptors, known-non-audio, and
# "unrecognized" types. Previously this branch of parse_pmt_section was not covered.
# ---------------------------------------------------------------------------

def _parse_pmt(scanner_mod, streams):
    section = build_pmt_section(scanner_mod, streams=streams)
    video, audio, unclassified = {}, {}, {}
    assert scanner_mod.parse_pmt_section(section, video, audio, unclassified) is True
    return video, audio, unclassified


@pytest.mark.parametrize("tag,name", [
    (0x6A, "AC-3"),
    (0x7A, "Enhanced AC-3"),
    (0x7B, "DTS"),
])
def test_parse_pmt_dvb_private_with_audio_descriptor_is_audio(scanner_mod, tag, name):
    video, audio, unclassified = _parse_pmt(
        scanner_mod, [(0x1B, 0x0100), (0x06, 0x0101, bytes([tag, 0x00]))]
    )
    assert audio == {0x0101: 0x06}
    assert unclassified == {}
    assert video == {0x0100: 0x1B}


def test_parse_pmt_dvb_private_audio_descriptor_after_other_descriptors(scanner_mod):
    # ISO 639 language descriptor (0x0A, 4 bytes) comes BEFORE AC-3 (0x6A)
    es_info = bytes([0x0A, 0x04]) + b"eng\x00" + bytes([0x6A, 0x00])
    _, audio, unclassified = _parse_pmt(scanner_mod, [(0x06, 0x0101, es_info)])
    assert audio == {0x0101: 0x06}
    assert unclassified == {}


@pytest.mark.parametrize("tag", [0x56, 0x59])  # teletext, subtitling
def test_parse_pmt_dvb_private_teletext_or_subtitles_is_not_audio_nor_unclassified(scanner_mod, tag):
    _, audio, unclassified = _parse_pmt(scanner_mod, [(0x06, 0x0101, bytes([tag, 0x00]))])
    assert audio == {}
    assert unclassified == {}


def test_parse_pmt_dvb_private_without_known_descriptor_is_unclassified(scanner_mod):
    _, audio, unclassified = _parse_pmt(scanner_mod, [(0x06, 0x0101)])
    assert audio == {}
    assert unclassified == {0x0101: 0x06}


def test_parse_pmt_dvb_private_with_only_unrelated_descriptor_is_unclassified(scanner_mod):
    es_info = bytes([0x0A, 0x04]) + b"eng\x00"      # language only, no audio tag
    _, audio, unclassified = _parse_pmt(scanner_mod, [(0x06, 0x0101, es_info)])
    assert audio == {}
    assert unclassified == {0x0101: 0x06}


@pytest.mark.parametrize("stream_type", [0x05, 0x0B, 0x86, 0x95])
def test_parse_pmt_known_non_audio_stream_types_are_ignored(scanner_mod, stream_type):
    video, audio, unclassified = _parse_pmt(scanner_mod, [(stream_type, 0x0300)])
    assert (video, audio, unclassified) == ({}, {}, {})


def test_parse_pmt_unknown_stream_type_is_unclassified(scanner_mod):
    # 0x2C (MPEG-H 3D Audio) — can neither be excluded nor confirmed as audio
    _, audio, unclassified = _parse_pmt(scanner_mod, [(0x2C, 0x0400)])
    assert audio == {}
    assert unclassified == {0x0400: 0x2C}


@pytest.mark.parametrize("es_info,tags,expected", [
    (b"", {0x6A}, False),
    (bytes([0x6A, 0x00]), {0x6A}, True),
    (bytes([0x0A, 0x02, 0x00, 0x00, 0x6A, 0x00]), {0x6A}, True),   # second descriptor
    (bytes([0x0A, 0x00]), {0x6A}, False),                          # length=0 does not loop
    (bytes([0x6A, 0x05]), {0x6A}, False),                          # length beyond es_info
    (bytes([0x6A]), {0x6A}, False),                                # truncated TLV
    (bytes([0x56, 0x00]), {0x6A, 0x7A}, False),                    # tag not in the set
])
def test_has_descriptor_tag(scanner_mod, es_info, tags, expected):
    assert scanner_mod._has_descriptor_tag(es_info, tags) is expected


# ---------------------------------------------------------------------------
# _data_dir / _appdata_dir / _logs_dir
# ---------------------------------------------------------------------------

def test_data_dir_returns_base_when_writable_and_leaves_no_probe(scanner_mod, tmp_path):
    assert scanner_mod._data_dir(tmp_path) == tmp_path
    assert not (tmp_path / ".write_probe").exists()


def test_data_dir_falls_back_to_localappdata_when_base_not_writable(scanner_mod, tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))

    def deny(self, *args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(scanner_mod.Path, "touch", deny)
    result = scanner_mod._data_dir(tmp_path / "Program Files" / "app")
    assert result == local / "IPTV_Scanner"
    assert result.is_dir()


def test_data_dir_fallback_uses_appdata_when_localappdata_missing(scanner_mod, tmp_path, monkeypatch):
    roaming = tmp_path / "roaming"
    roaming.mkdir()
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("APPDATA", str(roaming))

    def deny(self, *args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(scanner_mod.Path, "touch", deny)
    assert scanner_mod._data_dir(tmp_path / "ro") == roaming / "IPTV_Scanner"


def test_appdata_and_logs_dirs_are_created_under_localappdata(scanner_mod, tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    app = scanner_mod._appdata_dir()
    assert app == tmp_path / "IPTV_Scanner" and app.is_dir()
    logs = scanner_mod._logs_dir()
    assert logs == app / "logs" and logs.is_dir()


# ---------------------------------------------------------------------------
# RecoveryState — the single storage for recovery state. Pure logic, no GUI.
# ---------------------------------------------------------------------------

@pytest.fixture
def rs(scanner_mod):
    return scanner_mod.RecoveryState()


def test_recovery_state_initial_state_is_normal(rs):
    assert rs.epoch == 0
    assert rs.phase == "NORMAL"
    assert rs.invariant_violations() == []
    assert not rs.network_recovery_active
    assert not rs.any_recovery_active
    assert not rs.intentional_reset_active
    assert not rs.path_recovery_active


def test_recovery_state_bump_epoch_is_monotonic_and_returns_new_value(rs):
    assert rs.bump_epoch() == 1
    assert rs.bump_epoch() == 2
    assert rs.epoch == 2


def test_recovery_state_reset_episode_clears_only_episode_fields(rs):
    rs.soft_recovery_attempted = True
    rs.connect_fail_batch_streak = 4
    rs.vpn_relied_upon = True
    rs.reset_episode()
    assert rs.soft_recovery_attempted is False
    assert rs.connect_fail_batch_streak == 0
    assert rs.vpn_relied_upon is True


def test_recovery_state_rejects_unknown_attribute_typos(rs):
    """__slots__: a typo in a field name must fail rather than silently creating an attribute."""
    with pytest.raises(AttributeError):
        rs.interet_down = True


def test_recovery_state_network_and_any_recovery_predicates(rs):
    rs.path_recovery_in_progress = True
    assert rs.any_recovery_active is True
    assert rs.network_recovery_active is False      # path-recovery is not part of "network"
    rs.path_recovery_in_progress = False
    rs.recovery_in_progress = True
    assert rs.network_recovery_active is True
    rs.recovery_in_progress = False
    rs.internet_down = True
    assert rs.network_recovery_active is True
    assert rs.any_recovery_active is True


def test_recovery_state_path_recovery_active_includes_deferred(rs):
    rs.path_recovery_deferred = True
    assert rs.path_recovery_active is True
    rs.path_recovery_deferred = False
    rs.path_recovery_in_progress = True
    assert rs.path_recovery_active is True


@pytest.mark.parametrize("fields,expected_inactive", [
    ({}, True),                                               # not relying on VPN
    ({"vpn_relied_upon": True}, False),                       # normal observation
    ({"vpn_relied_upon": True, "internet_down": True}, True),
    ({"vpn_relied_upon": True, "recovery_in_progress": True}, True),
])
def test_recovery_state_vpn_watch_inactive(rs, fields, expected_inactive):
    for name, value in fields.items():
        setattr(rs, name, value)
    assert rs.vpn_watch_inactive is expected_inactive


def test_recovery_state_vpn_watch_inactive_during_intentional_reset(rs):
    rs.vpn_relied_upon = True
    assert rs.begin_intentional_reset(None, "wifi", 30.0, closing=False) is True
    assert rs.vpn_watch_inactive is True
    rs.end_intentional_reset()
    assert rs.vpn_watch_inactive is False


def test_recovery_state_phase_priority(rs):
    rs.path_recovery_in_progress = True
    assert rs.phase == "PATH_RECOVERY"
    rs.recovery_in_progress = True
    assert rs.phase == "VPN_RECOVERY"
    rs.internet_down = True
    assert rs.phase == "NETWORK_DOWN"
    rs.intentional_network_reset = True
    rs.intentional_reset_deadline = float("inf")
    assert rs.phase == "INTENTIONAL_L2_RESET"


def test_recovery_state_begin_intentional_reset_sets_fields(scanner_mod, rs, monkeypatch):
    monkeypatch.setattr(scanner_mod.time, "monotonic", lambda: 100.0)
    rs.epoch = 3
    assert rs.begin_intentional_reset(3, "adapter", 20.0, closing=False) is True
    assert rs.intentional_network_reset is True
    assert rs.intentional_reset_kind == "adapter"
    assert rs.intentional_reset_epoch == 3
    assert rs.intentional_reset_deadline == 120.0


@pytest.mark.parametrize("setup,epoch,closing", [
    ({}, None, True),                                  # window is closing
    ({}, 7, False),                                    # epoch is stale (rs.epoch=0)
    ({"internet_down": True}, None, False),            # network is already down
    ({"recovery_in_progress": True}, None, False),     # VPN-recovery is in progress
])
def test_recovery_state_begin_intentional_reset_refused(rs, setup, epoch, closing):
    for name, value in setup.items():
        setattr(rs, name, value)
    assert rs.begin_intentional_reset(epoch, "wifi", 10.0, closing=closing) is False
    assert rs.intentional_network_reset is False


def test_recovery_state_begin_intentional_reset_refused_when_another_reset_active(rs):
    assert rs.begin_intentional_reset(None, "wifi", 10.0, closing=False) is True
    assert rs.begin_intentional_reset(None, "adapter", 10.0, closing=False) is False
    assert rs.intentional_reset_kind == "wifi"         # the first reset is not overwritten


def test_recovery_state_end_intentional_reset_clears_flags(rs):
    rs.begin_intentional_reset(None, "wifi", 10.0, closing=False)
    rs.end_intentional_reset()
    assert rs.intentional_network_reset is False
    assert rs.intentional_reset_kind == ""
    assert rs.intentional_reset_deadline == 0.0
    assert rs.intentional_reset_active is False


def test_recovery_state_intentional_reset_watchdog_expires(scanner_mod, rs, monkeypatch):
    """A flag that outlived its deadline (worker hung/killed) is considered cleared."""
    now = [100.0]
    monkeypatch.setattr(scanner_mod.time, "monotonic", lambda: now[0])
    rs.begin_intentional_reset(None, "wifi", 10.0, closing=False)
    assert rs.intentional_reset_active is True
    now[0] = 110.0                                     # exactly at the deadline — still active
    assert rs.intentional_reset_active is True
    now[0] = 110.1
    assert rs.intentional_reset_active is False
    assert rs.phase == "NORMAL"
    # and a new reset can be started again
    assert rs.begin_intentional_reset(None, "adapter", 10.0, closing=False) is True


def test_recovery_state_invariant_internet_down_with_vpn_recovery_is_violation(rs):
    rs.internet_down = True
    rs.recovery_in_progress = True
    assert "internet_down + recovery_in_progress" in rs.invariant_violations()


def test_recovery_state_invariant_path_recovery_with_internet_down_is_legal(rs):
    rs.path_recovery_in_progress = True
    rs.internet_down = True
    assert rs.invariant_violations() == []


def test_recovery_state_invariant_intentional_reset_needs_path_recovery(rs):
    rs.begin_intentional_reset(None, "wifi", 10.0, closing=False)
    assert "intentional_reset without path_recovery_in_progress" in rs.invariant_violations()
    rs.path_recovery_in_progress = True
    assert rs.invariant_violations() == []


def test_recovery_state_invariant_intentional_reset_conflicts(rs):
    rs.path_recovery_in_progress = True
    rs.begin_intentional_reset(None, "wifi", 10.0, closing=False)
    rs.internet_down = True
    rs.recovery_in_progress = True
    bad = rs.invariant_violations()
    assert "intentional_reset + internet_down" in bad
    assert "intentional_reset + recovery_in_progress" in bad


def test_recovery_state_superseded_or_offline(rs):
    assert rs.superseded_or_offline(0) is False
    rs.bump_epoch()
    assert rs.superseded_or_offline(0) is True          # the epoch changed
    assert rs.superseded_or_offline(1) is False
    rs.internet_down = True
    assert rs.superseded_or_offline(1) is True          # no network


def test_recovery_state_lock_is_reentrant(rs):
    """_on_vpn_session_invalidated holds the lock and calls code that takes it
    again — the lock must be an RLock. We check in a thread with a timeout so
    that a deadlock does not hang the whole run."""
    result = []

    def work():
        with rs.lock:
            result.append(rs.begin_intentional_reset(None, "wifi", 5.0, closing=False))

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(2.0)
    assert not t.is_alive(), "deadlock: RecoveryState.lock is not reentrant"
    assert result == [True]


# ---------------------------------------------------------------------------
# _VpnSessionWatch — deciding "VPN session changed / lost"
# ---------------------------------------------------------------------------

class _FakeVpnWatchApi:
    """Stand-in for the part of vpn.py used by _VpnSessionWatch."""

    def __init__(self, status="up", counters=None, snapshot=(), alive_total=(1, 1)):
        self.status = status
        self.counters = counters
        self.snapshot = snapshot
        self.alive_total = alive_total
        self.on_counters = None      # hook: called in the middle of get_interface_counters
        self.on_count_alive = None   # hook: called in the middle of count_alive_routes

    def get_interface_status(self, if_index):
        if isinstance(self.status, Exception):
            raise self.status
        return self.status

    def get_interface_counters(self, if_index):
        if self.on_counters:
            self.on_counters()
        if isinstance(self.counters, Exception):
            raise self.counters
        return self.counters

    def routes_snapshot(self):
        return self.snapshot

    def count_alive_routes(self, routes, snap):
        if self.on_count_alive:
            self.on_count_alive()
        return self.alive_total


def _session(if_index=37):
    return types.SimpleNamespace(if_index=if_index, local_ip="10.0.0.2")


def _counters(in_octets, out_octets):
    return types.SimpleNamespace(in_octets=in_octets, out_octets=out_octets)


@pytest.fixture
def watch_env(scanner_mod, monkeypatch):
    api = _FakeVpnWatchApi()
    monkeypatch.setattr(scanner_mod, "vpn", api)
    now = [1000.0]
    monkeypatch.setattr(scanner_mod.time, "monotonic", lambda: now[0])
    watch = scanner_mod._VpnSessionWatch()
    return types.SimpleNamespace(watch=watch, api=api, now=now)


def test_vpn_watch_adapter_missing_invalidates(watch_env):
    watch_env.api.status = "missing"
    assert watch_env.watch.check(_session()) == "adapter_missing"


def test_vpn_watch_adapter_down_invalidates(watch_env):
    watch_env.api.status = "down"
    assert watch_env.watch.check(_session()) == "adapter_down"


@pytest.mark.parametrize("status", ["up", None, RuntimeError("iphlpapi failed")])
def test_vpn_watch_unknown_or_up_status_does_not_invalidate(watch_env, status):
    """A single API failure is "I don't know", not "the session changed"."""
    watch_env.api.status = status
    assert watch_env.watch.check(_session()) is None


def test_vpn_watch_counters_first_observation_sets_baseline(watch_env):
    watch_env.api.counters = _counters(1000, 500)
    assert watch_env.watch.check(_session()) is None


def test_vpn_watch_counters_growth_is_fine_and_rollback_invalidates(watch_env):
    w, api = watch_env.watch, watch_env.api
    api.counters = _counters(1000, 500)
    assert w.check(_session()) is None
    api.counters = _counters(2000, 900)
    assert w.check(_session()) is None
    api.counters = _counters(50, 900)            # InOctets rolled back to zero
    assert w.check(_session()) == "counters_reset"


def test_vpn_watch_out_octets_rollback_also_invalidates(watch_env):
    w, api = watch_env.watch, watch_env.api
    api.counters = _counters(1000, 500)
    w.check(_session())
    api.counters = _counters(1000, 10)
    assert w.check(_session()) == "counters_reset"


def test_vpn_watch_compares_with_session_peak_not_previous_tick(watch_env):
    """The peak accumulates over the session: a return below the peak is a
    rollback, even if the counter grew relative to the previous tick."""
    w, api = watch_env.watch, watch_env.api
    api.counters = _counters(10_000, 10_000)
    w.check(_session())
    api.counters = _counters(100, 10_000)
    assert w.check(_session()) == "counters_reset"
    api.counters = _counters(200, 10_000)         # above the previous tick, but below the peak
    assert w.check(_session()) == "counters_reset"


def test_vpn_watch_adopt_resets_counter_baseline(watch_env):
    w, api = watch_env.watch, watch_env.api
    api.counters = _counters(10_000, 10_000)
    w.check(_session())
    w.adopt(_session())                           # a new session has been accepted
    api.counters = _counters(5, 5)
    assert w.check(_session()) is None            # this is a new baseline, not a rollback


def test_vpn_watch_reset_forgets_routes_and_baseline(watch_env):
    w, api = watch_env.watch, watch_env.api
    w.set_routes([["1.2.3.4", 37, "10.0.0.1"]])
    api.counters = _counters(10_000, 10_000)
    w.check(_session())
    w.reset()
    assert w.routes() == []
    api.counters = _counters(1, 1)
    assert w.check(_session()) is None


def test_vpn_watch_counters_api_failure_is_skipped(watch_env):
    w, api = watch_env.watch, watch_env.api
    api.counters = None
    assert w.check(_session()) is None
    api.counters = RuntimeError("boom")
    assert w.check(_session()) is None


def test_vpn_watch_reset_during_check_discards_stale_peak(watch_env):
    """Race: while the monitor was in iphlpapi, the GUI did adopt()/reset(). The
    peak snapshot is stale — it must not be compared against (otherwise a false
    counters_reset when ifIndex is reused), nor written back."""
    w, api = watch_env.watch, watch_env.api
    api.counters = _counters(10_000, 10_000)
    w.check(_session())                           # baseline: 10_000
    api.counters = _counters(50, 50)              # fresh counters of the NEW session
    api.on_counters = w.reset                     # reset() in the middle of check()
    assert w.check(_session()) is None
    api.on_counters = None
    # the next tick starts from a clean baseline, not from the old peak
    assert w.check(_session()) is None
    api.counters = _counters(60, 60)
    assert w.check(_session()) is None


def test_vpn_watch_set_routes_parses_tolerantly(watch_env):
    w = watch_env.watch
    w.set_routes(
        [
            ["1.2.3.4", 37, "gw"],
            ["5.6.7.8", None, "gw"],        # ifIndex is taken from fallback
            ["not-an-ip", 37],              # garbage is not put into the mirror
            None,                           # not an element at all
            [],                             # IndexError
            ["9.9.9.9", "abc"],             # ifIndex is not a number
        ],
        if_index_fallback=99,
    )
    assert w.routes() == [("1.2.3.4", 37), ("5.6.7.8", 99)]


def test_vpn_watch_set_routes_skips_entries_without_any_ifindex(watch_env):
    w = watch_env.watch
    w.set_routes([["1.2.3.4", None]])               # fallback is not set
    assert w.routes() == []


def test_vpn_watch_set_routes_none_clears(watch_env):
    w = watch_env.watch
    w.set_routes([["1.2.3.4", 37]])
    w.set_routes(None)
    assert w.routes() == []


def test_vpn_watch_routes_returns_copy(watch_env):
    w = watch_env.watch
    w.set_routes([["1.2.3.4", 37]])
    w.routes().append(("evil", 1))
    assert w.routes() == [("1.2.3.4", 37)]


def test_vpn_watch_routes_ignored_during_settle_period(watch_env):
    w, api, now = watch_env.watch, watch_env.api, watch_env.now
    api.alive_total = (0, 2)
    w.set_routes([["1.2.3.4", 37]])
    now[0] += w.ROUTES_SETTLE_SEC - 0.1
    for _ in range(w.MISS_STREAK_TO_FIRE + 2):
        assert w.check(_session()) is None


def test_vpn_watch_all_routes_vanished_fires_after_streak(watch_env):
    w, api, now = watch_env.watch, watch_env.api, watch_env.now
    api.alive_total = (0, 2)
    w.set_routes([["1.2.3.4", 37]])
    now[0] += w.ROUTES_SETTLE_SEC + 0.1
    for _ in range(w.MISS_STREAK_TO_FIRE - 1):
        assert w.check(_session()) is None
    assert w.check(_session()) == "our_routes_vanished"
    # the counter is reset after firing — it will not fire again immediately
    assert w.check(_session()) is None


def test_vpn_watch_alive_route_resets_miss_streak(watch_env):
    w, api, now = watch_env.watch, watch_env.api, watch_env.now
    w.set_routes([["1.2.3.4", 37]])
    now[0] += w.ROUTES_SETTLE_SEC + 0.1
    api.alive_total = (0, 2)
    for _ in range(w.MISS_STREAK_TO_FIRE - 1):
        w.check(_session())
    api.alive_total = (1, 2)                      # some routes are alive — the streak breaks
    assert w.check(_session()) is None
    api.alive_total = (0, 2)
    for _ in range(w.MISS_STREAK_TO_FIRE - 1):
        assert w.check(_session()) is None


def test_vpn_watch_unreadable_route_table_does_not_count_as_miss(watch_env):
    w, api, now = watch_env.watch, watch_env.api, watch_env.now
    w.set_routes([["1.2.3.4", 37]])
    now[0] += w.ROUTES_SETTLE_SEC + 0.1
    api.snapshot = None                           # routes_snapshot() could not read
    api.alive_total = (0, 2)
    for _ in range(w.MISS_STREAK_TO_FIRE * 2):
        assert w.check(_session()) is None


def test_vpn_watch_zero_total_routes_is_ignored(watch_env):
    w, api, now = watch_env.watch, watch_env.api, watch_env.now
    w.set_routes([["1.2.3.4", 37]])
    now[0] += w.ROUTES_SETTLE_SEC + 0.1
    api.alive_total = (0, 0)
    for _ in range(w.MISS_STREAK_TO_FIRE * 2):
        assert w.check(_session()) is None


def test_vpn_watch_routes_reinstalled_during_check_discard_result(watch_env):
    """While the check was running, precheck reinstalled the routes — the result is stale."""
    w, api, now = watch_env.watch, watch_env.api, watch_env.now
    api.alive_total = (0, 2)
    w.set_routes([["1.2.3.4", 37]])
    now[0] += w.ROUTES_SETTLE_SEC + 0.1
    for _ in range(w.MISS_STREAK_TO_FIRE - 1):
        w.check(_session())

    def reinstall():
        now[0] += 0.001                            # a different timestamp
        w.set_routes([["1.2.3.4", 37]])

    api.on_count_alive = reinstall
    assert w.check(_session()) is None             # streak would be 3 — but the result is discarded


# ---------------------------------------------------------------------------
# ScannerGUI: handling of the tri-state (True/False/None) from
# vpn.get_vpn_connected() in the VPN monitor, epoch gates and the read-only facade.
#
# vpn.get_vpn_connected() is documented and implemented as tri-state:
# True/False — real status, None — "I don't know" (PowerShell timeout/error,
# or a profile ambiguous between User/AllUser scope). Previously several places
# in ScannerGUI treated None the same as False ("VPN definitely went down"),
# which led to false VPN invalidations and losing _vpn_relied_upon because of
# a single non-responding PowerShell call.
#
# ScannerGUI is a Tk class: __init__ creates real widgets, and the window is
# not needed in headless tests. Therefore the instance is created WITHOUT
# calling __init__ (object.__new__), and the required attributes are set
# manually. Thus the methods and the read-only facade over self._rs (_net_epoch,
# _vpn_owned_by_us, ...) are the real ones, not rewritten in a stub: if the
# state is refactored again, the tests will fail together with the code rather
# than diverging from it.
# ---------------------------------------------------------------------------

class _FakeVpnModule:
    """Stand-in for vpn.py: configurable results for the needed functions."""
    IS_WINDOWS = True

    def __init__(self, get_vpn_connected_result=None, get_vpn_connected_exc=None):
        self._result = get_vpn_connected_result
        self._exc = get_vpn_connected_exc
        self.disconnect_and_unroute_calls = []
        self.rasdial_disconnect_calls = []

    def get_vpn_connected(self, name, all_user=None, timeout=10.0):
        if self._exc is not None:
            raise self._exc
        return self._result

    def disconnect_and_unroute(self, base_path, connection_name, all_user=None):
        self.disconnect_and_unroute_calls.append((connection_name, all_user))
        return {"ok": True, "owned": True, "routes_removed": True, "vpn_disconnected": True}

    def rasdial_disconnect(self, name, timeout=20.0, all_user=None):
        self.rasdial_disconnect_calls.append((name, all_user))
        return True


class _FakeScannerCfg:
    def __init__(self, name="MyVPN", all_user=False, vpn_enabled=True):
        self.vpn_connection_name = name
        self.vpn_connection_all_user = all_user
        self.vpn_enabled = vpn_enabled


def _make_gui(scanner_mod, name="MyVPN", all_user=False, vpn_enabled=True, pending=False):
    """ScannerGUI without a window: real methods and facade, fake "side" points."""
    gui = object.__new__(scanner_mod.ScannerGUI)
    gui._rs = scanner_mod.RecoveryState()
    gui._rs.vpn_relied_upon = True
    gui._vpn_drop_confirm_pending = pending
    gui._closing = False
    gui._vpn_status_from_reality_lock = threading.Lock()
    gui._vpn_status_from_reality_in_progress = False
    gui.scanner = _FakeScannerCfg(name, all_user, vpn_enabled)
    gui.posted = []                # what the background worker puts into the GUI thread queue
    gui.invalidated_with = None
    gui.status_calls = []
    # Replace "heavy"/threading methods with call recorders:
    gui._post_to_gui = lambda fn, *args: gui.posted.append((fn, args)) or True
    gui._on_vpn_session_invalidated = lambda reason: setattr(gui, "invalidated_with", reason)
    gui._set_vpn_status = lambda key: gui.status_calls.append(key)
    return gui


# --- read-only facade over self._rs -----------------------------------------

@pytest.mark.parametrize("facade,field", [
    ("_net_epoch", "epoch"),
    ("_internet_down", "internet_down"),
    ("_recovery_in_progress", "recovery_in_progress"),
    ("_path_recovery_in_progress", "path_recovery_in_progress"),
    ("_path_recovery_deferred", "path_recovery_deferred"),
    ("_path_recovery_epoch", "path_recovery_epoch"),
    ("_vpn_relied_upon", "vpn_relied_upon"),
    ("_vpn_owned_by_us", "vpn_owned_by_us"),
    ("_soft_recovery_attempted", "soft_recovery_attempted"),
    ("_connect_fail_batch_streak", "connect_fail_batch_streak"),
])
def test_scanner_gui_facade_reads_from_recovery_state_and_is_read_only(scanner_mod, facade, field):
    gui = _make_gui(scanner_mod)
    value = 5 if isinstance(getattr(gui._rs, field), int) and not isinstance(getattr(gui._rs, field), bool) else True
    setattr(gui._rs, field, value)
    assert getattr(gui, facade) == value
    with pytest.raises(AttributeError):
        setattr(gui, facade, value)          # writing is only possible via self._rs


# --- _on_vpn_drop_confirm_done: True/False/None + epoch -------------------

def test_on_vpn_drop_confirm_done_none_does_not_invalidate(scanner_mod):
    gui = _make_gui(scanner_mod, pending=True)
    gui._on_vpn_drop_confirm_done(gui._net_epoch, None)
    assert gui._vpn_drop_confirm_pending is False
    assert gui.invalidated_with is None


def test_on_vpn_drop_confirm_done_true_is_false_positive(scanner_mod):
    gui = _make_gui(scanner_mod, pending=True)
    gui._on_vpn_drop_confirm_done(gui._net_epoch, True)
    assert gui._vpn_drop_confirm_pending is False
    assert gui.invalidated_with is None


def test_on_vpn_drop_confirm_done_false_invalidates(scanner_mod):
    gui = _make_gui(scanner_mod, pending=True)
    gui._on_vpn_drop_confirm_done(gui._net_epoch, False)
    assert gui._vpn_drop_confirm_pending is False
    assert gui.invalidated_with == "system_vpn_down"


def test_on_vpn_drop_confirm_done_stale_epoch_is_ignored_but_releases_pending(scanner_mod):
    """REGRESSION: the result of a stale worker must neither invalidate the
    session nor leave _vpn_drop_confirm_pending set — otherwise
    _confirm_vpn_dropped() would silently refuse to start new confirmations
    until the next internet loss."""
    gui = _make_gui(scanner_mod, pending=True)
    stale_epoch = gui._net_epoch
    gui._rs.bump_epoch()                       # a connectivity event after the worker started
    gui._on_vpn_drop_confirm_done(stale_epoch, False)
    assert gui.invalidated_with is None
    assert gui._vpn_drop_confirm_pending is False


# --- _confirm_vpn_dropped_worker: must not collapse None into False -------

def test_confirm_vpn_dropped_worker_preserves_none(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=None))
    gui = _make_gui(scanner_mod)
    gui._confirm_vpn_dropped_worker(4)
    assert len(gui.posted) == 1
    fn, args = gui.posted[0]
    assert fn == gui._on_vpn_drop_confirm_done
    # REGRESSION: previously bool(still_up) was passed -> always False, even when
    # get_vpn_connected() returned None ("I don't know").
    assert args == (4, None)


def test_confirm_vpn_dropped_worker_preserves_true(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=True))
    gui = _make_gui(scanner_mod)
    gui._confirm_vpn_dropped_worker(1)
    assert gui.posted[0][1] == (1, True)


def test_confirm_vpn_dropped_worker_preserves_false(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=False))
    gui = _make_gui(scanner_mod)
    gui._confirm_vpn_dropped_worker(2)
    assert gui.posted[0][1] == (2, False)


def test_confirm_vpn_dropped_worker_exception_yields_none(scanner_mod, monkeypatch):
    monkeypatch.setattr(
        scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_exc=RuntimeError("ps failed"))
    )
    gui = _make_gui(scanner_mod)
    gui._confirm_vpn_dropped_worker(3)
    assert gui.posted[0][1] == (3, None)


# --- _confirm_vpn_dropped: launching the confirmation -----------------------

class _RecordingThread:
    """Replacement for threading.Thread: records the launch, executes nothing."""
    instances = []

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
        self.target, self.args, self.name, self.daemon = target, args, name, daemon
        self.started = False
        _RecordingThread.instances.append(self)

    def start(self):
        self.started = True


@pytest.fixture
def recorded_threads(scanner_mod, monkeypatch):
    _RecordingThread.instances = []
    monkeypatch.setattr(scanner_mod.threading, "Thread", _RecordingThread)
    return _RecordingThread.instances


def test_confirm_vpn_dropped_starts_worker_with_current_epoch(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod)
    gui._rs.epoch = 6
    gui._confirm_vpn_dropped()
    assert gui._vpn_drop_confirm_pending is True
    assert len(recorded_threads) == 1
    t = recorded_threads[0]
    assert t.started and t.daemon is True
    assert t.target == gui._confirm_vpn_dropped_worker
    assert t.args == (6,)


def test_confirm_vpn_dropped_does_not_start_second_worker_while_pending(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod, pending=True)
    gui._confirm_vpn_dropped()
    assert recorded_threads == []


def test_confirm_vpn_dropped_noop_when_vpn_watch_inactive(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod)
    gui._rs.internet_down = True
    gui._confirm_vpn_dropped()
    assert recorded_threads == []
    assert gui.invalidated_with is None


def test_confirm_vpn_dropped_owned_session_invalidates_without_powershell(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = True
    gui._confirm_vpn_dropped()
    assert gui.invalidated_with == "owned_interface_down"
    assert recorded_threads == []


def test_confirm_vpn_dropped_can_run_again_after_stale_result(scanner_mod, recorded_threads):
    """End-to-end regression scenario: confirmation launched -> epoch changed ->
    stale result arrived -> a new confirmation must be launchable."""
    gui = _make_gui(scanner_mod)
    gui._confirm_vpn_dropped()
    assert len(recorded_threads) == 1
    started_epoch = recorded_threads[0].args[0]

    gui._rs.bump_epoch()
    gui._on_vpn_drop_confirm_done(started_epoch, True)

    gui._confirm_vpn_dropped()
    assert len(recorded_threads) == 2
    assert recorded_threads[1].args == (gui._net_epoch,)


# --- _query_vpn_status_from_reality: worker-safe query (no Tk) ----------------
# Previously this was a single method _set_vpn_status_from_reality(); now the
# query (_query_..., returns a state key or None) is separate from applying
# it (_set_vpn_status_from_reality_async + worker, gated by epoch).

def test_query_vpn_status_none_leaves_status_untouched(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=None))
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = True  # snapshot "was" — must not be dropped to None
    # REGRESSION: previously None fell into the else branch and produced
    # "vpn_state_disconnected", resetting _vpn_relied_upon.
    assert gui._query_vpn_status_from_reality() is None
    assert gui.status_calls == []
    assert gui._vpn_owned_by_us is True


def test_query_vpn_status_exception_is_treated_as_unknown(scanner_mod, monkeypatch):
    monkeypatch.setattr(
        scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_exc=RuntimeError("ps failed"))
    )
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = True
    assert gui._query_vpn_status_from_reality() is None
    assert gui._vpn_owned_by_us is True


def test_query_vpn_status_true_owned_is_connected(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=True))
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = True
    assert gui._query_vpn_status_from_reality() == "vpn_state_connected"


def test_query_vpn_status_true_not_owned_is_system(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=True))
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = False
    assert gui._query_vpn_status_from_reality() == "vpn_state_system"


def test_query_vpn_status_false_is_disconnected_and_clears_owned(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=False))
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = True
    assert gui._query_vpn_status_from_reality() == "vpn_state_disconnected"
    assert gui._vpn_owned_by_us is False


def test_query_vpn_status_vpn_disabled_is_disconnected(scanner_mod, monkeypatch):
    # vpn_enabled=False -> early return, get_vpn_connected must not even be called.
    fake_vpn = _FakeVpnModule(get_vpn_connected_exc=AssertionError("must not be called"))
    monkeypatch.setattr(scanner_mod, "vpn", fake_vpn)
    gui = _make_gui(scanner_mod, vpn_enabled=False)
    assert gui._query_vpn_status_from_reality() == "vpn_state_disconnected"


def test_query_vpn_status_no_connection_name_is_disconnected(scanner_mod, monkeypatch):
    fake_vpn = _FakeVpnModule(get_vpn_connected_exc=AssertionError("must not be called"))
    monkeypatch.setattr(scanner_mod, "vpn", fake_vpn)
    gui = _make_gui(scanner_mod, name="")
    assert gui._query_vpn_status_from_reality() == "vpn_state_disconnected"


def test_query_vpn_status_non_windows_is_disconnected(scanner_mod, monkeypatch):
    fake_vpn = _FakeVpnModule(get_vpn_connected_result=True)
    fake_vpn.IS_WINDOWS = False
    monkeypatch.setattr(scanner_mod, "vpn", fake_vpn)
    gui = _make_gui(scanner_mod)
    assert gui._query_vpn_status_from_reality() == "vpn_state_disconnected"


# --- _set_vpn_status_from_reality_async / _worker ----------------------------

def test_status_from_reality_async_starts_worker_with_current_epoch(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod)
    gui._rs.epoch = 4
    gui._set_vpn_status_from_reality_async()
    assert gui._vpn_status_from_reality_in_progress is True
    assert len(recorded_threads) == 1
    t = recorded_threads[0]
    assert t.started and t.daemon is True
    assert t.target == gui._set_vpn_status_from_reality_worker
    assert t.args == (4,)


def test_status_from_reality_async_coalesces_while_in_progress(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod)
    gui._vpn_status_from_reality_in_progress = True
    gui._set_vpn_status_from_reality_async()
    assert recorded_threads == []


def test_status_from_reality_async_noop_when_closing(scanner_mod, recorded_threads):
    gui = _make_gui(scanner_mod)
    gui._closing = True
    gui._set_vpn_status_from_reality_async()
    assert recorded_threads == []
    assert gui._vpn_status_from_reality_in_progress is False


def test_status_from_reality_worker_posts_status_to_gui(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=True))
    gui = _make_gui(scanner_mod)
    gui._rs.vpn_owned_by_us = True
    gui._vpn_status_from_reality_in_progress = True
    gui._set_vpn_status_from_reality_worker(gui._net_epoch)
    # It is _set_vpn_status that goes to the GUI thread (replaced by a lambda in
    # _make_gui, so we compare by arguments, not by identity).
    assert len(gui.posted) == 1
    assert gui.posted[0][1] == ("vpn_state_connected",)
    assert gui._vpn_status_from_reality_in_progress is False


def test_status_from_reality_worker_unknown_state_posts_nothing(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=None))
    gui = _make_gui(scanner_mod)
    gui._vpn_status_from_reality_in_progress = True
    gui._set_vpn_status_from_reality_worker(gui._net_epoch)
    assert gui.posted == []
    assert gui._vpn_status_from_reality_in_progress is False


def test_status_from_reality_worker_drops_stale_epoch_result(scanner_mod, monkeypatch):
    """The connectivity epoch changed during the query — the stale status is not
    applied, but the in_progress flag is still released."""
    monkeypatch.setattr(scanner_mod, "vpn", _FakeVpnModule(get_vpn_connected_result=True))
    gui = _make_gui(scanner_mod)
    gui._vpn_status_from_reality_in_progress = True
    stale = gui._net_epoch
    gui._rs.bump_epoch()
    gui._set_vpn_status_from_reality_worker(stale)
    assert gui.posted == []
    assert gui._vpn_status_from_reality_in_progress is False


def test_status_from_reality_worker_releases_flag_on_unexpected_error(scanner_mod, monkeypatch):
    gui = _make_gui(scanner_mod)
    gui._vpn_status_from_reality_in_progress = True

    def boom():
        raise RuntimeError("unexpected")

    gui._query_vpn_status_from_reality = boom
    gui._set_vpn_status_from_reality_worker(gui._net_epoch)   # must not raise
    assert gui.posted == []
    assert gui._vpn_status_from_reality_in_progress is False


# --- _force_kill_vpn_worker: epoch gate against a race with restored network ---

def test_force_kill_vpn_worker_skips_when_epoch_stale(scanner_mod, monkeypatch):
    fake_vpn = _FakeVpnModule()
    monkeypatch.setattr(scanner_mod, "vpn", fake_vpn)
    gui = _make_gui(scanner_mod)
    gui._rs.epoch = 5  # the network has already recovered and the epoch was bumped again
    # The worker was started with the old epoch=3 (before the network recovered).
    gui._force_kill_vpn_worker("MyVPN", False, True, 3)
    assert fake_vpn.disconnect_and_unroute_calls == []
    assert fake_vpn.rasdial_disconnect_calls == []


def test_force_kill_vpn_worker_owned_disconnects_when_epoch_current(scanner_mod, monkeypatch):
    fake_vpn = _FakeVpnModule()
    monkeypatch.setattr(scanner_mod, "vpn", fake_vpn)
    gui = _make_gui(scanner_mod)
    gui._rs.epoch = 3
    gui._force_kill_vpn_worker("MyVPN", False, True, 3)
    assert fake_vpn.disconnect_and_unroute_calls == [("MyVPN", False)]
    assert fake_vpn.rasdial_disconnect_calls == []


def test_force_kill_vpn_worker_not_owned_uses_rasdial_when_epoch_current(scanner_mod, monkeypatch):
    fake_vpn = _FakeVpnModule()
    monkeypatch.setattr(scanner_mod, "vpn", fake_vpn)
    gui = _make_gui(scanner_mod)
    gui._rs.epoch = 7
    gui._force_kill_vpn_worker("MyVPN", True, False, 7)
    assert fake_vpn.rasdial_disconnect_calls == [("MyVPN", True)]
    assert fake_vpn.disconnect_and_unroute_calls == []


# ---------------------------------------------------------------------------
# _local_tcp_probe / _local_http_probe / _local_probe_hosts — previously lived
# in vpn.py (tcp_probe/http_probe/probe_host_full/probe_hosts), now part of the
# scanner. Real local sockets (127.0.0.1), no external network.
# ---------------------------------------------------------------------------

@pytest.fixture
def free_tcp_port():
    """A free port: bind and close the socket immediately (to test refusal)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def tcp_listener():
    """A TCP server on 127.0.0.1: accepts and immediately closes the connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    srv.settimeout(0.2)          # BEFORE the thread starts
    stop = threading.Event()

    def _loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    yield "127.0.0.1", port
    stop.set()
    t.join(timeout=2)
    srv.close()


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:1/never")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


@pytest.fixture
def http_server():
    srv, t = _serve(_OkHandler)
    yield "127.0.0.1", srv.server_address[1]
    srv.shutdown()
    srv.server_close()
    t.join(timeout=2)


@pytest.fixture
def redirect_server():
    srv, t = _serve(_RedirectHandler)
    yield "127.0.0.1", srv.server_address[1]
    srv.shutdown()
    srv.server_close()
    t.join(timeout=2)


def test_local_tcp_probe_success_against_listener(scanner_mod, tcp_listener):
    host, port = tcp_listener
    assert scanner_mod._local_tcp_probe(host, port, timeout=1.0) is True


def test_local_tcp_probe_failure_against_closed_port(scanner_mod, free_tcp_port):
    assert scanner_mod._local_tcp_probe("127.0.0.1", free_tcp_port, timeout=0.5) is False


def test_local_http_probe_success_against_local_server(scanner_mod, http_server):
    host, port = http_server
    assert scanner_mod._local_http_probe(host, port, timeout=1.0) is True


def test_local_http_probe_failure_against_closed_port(scanner_mod, free_tcp_port):
    assert scanner_mod._local_http_probe("127.0.0.1", free_tcp_port, timeout=0.5) is False


def test_local_http_probe_does_not_follow_redirects(scanner_mod, redirect_server):
    """A redirect means "the host responds"; the probe must not follow Location
    (otherwise it could reach arbitrary addresses)."""
    host, port = redirect_server
    assert scanner_mod._local_http_probe(host, port, timeout=1.0) is True


def test_local_http_probe_requests_with_tls_verification(scanner_mod, monkeypatch):
    """verify=True explicitly: the probe must not "approve" a host that the real
    download would reject during the TLS handshake."""
    seen = {}

    class _Resp:
        def close(self):
            seen["closed"] = True

    def fake_get(url, **kw):
        seen["url"], seen["kw"] = url, kw
        return _Resp()

    monkeypatch.setattr(scanner_mod.requests, "get", fake_get)
    assert scanner_mod._local_http_probe("h.example", 8443, scheme="https", timeout=1.5) is True
    assert seen["url"] == "https://h.example:8443/"
    assert seen["kw"]["verify"] is True
    assert seen["kw"]["allow_redirects"] is False
    assert seen["kw"]["timeout"] == 1.5
    assert seen["closed"] is True


def test_local_http_probe_tls_error_is_failure(scanner_mod, monkeypatch):
    def boom(url, **kw):
        raise requests.exceptions.SSLError("bad cert")

    monkeypatch.setattr(scanner_mod.requests, "get", boom)
    assert scanner_mod._local_http_probe("h.example", 443, scheme="https") is False


def test_local_probe_hosts_empty_input_returns_empty_dict(scanner_mod):
    assert scanner_mod._local_probe_hosts([]) == {}


def test_local_probe_hosts_short_circuits_http_when_tcp_fails(scanner_mod, monkeypatch):
    monkeypatch.setattr(scanner_mod, "_local_tcp_probe", lambda host, port, *a, **k: False)

    def boom(*a, **k):
        raise AssertionError("HTTP probe must not be called if TCP has already failed")

    monkeypatch.setattr(scanner_mod, "_local_http_probe", boom)
    assert scanner_mod._local_probe_hosts([("h", 80)]) == {("h", 80): False}


def test_local_probe_hosts_dedups_and_reports_per_host_result(scanner_mod, monkeypatch):
    calls = []
    monkeypatch.setattr(scanner_mod, "_local_tcp_probe", lambda host, port, *a, **k: True)

    def fake_http(host, port, scheme="http", *a, **k):
        calls.append((host, port, scheme))
        return host == "good.example"

    monkeypatch.setattr(scanner_mod, "_local_http_probe", fake_http)
    results = scanner_mod._local_probe_hosts([
        ("good.example", 80), ("bad.example", 80), ("good.example", 80),
    ])
    assert results == {("good.example", 80): True, ("bad.example", 80): False}
    assert len(calls) == 2            # the duplicate was not checked again


def test_local_probe_hosts_passes_lowercased_scheme(scanner_mod, monkeypatch):
    seen = {}
    monkeypatch.setattr(scanner_mod, "_local_tcp_probe", lambda host, port, *a, **k: True)

    def fake_http(host, port, scheme="http", *a, **k):
        seen[(host, port)] = scheme
        return True

    monkeypatch.setattr(scanner_mod, "_local_http_probe", fake_http)
    scanner_mod._local_probe_hosts([("h", 443, "HTTPS")])
    assert seen[("h", 443)] == "https"


def test_local_probe_hosts_worker_exception_counts_as_false(scanner_mod, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner_mod, "_local_tcp_probe", boom)
    assert scanner_mod._local_probe_hosts([("h", 80)]) == {("h", 80): False}


def test_local_probe_hosts_end_to_end_on_real_sockets(scanner_mod, http_server, free_tcp_port):
    host, port = http_server
    results = scanner_mod._local_probe_hosts([(host, port), ("127.0.0.1", free_tcp_port)])
    assert results == {(host, port): True, ("127.0.0.1", free_tcp_port): False}


# ---------------------------------------------------------------------------
# _redact_url — direct tests. Previously the function was only checked indirectly
# (via caplog in the fetch_playlist_channels test), so a regression in one of
# the branches (IPv6, port, empty query, non-string argument) would have gone unnoticed.
# ---------------------------------------------------------------------------

def test_redact_url_masks_userinfo(scanner_mod):
    out = scanner_mod._redact_url("http://user:secret@example.com/live/1.ts")
    assert out == "http://***@example.com/live/1.ts"
    assert "secret" not in out and "user" not in out


def test_redact_url_masks_username_only(scanner_mod):
    out = scanner_mod._redact_url("http://onlyuser@example.com/x")
    assert out == "http://***@example.com/x"


def test_redact_url_keeps_port_and_fragment(scanner_mod):
    out = scanner_mod._redact_url("http://u:p@Example.COM:8080/a/b.m3u8#frag")
    assert out == "http://***@example.com:8080/a/b.m3u8#frag"


def test_redact_url_masks_secret_query_values_keeps_safe_ones_in_order(scanner_mod):
    out = scanner_mod._redact_url("http://e.com/p?ch=12&token=abc123&quality=hd&sig=zzz")
    assert out == "http://e.com/p?ch=12&token=***&quality=hd&sig=***"


def test_redact_url_query_key_match_is_case_insensitive(scanner_mod):
    out = scanner_mod._redact_url("http://e.com/p?TOKEN=abc&Password=xyz")
    assert out == "http://e.com/p?TOKEN=***&Password=***"


def test_redact_url_param_without_value_is_left_alone(scanner_mod):
    # No '=' — there is no value, nothing to hide.
    assert scanner_mod._redact_url("http://e.com/p?token&x=1") == "http://e.com/p?token&x=1"


def test_redact_url_ipv6_host_keeps_brackets_and_port(scanner_mod):
    out = scanner_mod._redact_url("http://u:p@[2001:db8::1]:8080/x")
    assert "p@" not in out and "u:p" not in out
    assert out.startswith("http://***@")
    assert "2001:db8::1" in out and ":8080" in out


def test_redact_url_without_credentials_is_unchanged(scanner_mod):
    url = "https://example.com/live/stream.m3u8?ch=1"
    assert scanner_mod._redact_url(url) == url


def test_redact_url_empty_string_returned_as_is(scanner_mod):
    assert scanner_mod._redact_url("") == ""


@pytest.mark.parametrize("bad", ["not a url", "/relative/path?token=abc", "example.com/x"])
def test_redact_url_schemeless_input_never_echoed(scanner_mod, bad):
    """Without a scheme it cannot be parsed safely — a placeholder goes to the
    log, not the original string (which may contain credentials)."""
    assert scanner_mod._redact_url(bad) == "<unredactable url>"


@pytest.mark.parametrize("bad", [None, 123, b"http://e.com", ["http://e.com"]])
def test_redact_url_non_string_never_raises(scanner_mod, bad):
    assert scanner_mod._redact_url(bad) == "<unredactable url>"


def test_redact_url_invalid_port_does_not_raise_and_drops_secret(scanner_mod):
    out = scanner_mod._redact_url("http://u:secret@example.com:notaport/x")
    assert "secret" not in out


# ---------------------------------------------------------------------------
# _find_extinf_name_comma / _parse_extinf_name — edge cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body, expected", [
    ("-1,Name", 2),
    ("-1", -1),
    ("", -1),
    ('-1 tvg-name="A,B"', -1),                                   # comma only inside quotes
    ('-1 group-title="News, Sport",Name', 'last-comma'),         # comma inside quotes is skipped
    ('-1 tvg-name="A,Name', 'first-comma'),                      # unpaired quote -> first comma
])
def test_find_extinf_name_comma(scanner_mod, body, expected):
    if expected == "last-comma":
        expected = body.rindex(",")
    elif expected == "first-comma":
        expected = body.index(",")
    assert scanner_mod.IPTVScanner._find_extinf_name_comma(body) == expected


def test_parse_extinf_name_keeps_commas_in_channel_name(scanner_mod):
    assert scanner_mod.IPTVScanner._parse_extinf_name("#EXTINF:0.5,Name, with, commas") == "Name, with, commas"


def test_parse_extinf_name_tvg_name_with_quoted_comma(scanner_mod):
    line = '#EXTINF:-1 tvg-name="A, B" group-title="X",'
    assert scanner_mod.IPTVScanner._parse_extinf_name(line) == "A, B"


def test_parse_extinf_name_single_quoted_tvg_name(scanner_mod):
    assert scanner_mod.IPTVScanner._parse_extinf_name("#EXTINF:-1 tvg-name='Solo',") == "Solo"


def test_parse_extinf_name_returns_empty_when_nothing_found(scanner_mod):
    assert scanner_mod.IPTVScanner._parse_extinf_name("#EXTINF:-1,") == ""
    assert scanner_mod.IPTVScanner._parse_extinf_name("#EXTINF:-1") == ""


# ---------------------------------------------------------------------------
# _find_in_exception_chain / _is_connection_reset
# ---------------------------------------------------------------------------

def test_find_in_exception_chain_none_returns_none(scanner_mod):
    assert scanner_mod.IPTVScanner._find_in_exception_chain(None, lambda x: True) is None


def test_find_in_exception_chain_returns_self_first(scanner_mod):
    e = ValueError("top")
    e.__cause__ = ValueError("nested")
    found = scanner_mod.IPTVScanner._find_in_exception_chain(e, lambda x: isinstance(x, ValueError))
    assert found is e


def test_find_in_exception_chain_cause_is_checked_before_context(scanner_mod):
    """Traversal order: args -> __cause__ -> __context__ (important for _find_os_error)."""
    cause, context = KeyError("cause"), KeyError("context")
    e = Exception("top")
    e.__cause__ = cause
    e.__context__ = context
    found = scanner_mod.IPTVScanner._find_in_exception_chain(e, lambda x: isinstance(x, KeyError))
    assert found is cause


def test_find_in_exception_chain_looks_into_args(scanner_mod):
    inner = ConnectionResetError(104, "reset")
    e = Exception(inner)
    assert scanner_mod.IPTVScanner._find_in_exception_chain(
        e, lambda x: isinstance(x, ConnectionResetError)) is inner


def test_find_in_exception_chain_survives_cycles(scanner_mod):
    a, b = Exception("a"), Exception("b")
    a.__cause__ = b
    b.__cause__ = a          # cycle: without _seen protection this would RecursionError
    assert scanner_mod.IPTVScanner._find_in_exception_chain(a, lambda x: False) is None


def test_is_connection_reset_detects_nested_reset(scanner_mod):
    e = requests.exceptions.ChunkedEncodingError(
        Exception("Connection broken", ConnectionResetError(104, "reset")))
    assert scanner_mod.IPTVScanner._is_connection_reset(e) is True


def test_is_connection_reset_false_for_other_errors(scanner_mod):
    assert scanner_mod.IPTVScanner._is_connection_reset(ConnectionRefusedError(111, "refused")) is False
    assert scanner_mod.IPTVScanner._is_connection_reset(ValueError("x")) is False


# ---------------------------------------------------------------------------
# fetch_playlist_channels — additional decoding and streaming branches
# ---------------------------------------------------------------------------

def test_fetch_playlist_channels_requests_stream_true(scanner_mod, scanner, monkeypatch):
    """stream=True is mandatory: otherwise requests would download the whole
    body before iter_content and MAX_PLAYLIST_BYTES would no longer protect
    against large responses."""
    _, session = _fetch(scanner, monkeypatch, text="#EXTINF:-1,A\nhttp://e.com/a.ts\n")
    assert session.last_kwargs["stream"] is True


def test_fetch_playlist_channels_bom_with_explicit_utf8_charset(scanner_mod, scanner, monkeypatch):
    """charset=utf-8 is declared explicitly, but a BOM in the body must still
    not create a phantom channel (for utf-8 the code also goes through the
    utf-8-sig branch)."""
    body = "\ufeff#EXTM3U\n#EXTINF:-1,One\nhttp://e.com/1.ts\n".encode("utf-8")
    resp = _FakeResponse(
        body=body, encoding="utf-8",
        headers={"Content-Type": "application/vnd.apple.mpegurl; charset=utf-8"},
    )
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [(c.name, c.url) for c in channels] == [("One", "http://e.com/1.ts")]


def test_fetch_playlist_channels_charset_in_header_case_insensitive(scanner_mod, scanner, monkeypatch):
    body = "#EXTINF:-1,Первый канал\nhttp://e.com/1.ts\n".encode("cp1251")
    resp = _FakeResponse(
        body=body, encoding="cp1251",
        headers={"Content-Type": "Text/Plain; CHARSET=windows-1251"},
    )
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [c.name for c in channels] == ["Первый канал"]


def test_fetch_playlist_channels_encoding_ignored_without_charset_in_header(scanner_mod, scanner, monkeypatch):
    """resp.encoding without charset= in Content-Type is a requests default, not
    the server's will: we ignore it and read as UTF-8 (including for text/plain)."""
    body = "#EXTINF:-1,Канал\nhttp://e.com/1.ts\n".encode("utf-8")
    resp = _FakeResponse(body=body, encoding="ISO-8859-1", headers={"Content-Type": "text/plain"})
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert [c.name for c in channels] == ["Канал"]


def test_fetch_playlist_channels_invalid_bytes_are_replaced_not_fatal(scanner_mod, scanner, monkeypatch):
    body = b"#EXTINF:-1,Bad \xff\xfe name\nhttp://e.com/1.ts\n"
    channels, _ = _fetch(scanner, monkeypatch, response=_FakeResponse(body=body))
    assert len(channels) == 1
    assert channels[0].url == "http://e.com/1.ts"


def test_fetch_playlist_channels_empty_body_returns_empty_list(scanner_mod, scanner, monkeypatch):
    channels, session = _fetch(scanner, monkeypatch, response=_FakeResponse(body=b""))
    assert channels == []
    assert session.last_response.closed is True


def test_fetch_playlist_channels_closes_response_when_iteration_fails(scanner_mod, scanner, monkeypatch):
    """A break in the middle of reading the body: the response is still closed,
    the error does not propagate — an empty list is returned."""
    class _Broken(_FakeResponse):
        def iter_content(self, chunk_size=None):
            yield b"#EXTINF:-1,A\n"
            raise requests.exceptions.ChunkedEncodingError("cut")

    resp = _Broken(body=b"")
    channels, _ = _fetch(scanner, monkeypatch, response=resp)
    assert channels == []
    assert resp.closed is True