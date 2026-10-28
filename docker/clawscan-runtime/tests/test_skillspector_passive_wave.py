"""Native PCM evidence remains tied to complete non-executable source bytes."""

import struct

import pytest

from skillspector.nodes.build_context import _build_component_metadata
from skillspector.nodes.report import _json_component


def wave_bytes(*, channels=1, rate=44100, bits=16, payload=None, codec=1):
    block = channels * (bits // 8)
    payload = b"\x00" * max(block * 3, 1) if payload is None else payload
    padding = b"\x00" if len(payload) % 2 else b""
    body = (
        struct.pack(
            "<4sIHHIIHH4sI",
            b"fmt ",
            16,
            codec,
            channels,
            rate,
            rate * block,
            block,
            bits,
            b"data",
            len(payload),
        )
        + payload
        + padding
    )
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WAVE" + body


def metadata(tmp_path, raw, *, name="assets/bark.wav", mode=0o644, cached=None):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    target.chmod(mode)
    rows, _ = _build_component_metadata(
        tmp_path, [name], {}, {name: raw if cached is None else cached}
    )
    return rows[0]


@pytest.mark.parametrize("channels,bits,size", [(1, 8, 3), (1, 16, 6), (2, 24, 18), (8, 32, 96)])
def test_complete_pcm_evidence_survives_json_report(tmp_path, channels, bits, size):
    raw = wave_bytes(channels=channels, bits=bits, payload=b"\x00" * size)
    original = bytes(raw)
    row = metadata(tmp_path, raw)
    evidence = row.get("passive_binary")
    assert evidence == {
        "format": "riff_wave_pcm_v1",
        "channels": channels,
        "sample_rate": 44100,
        "bits_per_sample": bits,
        "block_align": channels * (bits // 8),
        "byte_rate": 44100 * channels * (bits // 8),
        "data_bytes": size,
        "frames": size // (channels * (bits // 8)),
        "container_bytes": len(raw),
    }
    assert _json_component(row)["passive_binary"] == evidence
    assert row["type"] == "other" and row["executable"] is False and row["lines"] == 0
    assert raw == original and (tmp_path / "assets/bark.wav").read_bytes() == original


def mutate(raw, offset, value):
    return raw[:offset] + value + raw[offset + len(value) :]


@pytest.mark.parametrize(
    "change",
    [
        lambda b: mutate(b, 0, b"RIFX"),
        lambda b: mutate(b, 0, b"RF64"),
        lambda b: mutate(b, 4, struct.pack("<I", len(b))),
        lambda b: mutate(b, 8, b"AVI "),
        lambda b: mutate(b, 12, b"LIST"),
        lambda b: mutate(b, 16, struct.pack("<I", 18)),
        lambda b: mutate(b, 20, struct.pack("<H", 3)),
        lambda b: mutate(b, 22, struct.pack("<H", 0)),
        lambda b: mutate(b, 22, struct.pack("<H", 9)),
        lambda b: mutate(b, 24, struct.pack("<I", 0)),
        lambda b: mutate(b, 24, struct.pack("<I", 384001)),
        lambda b: mutate(b, 28, struct.pack("<I", 1)),
        lambda b: mutate(b, 32, struct.pack("<H", 1)),
        lambda b: mutate(b, 34, struct.pack("<H", 64)),
        lambda b: mutate(b, 36, b"JUNK"),
        lambda b: mutate(b, 40, struct.pack("<I", 0)),
        lambda b: mutate(b, 40, struct.pack("<I", 3)),
        lambda b: b[:-1],
        lambda b: b + b"\x00",  # Unaccounted trailer.
        lambda b: mutate(b, 4, struct.pack("<I", len(b) + 8)) + b"LIST\x00\x00\x00\x00",
        lambda b: b"\x7fELF" + b[4:],
        lambda b: b"MZ" + b[2:],
        lambda b: b"#!/bin/sh\n" + b,
        lambda b: b"\xa7\x0d\x0d\x0a" + b[4:],
    ],
)
def test_unknown_or_executable_carriers_receive_no_pcm_evidence(tmp_path, change):
    assert "passive_binary" not in metadata(tmp_path, change(wave_bytes()))


@pytest.mark.parametrize(
    "mode,cached,name",
    [
        (0o755, None, "assets/bark.wav"),
        (0o644, b"RIFF", "assets/bark.wav"),
        (0o644, b"", "assets/bark.wav"),
        (0o644, None, "assets/bark.bin"),
        (0o644, None, "assets/bark.wav.py"),
    ],
)
def test_proof_requires_complete_passive_named_source(tmp_path, mode, cached, name):
    assert "passive_binary" not in metadata(
        tmp_path, wave_bytes(), mode=mode, cached=cached, name=name
    )


def test_noncanonical_padding_receives_no_pcm_evidence(tmp_path):
    raw = wave_bytes(bits=8, payload=b"\x80" * 3)
    assert "passive_binary" not in metadata(tmp_path, raw[:-1] + b"x")


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "safe"),
        ("channels", True),
        ("sample_rate", 0),
        ("bits_per_sample", 64),
        ("block_align", 1),
        ("byte_rate", 1),
        ("data_bytes", 0),
        ("frames", 0),
        ("container_bytes", 1),
        ("extra", "unsupported"),
    ],
)
def test_report_does_not_forward_invalid_pcm_claims(tmp_path, field, value):
    row = metadata(tmp_path, wave_bytes())
    assert row.get("passive_binary") is not None
    row["passive_binary"] = {**row["passive_binary"], field: value}
    assert "passive_binary" not in _json_component(row)


@pytest.mark.parametrize(
    "field",
    [
        "channels",
        "sample_rate",
        "bits_per_sample",
        "block_align",
        "byte_rate",
        "data_bytes",
        "frames",
        "container_bytes",
    ],
)
@pytest.mark.parametrize("value", [True, False, None, "1", 1.5, -1])
def test_report_rejects_noninteger_or_negative_counts(tmp_path, field, value):
    row = metadata(tmp_path, wave_bytes())
    row["passive_binary"][field] = value
    assert "passive_binary" not in _json_component(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "assets/bark.bin"),
        ("path", ".private/bark.wav"),
        ("path", "bundle.zip!/bark.wav"),
        ("path", "assets/../bark.wav"),
        ("type", "python"),
        ("executable", True),
        ("lines", -1),
        ("local_only", True),
        ("hidden", True),
        ("source_local_only", True),
        ("outer_path", "bundle.zip"),
        ("container_depth", 1),
    ],
)
def test_report_rejects_proof_attached_to_ineligible_component(tmp_path, field, value):
    row = metadata(tmp_path, wave_bytes())
    row[field] = value
    assert "passive_binary" not in _json_component(row)


def test_all_truncated_canonical_inputs_remain_unproved(tmp_path):
    raw = wave_bytes()
    for length in range(len(raw)):
        assert "passive_binary" not in metadata(tmp_path, raw[:length])


@pytest.mark.parametrize("name", [".private/bark.wav", "bundle.zip!/bark.wav"])
def test_builder_omits_hidden_and_nested_proof(tmp_path, name):
    assert "passive_binary" not in metadata(tmp_path, wave_bytes(), name=name)


def test_normal_build_context_retains_decoded_cache_counts_and_pcm_proof(tmp_path):
    from skillspector.artifacts import ContentKind, decode_text
    from skillspector.nodes.build_context import build_context

    (tmp_path / "SKILL.md").write_text(
        "---\nname: pcm-fixture\ndescription: sound asset\n---\n# Sound\n"
    )
    raw = wave_bytes(payload=b"\xff\n" * 12)
    asset = tmp_path / "assets/bark.wav"
    asset.parent.mkdir()
    asset.write_bytes(raw)
    result = build_context({"skill_path": str(tmp_path)})
    row = next(c for c in result["component_metadata"] if c["path"] == "assets/bark.wav")
    assert row["lines"] == len(decode_text(raw).splitlines()) > 0
    assert row.get("passive_binary") is not None
    assert _json_component(row)["passive_binary"] == row["passive_binary"]
    artifact = next(a for a in result["artifact_inventory"] if a["path"] == row["path"])
    assert artifact["content_kind"] is ContentKind.BINARY
    assert result["raw_file_cache"][row["path"]] == raw == asset.read_bytes()


def test_utf8_decodable_wave_keeps_text_inspection_without_binary_proof(tmp_path):
    raw = wave_bytes(rate=1024, payload=b"\x00" * 6)
    assert raw.decode("utf-8")
    assert "passive_binary" not in metadata(tmp_path, raw)
