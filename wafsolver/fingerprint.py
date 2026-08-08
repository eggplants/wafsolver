"""The browser fingerprint AWS WAF expects alongside a challenge solution.

``challenge.js`` collects a large JSON blob describing the browser, prefixes it
with the CRC32 of its own serialisation, encrypts that with a hard-coded
AES-GCM key, and sends the result as the ``Zoey`` signal. The same checksum is
sent in clear and is mixed into the proof-of-work input.
"""

from __future__ import annotations

import base64
import json
import os
import random
import time
import uuid
import zlib
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: AES-GCM key embedded in challenge.js.
FP_KEY = bytes.fromhex(
    "6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98",
)

#: Default user agent, matching the fingerprint's other claims.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)

_SCREEN_INFO = "1920-1080-1032-24-*-*-*"

_PLUGINS = (
    "PDF Viewer",
    "Chrome PDF Viewer",
    "Chromium PDF Viewer",
    "Microsoft Edge PDF Viewer",
    "WebKit built-in PDF",
)

#: The fingerprint reports a GPU; any plausible one will do.
GPUS: tuple[dict[str, str], ...] = (
    {
        "vendor": "Google Inc. (AMD)",
        "model": (
            "ANGLE (AMD, AMD Radeon(TM) Graphics (0x00001681) "
            "Direct3D11 vs_5_0 ps_5_0, D3D11)"
        ),
    },
    {
        "vendor": "Google Inc. (Intel)",
        "model": (
            "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) "
            "Direct3D11 vs_5_0 ps_5_0, D3D11)"
        ),
    },
)

GPU_EXTENSIONS = (
    "ANGLE_instanced_arrays",
    "EXT_blend_minmax",
    "EXT_clip_control",
    "EXT_color_buffer_half_float",
    "EXT_depth_clamp",
    "EXT_disjoint_timer_query",
    "EXT_float_blend",
    "EXT_frag_depth",
    "EXT_polygon_offset_clamp",
    "EXT_shader_texture_lod",
    "EXT_texture_compression_bptc",
    "EXT_texture_compression_rgtc",
    "EXT_texture_filter_anisotropic",
    "EXT_texture_mirror_clamp_to_edge",
    "EXT_sRGB",
    "KHR_parallel_shader_compile",
    "OES_element_index_uint",
    "OES_fbo_render_mipmap",
    "OES_standard_derivatives",
    "OES_texture_float",
    "OES_texture_float_linear",
    "OES_texture_half_float",
    "OES_texture_half_float_linear",
    "OES_vertex_array_object",
    "WEBGL_blend_func_extended",
    "WEBGL_color_buffer_float",
    "WEBGL_compressed_texture_s3tc",
    "WEBGL_compressed_texture_s3tc_srgb",
    "WEBGL_debug_renderer_info",
    "WEBGL_debug_shaders",
    "WEBGL_depth_texture",
    "WEBGL_draw_buffers",
    "WEBGL_lose_context",
    "WEBGL_multi_draw",
    "WEBGL_polygon_mode",
)

_IV_SIZE = 12
_TAG_SIZE = 16


def encrypt(plaintext: bytes, key: bytes = FP_KEY) -> str:
    """Encrypt a payload into the ``iv::tag::ciphertext`` form WAF expects.

    Args:
        plaintext (bytes): The payload to encrypt.
        key (bytes): The AES-GCM key. Defaults to the challenge.js key.

    Returns:
        str: The encoded ciphertext.
    """
    iv = os.urandom(_IV_SIZE)
    blob = AESGCM(key).encrypt(iv, plaintext, None)
    tag, ciphertext = blob[-_TAG_SIZE:], blob[:-_TAG_SIZE]
    return f"{base64.b64encode(iv).decode()}::{tag.hex()}::{ciphertext.hex()}"


def decrypt(encrypted: str, key: bytes = FP_KEY) -> bytes:
    """Reverse :func:`encrypt`.

    Args:
        encrypted (str): An ``iv::tag::ciphertext`` string.
        key (bytes): The AES-GCM key. Defaults to the challenge.js key.

    Returns:
        bytes: The decrypted payload.
    """
    iv_b64, tag_hex, ciphertext_hex = encrypted.split("::")
    return AESGCM(key).decrypt(
        base64.b64decode(iv_b64),
        bytes.fromhex(ciphertext_hex) + bytes.fromhex(tag_hex),
        None,
    )


def build_payload(user_agent: str = USER_AGENT) -> dict[str, Any]:
    """Build the raw fingerprint object.

    Args:
        user_agent (str): The user agent to report.

    Returns:
        dict[str, Any]: The fingerprint, ready to be serialised.
    """
    now_ms = int(time.time() * 1000)
    gpu = random.choice(GPUS)  # noqa: S311 - not security sensitive
    bins = [random.randrange(0, 40) for _ in range(256)]  # noqa: S311
    bins[0] = random.randrange(14473, 16573)  # noqa: S311
    bins[-1] = random.randrange(14473, 16573)  # noqa: S311
    return {
        "metrics": {
            "fp2": 1,
            "browser": 0,
            "capabilities": 1,
            "gpu": 7,
            "dnt": 0,
            "math": 0,
            "screen": 0,
            "navigator": 0,
            "auto": 1,
            "stealth": 0,
            "subtle": 0,
            "canvas": 5,
            "formdetector": 1,
            "be": 0,
        },
        "start": now_ms,
        "flashVersion": None,
        "plugins": [{"name": name, "str": f"{name} "} for name in _PLUGINS],
        "dupedPlugins": "".join(f"{name} " for name in _PLUGINS) + f"||{_SCREEN_INFO}",
        "screenInfo": _SCREEN_INFO,
        "referrer": "",
        "userAgent": user_agent,
        "location": "",
        "webDriver": False,
        "capabilities": {
            "css": {
                "textShadow": 1,
                "WebkitTextStroke": 1,
                "boxShadow": 1,
                "borderRadius": 1,
                "borderImage": 1,
                "opacity": 1,
                "transform": 1,
                "transition": 1,
            },
            "js": {
                "audio": True,
                "geolocation": random.choice([True, False]),  # noqa: S311
                "localStorage": "supported",
                "touch": False,
                "video": True,
                "webWorker": random.choice([True, False]),  # noqa: S311
            },
            "elapsed": 1,
        },
        "gpu": {
            "vendor": gpu["vendor"],
            "model": gpu["model"],
            "extensions": list(GPU_EXTENSIONS),
        },
        "dnt": None,
        "math": {
            "tan": "-1.4214488238747245",
            "sin": "0.8178819121159085",
            "cos": "-0.5753861119575491",
        },
        "automation": {
            "wd": {"properties": {"document": [], "window": [], "navigator": []}},
            "phantom": {"properties": {"window": []}},
        },
        "stealth": {"t1": 0, "t2": 0, "i": 1, "mte": 0, "mtd": False},
        "crypto": {
            "crypto": 1,
            "subtle": 1,
            "encrypt": True,
            "decrypt": True,
            "wrapKey": True,
            "unwrapKey": True,
            "sign": True,
            "verify": True,
            "digest": True,
            "deriveBits": True,
            "deriveKey": True,
            "getRandomValues": True,
            "randomUUID": True,
        },
        "canvas": {
            "hash": random.randrange(645172295, 735192295),  # noqa: S311
            "emailHash": None,
            "histogramBins": bins,
        },
        "formDetected": False,
        "numForms": 0,
        "numFormElements": 0,
        "be": {"si": False},
        "end": now_ms + 1,
        "errors": [],
        "version": "2.4.0",
        "id": str(uuid.uuid4()),
    }


def build(user_agent: str = USER_AGENT) -> tuple[str, str]:
    """Build the fingerprint signal and its checksum.

    Args:
        user_agent (str): The user agent to report.

    Returns:
        tuple[str, str]: The CRC32 checksum and the encrypted fingerprint.
    """
    payload = json.dumps(build_payload(user_agent), separators=(",", ":")).encode()
    checksum = f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}".upper()
    return checksum, encrypt(checksum.encode("ascii") + b"#" + payload)


def build_metrics() -> list[dict[str, Any]]:
    """Build the timing metrics challenge.js reports alongside the solution.

    Returns:
        list[dict[str, Any]]: The metrics entries.
    """

    def metric(name: str, value: float, unit: str = "2") -> dict[str, Any]:
        return {"name": name, "value": value, "unit": unit}

    rand = random.uniform
    return [
        metric("2", rand(0, 1)),
        metric("100", 0),
        metric("101", 0),
        metric("102", 0),
        metric("103", 8),
        metric("104", 0),
        metric("105", 0),
        metric("106", 0),
        metric("107", 0),
        metric("108", 1),
        metric("undefined", 0),
        metric("110", 0),
        metric("111", 2),
        metric("112", 0),
        metric("undefined", 0),
        metric("3", 4),
        metric("7", 0, "4"),
        metric("1", rand(10, 20)),
        metric("4", 36.5),
        metric("5", rand(0, 1)),
        metric("6", rand(50, 60)),
        metric("0", rand(130, 140)),
        metric("8", 1, "4"),
    ]


__all__ = (
    "FP_KEY",
    "GPUS",
    "GPU_EXTENSIONS",
    "USER_AGENT",
    "build",
    "build_metrics",
    "build_payload",
    "decrypt",
    "encrypt",
)
