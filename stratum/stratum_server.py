#!/usr/bin/env python3
"""
Caps Stratum v1 Mining Server
Asyncio-based Stratum server for SHA-256d mining on the Caps network.
Supports Nerdminer, cgminer, and other Stratum v1 compatible miners.
"""

import asyncio
import concurrent.futures
import hashlib
import json
import logging
import os
import sqlite3
import struct
import sys
import time
import urllib.request
import binascii
from collections import OrderedDict
from http import HTTPStatus

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("stratum")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


def validate_settings(data: dict) -> list:
    """Validate settings dict. Returns list of error strings (empty = valid)."""
    errors = []
    for field in ("rpc_host", "rpc_port", "rpc_user", "payout_address"):
        if not data.get(field):
            errors.append(f"Missing required field: {field}")
    for port_field in ("rpc_port", "stratum_port", "dashboard_port"):
        v = data.get(port_field)
        if v is not None:
            try:
                iv = int(v)
                if iv < 1 or iv > 65535:
                    errors.append(f"{port_field} must be 1-65535")
            except (ValueError, TypeError):
                errors.append(f"{port_field} must be an integer")
    for vb in ("p2pkh_version", "p2sh_version"):
        v = data.get(vb)
        if v is not None:
            try:
                iv = int(v)
                if iv < 0 or iv > 255:
                    errors.append(f"{vb} must be 0-255")
            except (ValueError, TypeError):
                errors.append(f"{vb} must be an integer")
    for pos_field in ("difficulty", "poll_interval"):
        v = data.get(pos_field)
        if v is not None:
            try:
                fv = float(v)
                if fv <= 0:
                    errors.append(f"{pos_field} must be a positive number")
            except (ValueError, TypeError):
                errors.append(f"{pos_field} must be a number")
    return errors


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def uint256_from_bytes_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def swap32(hex_str: str) -> str:
    """Swap every 4 bytes (8 hex chars) in the string."""
    return "".join(
        hex_str[i + 6 : i + 8]
        + hex_str[i + 4 : i + 6]
        + hex_str[i + 2 : i + 4]
        + hex_str[i : i + 2]
        for i in range(0, len(hex_str), 8)
    )


def int_to_varint(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def script_number(n: int) -> bytes:
    """Encode a number for use in coinbase script (BIP34-style height).

    Uses CScriptNum serialization: for values 1-16 this could use OP_N,
    but BIP34 specifies the serialized CScriptNum format (length + LE bytes).
    However, Bitcoin Core's generatetoaddress uses OP_N for small values,
    so we match that behavior for compatibility.
    """
    if n == 0:
        return b"\x00"  # OP_0
    if 1 <= n <= 16:
        return bytes([0x50 + n])  # OP_1 through OP_16
    # For larger values, use length-prefixed little-endian encoding
    negative = n < 0
    absvalue = abs(n)
    result = bytearray()
    while absvalue:
        result.append(absvalue & 0xFF)
        absvalue >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes([len(result)]) + bytes(result)


def address_to_script(address: str, bech32_hrp: str = "caps",
                      p2pkh_version: int = 0x1C, p2sh_version: int = 0x1D) -> bytes:
    """Convert an address to its output script (P2PKH, P2SH, bech32, or CashAddr)."""
    # Try bech32 first
    bech32_prefix = bech32_hrp + "1"
    if bech32_hrp and address.lower().startswith(bech32_prefix):
        hrp, data = bech32_decode(address)
        if data is not None:
            witness_ver = data[0]
            witness_prog = bytes(bech32_convert_bits(data[1:], 5, 8, False))
            if witness_ver == 0 and len(witness_prog) == 20:
                return bytes([0x00, 0x14]) + witness_prog
            elif witness_ver == 0 and len(witness_prog) == 32:
                return bytes([0x00, 0x20]) + witness_prog
            elif witness_ver == 1 and len(witness_prog) == 32:
                return bytes([0x51, 0x20]) + witness_prog

    # Try CashAddr (Bitcoin Cash: "bitcoincash:q..." or bare "q..."/"p...")
    lower = address.lower()
    if lower.startswith("bitcoincash:") or lower.startswith("bchtest:"):
        result = cashaddr_decode(address)
        if result is not None:
            prefix, addr_type, hash_bytes = result
            if addr_type == 0:  # P2PKH
                return bytes([0x76, 0xA9, 0x14]) + hash_bytes + bytes([0x88, 0xAC])
            elif addr_type == 1:  # P2SH
                return bytes([0xA9, 0x14]) + hash_bytes + bytes([0x87])

    # Base58Check decode
    raw = base58_decode_check(address)
    if raw is None:
        # Last resort: try CashAddr without prefix (bare "q..."/"p..." form)
        result = cashaddr_decode(address)
        if result is not None:
            prefix, addr_type, hash_bytes = result
            if addr_type == 0:
                return bytes([0x76, 0xA9, 0x14]) + hash_bytes + bytes([0x88, 0xAC])
            elif addr_type == 1:
                return bytes([0xA9, 0x14]) + hash_bytes + bytes([0x87])
        raise ValueError(f"Cannot decode address: {address}")

    version = raw[0]
    payload = raw[1:]
    if version == p2pkh_version:
        return bytes([0x76, 0xA9, 0x14]) + payload + bytes([0x88, 0xAC])
    elif version == p2sh_version:
        return bytes([0xA9, 0x14]) + payload + bytes([0x87])
    else:
        raise ValueError(f"Unknown address version: {version}")


# ---------------------------------------------------------------------------
# Base58 helpers
# ---------------------------------------------------------------------------
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode_check(s: str) -> bytes:
    """Decode a Base58Check-encoded string."""
    result = 0
    for c in s.encode("ascii"):
        result = result * 58 + B58_ALPHABET.index(c)
    # Convert to bytes
    byte_length = (result.bit_length() + 7) // 8
    raw = result.to_bytes(byte_length, "big") if byte_length > 0 else b""
    # Restore leading zeros
    pad = 0
    for c in s.encode("ascii"):
        if c == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    raw = b"\x00" * pad + raw
    # Verify checksum
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        return None
    return payload


# ---------------------------------------------------------------------------
# Bech32 helpers (BIP173/BIP350)
# ---------------------------------------------------------------------------
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_decode(bech):
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None)
    bech_lower = bech.lower()
    pos = bech_lower.rfind("1")
    if pos < 1 or pos + 7 > len(bech_lower):
        return (None, None)
    hrp = bech_lower[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech_lower[pos + 1 :]]
    if -1 in data:
        return (None, None)
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])


def bech32_convert_bits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


# ---------------------------------------------------------------------------
# CashAddr helpers (Bitcoin Cash address format)
# ---------------------------------------------------------------------------
CASHADDR_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CASHADDR_PREFIX = "bitcoincash"


def _cashaddr_polymod(values):
    gen = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]
    chk = 1
    for v in values:
        b = chk >> 35
        chk = ((chk & 0x07FFFFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk ^ 1


def _cashaddr_prefix_expand(prefix):
    return [ord(c) & 0x1F for c in prefix] + [0]


def cashaddr_decode(address: str):
    """Decode a CashAddr address. Returns (prefix, version_byte, payload_hash) or None.

    Accepts both 'bitcoincash:qr...' and bare 'qr...' forms.
    version_byte: 0 = P2PKH, 1 = P2SH (8 = P2SH in raw encoding, mapped to 1).
    """
    addr_lower = address.lower()
    if ":" in addr_lower:
        prefix, payload_str = addr_lower.split(":", 1)
    else:
        prefix = CASHADDR_PREFIX
        payload_str = addr_lower

    # Decode base32
    data5 = []
    for c in payload_str:
        idx = CASHADDR_CHARSET.find(c)
        if idx == -1:
            return None
        data5.append(idx)

    # Verify checksum (8 x 5-bit words = 40-bit checksum)
    if len(data5) < 9:
        return None
    prefix_exp = _cashaddr_prefix_expand(prefix)
    if _cashaddr_polymod(prefix_exp + data5) != 0:
        return None

    # Strip checksum (last 8 groups)
    data5 = data5[:-8]

    # Convert from 5-bit to 8-bit
    data8 = bech32_convert_bits(data5, 5, 8, False)
    if data8 is None or len(data8) < 1:
        return None

    # First byte encodes type (high 4 bits) and size (low 4 bits)
    version_byte = data8[0]
    addr_type = (version_byte >> 3) & 0x1F  # 0 = P2PKH, 1 = P2SH
    hash_bytes = bytes(data8[1:])

    if len(hash_bytes) != 20:
        return None

    return (prefix, addr_type, hash_bytes)


# ---------------------------------------------------------------------------
# RPC client
# ---------------------------------------------------------------------------
class RPCClient:
    def __init__(self, host, port, user, password):
        self.url = f"http://{host}:{port}"
        self.auth = (
            "Basic "
            + binascii.b2a_base64(f"{user}:{password}".encode()).decode().strip()
        )
        self._id = 0
        # Dedicated thread pool so RPC calls don't starve the default executor
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="rpc")

    def _call_sync(self, method, params=None):
        """Synchronous RPC call (runs in thread pool to avoid blocking event loop)."""
        self._id += 1
        payload = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": self._id,
                "method": method,
                "params": params or [],
            }
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("error"):
                    log.error("RPC error: %s", data["error"])
                    return None
                return data.get("result")
        except Exception as e:
            log.error("RPC call %s failed: %s", method, e)
            return None

    async def acall(self, method, params=None):
        """Async wrapper — runs the blocking HTTP call in a dedicated thread
        pool so the asyncio event loop stays responsive for miner I/O."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._call_sync, method, params)

    def call(self, method, params=None):
        """Blocking call for use outside the event loop (startup checks)."""
        return self._call_sync(method, params)


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------
def build_merkle_branches(tx_hashes: list) -> list:
    """Build merkle branches (excluding coinbase) for stratum mining.notify."""
    branches = []
    hashes = list(tx_hashes)
    while len(hashes) > 1:
        branches.append(hashes[0])
        new = []
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        for i in range(0, len(hashes), 2):
            new.append(sha256d(hashes[i] + hashes[i + 1]))
        hashes = new
    if hashes:
        branches.append(hashes[0])
    return branches


def compute_merkle_root(coinbase_hash: bytes, branches: list) -> bytes:
    """Compute the merkle root from coinbase hash and branches."""
    current = coinbase_hash
    for branch in branches:
        current = sha256d(current + branch)
    return current


def build_merkle_from_txids(coinbase_hash: bytes, tx_hashes: list) -> bytes:
    """Build full merkle root from coinbase + all transaction hashes."""
    hashes = [coinbase_hash] + tx_hashes
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        new = []
        for i in range(0, len(hashes), 2):
            new.append(sha256d(hashes[i] + hashes[i + 1]))
        hashes = new
    return hashes[0]


# ---------------------------------------------------------------------------
# Job (block template + coinbase construction)
# ---------------------------------------------------------------------------
class Job:
    _counter = 0

    def __init__(self, template: dict, payout_script: bytes, extranonce1_size: int,
                 coinbase_message: str = "/Caps Stratum Pool/"):
        Job._counter += 1
        self.job_id = format(Job._counter, "x")
        self.template = template
        self.height = template["height"]
        self.version = template["version"]
        self.prev_hash = template["previousblockhash"]
        self.bits = template["bits"]
        self.curtime = template["curtime"]
        self.target = template["target"]
        self.coinbasevalue = template["coinbasevalue"]
        self.transactions = template.get("transactions", [])
        self.payout_script = payout_script
        self.extranonce1_size = extranonce1_size
        self.extranonce2_size = 4
        self._coinbase_message = coinbase_message

        # Build coinbase halves
        self._build_coinbase()

        # Build merkle branches from transaction data
        self.tx_hashes = [
            bytes.fromhex(tx["txid"])[::-1] for tx in self.transactions
        ]
        self.merkle_branches = self._build_branches()

    def _build_coinbase(self):
        """Construct coinbase1 and coinbase2 with extranonce placeholder."""
        # Coinbase input script: height (BIP34) + arbitrary data
        height_script = script_number(self.height)
        coinbase_message = self._coinbase_message.encode("utf-8")
        script_sig = height_script + coinbase_message

        # We split the coinbase tx so the extranonce goes between coinbase1 and coinbase2.
        # coinbase1 = version + txin_count + prev_hash + prev_index + scriptSig_len(partial) + scriptSig(before extranonce)
        # [extranonce1 + extranonce2 goes here]
        # coinbase2 = remaining scriptSig + sequence + txout_count + txout + locktime

        total_extranonce_size = self.extranonce1_size + self.extranonce2_size
        full_script_len = len(script_sig) + total_extranonce_size

        witness_commitment = self.template.get("default_witness_commitment", "")

        # --- coinbase1 / coinbase2: NON-WITNESS serialization ---
        # This is what the miner hashes to produce the TXID for the merkle root.
        cb1 = bytearray()
        # Version (4 bytes LE)
        cb1 += struct.pack("<I", 2)
        # NO segwit marker/flag here
        # Input count
        cb1 += b"\x01"
        # Previous output (null)
        cb1 += b"\x00" * 32
        cb1 += struct.pack("<I", 0xFFFFFFFF)
        # Script length
        cb1 += int_to_varint(full_script_len)
        # Script before extranonce
        cb1 += script_sig

        self.coinbase1 = bytes(cb1)

        # coinbase2: sequence + outputs + locktime (NO witness)
        cb2 = bytearray()
        # Sequence
        cb2 += struct.pack("<I", 0xFFFFFFFF)
        # Output count
        if witness_commitment:
            cb2 += b"\x02"  # 2 outputs
        else:
            cb2 += b"\x01"  # 1 output

        # Output 1: block reward to pool address
        cb2 += struct.pack("<Q", self.coinbasevalue)
        cb2 += int_to_varint(len(self.payout_script))
        cb2 += self.payout_script

        # Output 2: witness commitment (if segwit)
        if witness_commitment:
            witness_script = bytes.fromhex(witness_commitment)
            cb2 += struct.pack("<Q", 0)  # 0 value
            cb2 += int_to_varint(len(witness_script))
            cb2 += witness_script

        # Locktime (NO witness stack here - this is the non-witness serialization)
        cb2 += struct.pack("<I", 0)

        self.coinbase2 = bytes(cb2)

        # --- Store witness commitment flag so we can build the full witness
        #     serialization at block-submit time ---
        self.has_witness = bool(witness_commitment)

    def _build_branches(self) -> list:
        """Compute merkle branches from transaction hashes (excluding coinbase)."""
        branches = []
        hashes = list(self.tx_hashes)
        while len(hashes) > 0:
            branches.append(hashes.pop(0).hex())
            if not hashes:
                break
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            new = []
            for i in range(0, len(hashes), 2):
                new.append(sha256d(hashes[i] + hashes[i + 1]))
            hashes = new
        return branches

    def get_notify_params(self, clean_jobs=True):
        """Return parameters for mining.notify."""
        # prevhash from getblocktemplate is in RPC display order (big-endian).
        # For stratum we need: internal byte order (LE) with each 4-byte word
        # byte-swapped.  The miner will swap each word back to reconstruct
        # the correct header bytes.
        prev_hash_internal = bytes.fromhex(self.prev_hash)[::-1]  # BE→LE
        prev_hash_hex = swap32(prev_hash_internal.hex())  # swap 4-byte words
        return [
            self.job_id,
            prev_hash_hex,
            self.coinbase1.hex(),
            self.coinbase2.hex(),
            self.merkle_branches,
            format(self.version, "08x"),
            self.bits,
            format(self.curtime, "08x"),
            clean_jobs,
        ]

    def build_block_header(self, extranonce1: bytes, extranonce2: bytes, ntime_hex: str, nonce_hex: str) -> bytes:
        """Reconstruct the full block header from miner-submitted parameters.

        ntime_hex: big-endian hex from miner (same format as mining.notify)
        nonce_hex: raw LE header bytes as hex (NerdMiner/cgminer convention)
        """
        # coinbase1/coinbase2 are already non-witness, so this hash IS the TXID
        coinbase_txid = sha256d(self.coinbase1 + extranonce1 + extranonce2 + self.coinbase2)

        # Compute merkle root
        merkle_root = build_merkle_from_txids(coinbase_txid, self.tx_hashes)

        # Build 80-byte header
        # prev_hash: swap32 format (same as sent to miner via mining.notify)
        # ntime: BE hex -> reverse to LE bytes
        # nbits: BE hex -> reverse to LE bytes
        # nonce: raw LE bytes from miner (bytes.fromhex directly)
        header = bytearray()
        header += struct.pack("<I", self.version)
        header += bytes.fromhex(self.prev_hash)[::-1]  # RPC display (BE) → internal (LE)
        header += merkle_root
        header += bytes.fromhex(ntime_hex)[::-1]
        header += bytes.fromhex(self.bits)[::-1]
        header += bytes.fromhex(nonce_hex)
        return bytes(header)

    def _build_witness_coinbase(self, extranonce1: bytes, extranonce2: bytes) -> bytes:
        """Build the full witness-serialized coinbase for block submission."""
        if not self.has_witness:
            # No witness needed, just return the non-witness coinbase
            return self.coinbase1 + extranonce1 + extranonce2 + self.coinbase2

        # Reconstruct with segwit marker/flag and witness stack
        non_witness = self.coinbase1 + extranonce1 + extranonce2 + self.coinbase2
        # non_witness = version(4) + vin_count(1) + ... + outputs + locktime(4)
        version = non_witness[:4]
        body = non_witness[4:-4]  # everything between version and locktime
        locktime = non_witness[-4:]

        # Witness stack: 1 item, 32 zero bytes
        witness = b"\x01\x20" + b"\x00" * 32

        return version + b"\x00\x01" + body + witness + locktime

    def build_submit_block(self, extranonce1: bytes, extranonce2: bytes, ntime_hex: str, nonce_hex: str) -> str:
        """Build the full serialized block hex for submitblock RPC."""
        # Block header
        header = self.build_block_header(extranonce1, extranonce2, ntime_hex, nonce_hex)

        # Full witness coinbase for the actual block
        coinbase_witness = self._build_witness_coinbase(extranonce1, extranonce2)

        # Serialize block
        block = bytearray(header)
        # Transaction count (coinbase + others)
        block += int_to_varint(1 + len(self.transactions))
        # Coinbase tx (with witness)
        block += coinbase_witness
        # Other transactions
        for tx in self.transactions:
            block += bytes.fromhex(tx["data"])

        return block.hex()

    def build_block_header_raw(self, extranonce1: bytes, extranonce2: bytes, ntime_bytes: bytes, nonce_bytes: bytes, version_override: int = None) -> bytes:
        """Reconstruct the 80-byte block header using raw bytes for ntime and nonce.

        ntime_bytes and nonce_bytes are placed directly into the header (4 bytes each, LE).
        The caller is responsible for choosing the correct byte order.
        version_override: if set, use this version instead of the template version
                          (needed for BIP 310 version rolling).
        """
        coinbase_txid = sha256d(self.coinbase1 + extranonce1 + extranonce2 + self.coinbase2)
        merkle_root = build_merkle_from_txids(coinbase_txid, self.tx_hashes)

        ver = version_override if version_override is not None else self.version
        header = bytearray()
        header += struct.pack("<I", ver)
        header += bytes.fromhex(self.prev_hash)[::-1]  # RPC display (BE) → internal (LE)
        header += merkle_root
        header += ntime_bytes
        header += bytes.fromhex(self.bits)[::-1]
        header += nonce_bytes
        return bytes(header)

    def build_submit_block_raw(self, extranonce1: bytes, extranonce2: bytes, ntime_bytes: bytes, nonce_bytes: bytes, version_override: int = None) -> str:
        """Build the full serialized block hex using raw ntime/nonce bytes."""
        header = self.build_block_header_raw(extranonce1, extranonce2, ntime_bytes, nonce_bytes, version_override=version_override)

        coinbase_witness = self._build_witness_coinbase(extranonce1, extranonce2)

        block = bytearray(header)
        block += int_to_varint(1 + len(self.transactions))
        block += coinbase_witness
        for tx in self.transactions:
            block += bytes.fromhex(tx["data"])

        return block.hex()


# ---------------------------------------------------------------------------
# Miner session
# ---------------------------------------------------------------------------
class MinerSession:
    _extranonce_counter = 0

    def __init__(self, reader, writer, server):
        MinerSession._extranonce_counter += 1
        self.reader = reader
        self.writer = writer
        self.server = server
        self.extranonce1 = struct.pack(">I", MinerSession._extranonce_counter)
        self.extranonce2_size = 4
        self.subscribed = False
        self.authorized = False
        self.worker_name = "unknown"
        self.difficulty = server.default_difficulty
        self.version_rolling_mask = 0  # BIP 310: no version rolling by default
        self.user_agent = "unknown"
        self.addr = writer.get_extra_info("peername")
        self._msg_id = 0
        self._write_lock = asyncio.Lock()  # prevent concurrent writes to same socket
        self._task = None  # set by handle_client after task creation
        self.connected_at = time.time()
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.last_share_time = None
        self.vardiff_share_times = []      # timestamps of recent shares for rate calculation
        self.vardiff_last_retarget = time.time()
        self.vardiff_frozen_until = 0      # if miner used suggest_difficulty, freeze vardiff temporarily
        self.prev_difficulty = None        # previous diff for grace period after retarget
        self.diff_change_time = 0          # when difficulty last changed
        self._suggested_difficulty = None  # buffered suggest_difficulty before subscribe

    @staticmethod
    def _extract_json_objects(line: str) -> list:
        """Try to extract one or more JSON objects from a line.

        The NerdMiner sometimes sends concatenated JSON without a newline
        separator (e.g.  '{"id":1,...}{"id":2,...}') or pads messages with
        NUL bytes / spaces.  This helper splits on '}{' boundaries and
        tries to parse each piece individually.
        """
        # Strip NUL bytes and non-printable chars the NerdMiner sometimes sends
        line = line.replace("\x00", "").strip()
        if not line:
            return []

        # Fast path: single valid JSON object
        try:
            return [json.loads(line)]
        except json.JSONDecodeError:
            pass

        # Try splitting on '}{' (concatenated objects)
        parts = line.replace("}{", "}\n{").split("\n")
        results = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            try:
                results.append(json.loads(part))
            except json.JSONDecodeError:
                pass
        return results

    async def handle(self):
        peer = f"{self.addr[0]}:{self.addr[1]}" if self.addr else "unknown"
        log.info("Miner connected: %s", peer)
        try:
            buffer = ""
            while True:
                try:
                    data = await asyncio.wait_for(self.reader.read(4096), timeout=300)
                except asyncio.TimeoutError:
                    log.info("Miner %s read timeout (300s idle), disconnecting", self.worker_name)
                    break
                if not data:
                    break
                # Strip NUL bytes from raw data before decoding
                raw = data.replace(b"\x00", b"")
                buffer += raw.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    for msg in self._extract_json_objects(line):
                        await self.handle_message(msg)
        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception as e:
            log.error("Error handling miner %s: %s", peer, e)
        finally:
            log.info("Miner disconnected: %s [%s]", peer, self.worker_name)
            self.server.remove_miner(self)

    async def handle_message(self, msg):
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", [])

        if method == "mining.configure":
            await self.handle_configure(msg_id, params)
        elif method == "mining.subscribe":
            await self.handle_subscribe(msg_id, params)
        elif method == "mining.authorize":
            await self.handle_authorize(msg_id, params)
        elif method == "mining.submit":
            await self.handle_submit(msg_id, params)
        elif method == "mining.extranonce.subscribe":
            await self.send_result(msg_id, True)
        elif method == "mining.suggest_difficulty":
            await self.handle_suggest_difficulty(msg_id, params)
        else:
            log.debug("Unknown method from %s: %s", self.worker_name, method)
            if msg_id is not None:
                await self.send_result(msg_id, None, [20, "Unknown method", None])

    async def handle_configure(self, msg_id, params):
        """Handle mining.configure (BIP 310) — negotiate extensions like version rolling."""
        extensions = params[0] if len(params) > 0 else []
        ext_params = params[1] if len(params) > 1 else {}
        result = {}

        for ext in extensions:
            if ext == "version-rolling":
                # Accept version rolling — intersect miner's requested mask
                # with the server-allowed mask (BIP 310 compliance).
                mask = ext_params.get("version-rolling.mask", "1fffe000")
                miner_mask = int(mask, 16)
                effective_mask = miner_mask & self.server.allowed_version_mask
                self.version_rolling_mask = effective_mask
                result["version-rolling"] = True
                result["version-rolling.mask"] = f"{effective_mask:08x}"
                log.info("Version rolling enabled for %s (requested: %s, effective: %08x)",
                         self.addr, mask, effective_mask)
            elif ext == "minimum-difficulty":
                min_diff = ext_params.get("minimum-difficulty.value", 1)
                result["minimum-difficulty"] = True
                log.info("Minimum difficulty %s for %s", min_diff, self.addr)
            else:
                result[ext] = False

        await self.send_result(msg_id, result)

    def _pick_difficulty(self, user_agent: str) -> float:
        """Choose an appropriate share difficulty based on miner type."""
        agent_lower = user_agent.lower()
        # NerdMiner / low-power devices: very low difficulty
        if "nmminer" in agent_lower or "nerdminer" in agent_lower:
            return self.server.default_difficulty
        # ASIC miners: higher difficulty for ~1 share every few seconds
        # 256 difficulty → ~1 share/sec at 1 TH/s, ~1 share/5s at 200 GH/s
        if "bitdsk" in agent_lower or "antminer" in agent_lower or "whatsminer" in agent_lower:
            return 256
        # Unknown miners: moderate difficulty
        return max(self.server.default_difficulty, 1)

    async def handle_subscribe(self, msg_id, params):
        if self.subscribed:
            # Already subscribed on this connection — ignore duplicate
            await self.send_result(msg_id, [
                [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                self.extranonce1.hex(),
                self.extranonce2_size,
            ])
            return
        self.subscribed = True
        self.user_agent = params[0] if params else "unknown"
        log.info("Miner subscribed: %s (agent: %s)", self.addr, self.user_agent)

        # Use buffered suggest_difficulty if the miner sent it before subscribe,
        # otherwise pick based on user agent.
        if self._suggested_difficulty is not None:
            self.difficulty = self._suggested_difficulty
            self.vardiff_frozen_until = time.time() + 300
            self._suggested_difficulty = None
            log.info("Using suggested difficulty %s for %s", self.difficulty, self.user_agent)
        else:
            self.difficulty = self._pick_difficulty(self.user_agent)
            log.info("Setting difficulty %s for %s", self.difficulty, self.user_agent)

        result = [
            [
                ["mining.set_difficulty", "1"],
                ["mining.notify", "1"],
            ],
            self.extranonce1.hex(),
            self.extranonce2_size,
        ]
        await self.send_result(msg_id, result)

        # Send difficulty and initial work immediately so the miner has
        # something to work on even if its authorize message gets lost.
        await self.send_method("mining.set_difficulty", [self.difficulty])
        if self.server.current_job:
            notify_params = self.server.current_job.get_notify_params(clean_jobs=True)
            await self.send_method("mining.notify", notify_params)

    async def handle_suggest_difficulty(self, msg_id, params):
        """Honor the miner's suggested difficulty, clamped to vardiff bounds."""
        if params and isinstance(params[0], (int, float)) and params[0] > 0:
            cfg = self.server.vardiff_config
            suggested = max(cfg["min_diff"], min(cfg["max_diff"], params[0]))
            if not self.subscribed:
                # Buffer it — will be applied in handle_subscribe.
                # Don't send set_difficulty before subscribe or NerdMiners hang.
                self._suggested_difficulty = suggested
                log.info("Miner %s buffered suggest_difficulty %s (pre-subscribe)",
                         self.worker_name, suggested)
                return
            self.prev_difficulty = self.difficulty
            self.diff_change_time = time.time()
            self.difficulty = suggested
            self.vardiff_frozen_until = time.time() + 300  # freeze vardiff for 5 min
            log.info("Miner %s suggested difficulty %s, accepted (vardiff frozen 5m)",
                     self.worker_name, suggested)
            await self.send_method("mining.set_difficulty", [self.difficulty])

    async def handle_authorize(self, msg_id, params):
        self.worker_name = params[0] if params else "unknown"
        self.authorized = True
        log.info("Miner authorized: %s", self.worker_name)
        await self.send_result(msg_id, True)

    def _maybe_retarget(self):
        """Check if difficulty needs adjusting based on share rate.

        Returns the new difficulty if changed, or None if no change needed.
        """
        cfg = self.server.vardiff_config
        now = time.time()

        # Don't retarget if frozen (miner used suggest_difficulty)
        if now < self.vardiff_frozen_until:
            return None

        # Don't retarget too frequently
        elapsed = now - self.vardiff_last_retarget
        if elapsed < cfg["retarget_interval"]:
            return None

        # Calculate actual shares/min over the retarget window
        cutoff = now - elapsed
        recent = [t for t in self.vardiff_share_times if t > cutoff]
        if not recent:
            return None

        shares_per_min = len(recent) / (elapsed / 60)
        target_spm = cfg["target_shares_per_min"]

        # Within tolerance band — no change needed
        if abs(shares_per_min - target_spm) / target_spm < cfg["tolerance"]:
            return None

        # Proportional adjustment, capped at 4x change per retarget
        ratio = shares_per_min / target_spm
        ratio = max(0.25, min(4.0, ratio))
        new_diff = self.difficulty * ratio

        # Clamp to bounds
        new_diff = max(cfg["min_diff"], min(cfg["max_diff"], new_diff))

        # Apply — keep previous diff for grace period
        self.prev_difficulty = self.difficulty
        self.diff_change_time = now
        self.difficulty = new_diff
        self.vardiff_last_retarget = now
        self.vardiff_share_times.clear()
        return new_diff  # caller sends mining.set_difficulty

    async def handle_submit(self, msg_id, params):
        """Handle mining.submit.

        Standard:        [worker, job_id, extranonce2, ntime, nonce]
        Version-rolling: [worker, job_id, extranonce2, ntime, nonce, version]
        """
        if not self.authorized:
            await self.send_result(msg_id, None, [24, "Unauthorized worker", None])
            return

        if len(params) < 5:
            await self.send_result(msg_id, None, [20, "Invalid parameters", None])
            return

        worker_name, job_id, extranonce2_hex, ntime_hex, nonce_hex = params[:5]

        # 6th param = rolled version bits (BIP 310)
        version_hex = params[5] if len(params) >= 6 else None

        # Find the job
        job = self.server.find_job(job_id)
        if job is None:
            await self.send_result(msg_id, None, [21, "Job not found (stale)", None])
            log.debug("Stale share from %s: job %s not found", self.worker_name, job_id)
            return

        # Skip validation if we already found a block for this job
        if getattr(job, 'block_found', False):
            self.server.stats["accepted"] += 1
            self.shares_accepted += 1
            self.last_share_time = time.time()
            self.server.share_log.append((time.time(), self.difficulty))
            await self.send_result(msg_id, True)
            return

        try:
            extranonce2 = bytes.fromhex(extranonce2_hex)
            bytes.fromhex(ntime_hex)
            bytes.fromhex(nonce_hex)
        except (ValueError, TypeError) as e:
            await self.send_result(msg_id, None, [20, f"Bad params: {e}", None])
            return

        # Determine the block version to use in the header.
        # For version-rolling miners, the 6th param contains the rolled bits.
        # The actual version used in the header = base_version XOR rolled_bits.
        if version_hex:
            rolled_bits = int(version_hex, 16)
            # Validate that rolled bits fall within the negotiated mask
            if rolled_bits & ~self.version_rolling_mask:
                self.server.stats["rejected"] += 1
                self.shares_rejected += 1
                await self.send_result(msg_id, None, [20, "Version rolling outside mask", None])
                log.warning("Rejected share from %s: rolled bits %08x outside mask %08x",
                            self.worker_name, rolled_bits, self.version_rolling_mask)
                return
            header_version = job.version ^ rolled_bits
        else:
            header_version = job.version

        # Build header BEFORE accepting — validate the share meets difficulty
        ntime_bytes = bytes.fromhex(ntime_hex)[::-1]
        nonce_bytes = bytes.fromhex(nonce_hex)[::-1]

        try:
            header = job.build_block_header_raw(
                self.extranonce1, extranonce2,
                ntime_bytes, nonce_bytes,
                version_override=header_version
            )
            header_hash = sha256d(header)
            hash_int = uint256_from_bytes_le(header_hash)
        except Exception as e:
            log.error("Header build error from %s: %s", self.worker_name, e)
            await self.send_result(msg_id, None, [20, "Internal error", None])
            return

        # Check share meets the miner's difficulty target.
        # After a difficulty change, allow a 10s grace period where we also
        # accept shares at the previous (typically lower) difficulty — the
        # miner may have been working on those before it received the update.
        share_target = self.server.diff_to_target(self.difficulty)
        share_ok = hash_int <= share_target
        if not share_ok and self.prev_difficulty is not None:
            grace = time.time() - self.diff_change_time
            if grace < 10:
                prev_target = self.server.diff_to_target(self.prev_difficulty)
                share_ok = hash_int <= prev_target
        if not share_ok:
            self.server.stats["rejected"] += 1
            self.shares_rejected += 1
            await self.send_result(msg_id, None, [23, "Low difficulty share", None])
            log.debug("Low difficulty share from %s (diff=%.6f)", self.worker_name, self.difficulty)
            return

        # --- Share is valid — accept it ---
        now = time.time()
        self.server.stats["accepted"] += 1
        self.shares_accepted += 1
        self.last_share_time = now
        self.vardiff_share_times.append(now)
        self.server.share_log.append((now, self.difficulty))
        await self.send_result(msg_id, True)

        # Persist share to DB (fire-and-forget)
        asyncio.ensure_future(self.server.db.record_share(
            now, self.worker_name, self.difficulty, job.height
        ))

        # Vardiff: check if we should retarget this miner's difficulty
        new_diff = self._maybe_retarget()
        if new_diff is not None:
            await self.send_method("mining.set_difficulty", [new_diff])
            log.info("Vardiff: %s -> %.6f", self.worker_name, new_diff)

        # Check if share also meets the network target (block found!)
        try:
            network_target = int(job.target, 16)

            if hash_int <= network_target:
                log.info("*** BLOCK FOUND by %s! height=%d ***",
                         self.worker_name, job.height)
                log.info("Block hash: %s", header_hash[::-1].hex())

                # Mark job so we don't submit duplicates
                job.block_found = True

                block_hex = job.build_submit_block_raw(
                    self.extranonce1, extranonce2,
                    ntime_bytes, nonce_bytes,
                    version_override=header_version
                )
                log.debug("Submitting block hex (len=%d): %s", len(block_hex), block_hex)
                log.debug("extranonce1=%s extranonce2=%s ntime=%s nonce=%s",
                          self.extranonce1.hex(), extranonce2.hex(),
                          ntime_bytes.hex(), nonce_bytes.hex())
                log.info("Submitting block to node...")
                result = await self.server.rpc.acall("submitblock", [block_hex])
                log.info("submitblock returned: %r", result)
                if result is None or result == "":
                    log.info("Block submitted successfully! height=%d", job.height)
                    self.server.stats["blocks"] += 1
                    block_time = time.time()
                    block_hash_hex = header_hash[::-1].hex()
                    self.server.recent_blocks.append({
                        "height": job.height,
                        "hash": block_hash_hex,
                        "time": block_time,
                        "worker": self.worker_name,
                    })
                    if len(self.server.recent_blocks) > 20:
                        self.server.recent_blocks = self.server.recent_blocks[-20:]
                    # Persist block and updated stats to DB
                    asyncio.ensure_future(self.server.db.record_block(
                        job.height, block_hash_hex, self.worker_name, block_time
                    ))
                    asyncio.ensure_future(self.server.db.save_pool_stats(
                        self.server.stats["accepted"],
                        self.server.stats["rejected"],
                        self.server.stats["blocks"],
                    ))
                else:
                    log.error("Block rejected by node: %s", result)

                # Immediately refresh the template for the next block
                log.info("Scheduling update_job after block found")
                asyncio.ensure_future(self.server.update_job())
                log.info("handle_submit block-found path complete")
        except Exception as e:
            log.error("Block check error: %s", e, exc_info=True)

    async def send_result(self, msg_id, result, error=None):
        msg = {"id": msg_id, "result": result, "error": error}
        await self._send(msg)

    async def send_method(self, method, params):
        msg = {"id": None, "method": method, "params": params}
        await self._send(msg)

    async def _send(self, msg):
        try:
            async with self._write_lock:
                data = json.dumps(msg) + "\n"
                self.writer.write(data.encode())
                await asyncio.wait_for(self.writer.drain(), timeout=5)
        except (ConnectionError, OSError):
            pass
        except asyncio.TimeoutError:
            log.debug("Send timeout to %s, aborting connection", self.worker_name)
            try:
                self.writer.transport.abort()
            except Exception:
                pass
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Dashboard HTML (Vault-Tec / Pip-Boy theme)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>C.A.P.S. S.M.S.D. - Vault-Tec Mining Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
:root {
  --pip-green: #14fe17;
  --pip-green-dim: #0a8f0c;
  --pip-green-dark: #063f07;
  --pip-bg: #0b0c0a;
  --pip-panel: rgba(20, 254, 23, 0.05);
  --pip-border: rgba(20, 254, 23, 0.3);
  --pip-glow: 0 0 10px rgba(20, 254, 23, 0.3);
  --pip-scanline: rgba(20, 254, 23, 0.03);
  --pip-amber: #ffc107;
  --pip-red: #ff3d3d;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background:
    repeating-linear-gradient(
      0deg,
      transparent,
      transparent 3px,
      var(--pip-scanline) 3px,
      var(--pip-scanline) 4px
    ),
    var(--pip-bg);
  color: var(--pip-green);
  font-family: 'Share Tech Mono', monospace;
  min-height: 100vh;
  overflow-x: hidden;
}

/* CRT scanline effect */
body::after {
  content: '';
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.12) 2px,
    rgba(0, 0, 0, 0.12) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* CRT vignette */
body::before {
  content: '';
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.6) 100%);
  pointer-events: none;
  z-index: 9998;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

/* Header */
.header {
  text-align: center;
  padding: 30px 20px 20px;
  border-bottom: 2px solid var(--pip-border);
  margin-bottom: 25px;
  position: relative;
}

.header::before {
  content: 'VAULT-TEC INDUSTRIES';
  display: block;
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  letter-spacing: 6px;
  color: var(--pip-green-dim);
  margin-bottom: 8px;
}

.header h1 {
  font-family: 'Orbitron', sans-serif;
  font-size: 28px;
  font-weight: 900;
  letter-spacing: 4px;
  text-shadow: var(--pip-glow), 0 0 20px var(--pip-green-dark);
  color: var(--pip-green);
}

.header .header-acronym {
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--pip-green-dim);
  margin-top: 4px;
  margin-bottom: 8px;
}

.header .subtitle {
  font-size: 12px;
  color: var(--pip-green-dim);
  margin-top: 6px;
  letter-spacing: 2px;
}

/* Stats bar */
.stats-bar {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 15px;
  margin-bottom: 25px;
}

.stat-card {
  background: var(--pip-panel);
  border: 1px solid var(--pip-border);
  padding: 18px 15px;
  text-align: center;
  position: relative;
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 100%;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--pip-green), transparent);
}

.stat-label {
  font-size: 10px;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: var(--pip-green-dim);
  margin-bottom: 8px;
}

.stat-value {
  font-family: 'Orbitron', sans-serif;
  font-size: 26px;
  font-weight: 700;
  text-shadow: var(--pip-glow);
}

/* Section */
.section {
  margin-bottom: 25px;
}

.section-title {
  font-family: 'Orbitron', sans-serif;
  font-size: 14px;
  letter-spacing: 3px;
  color: var(--pip-green);
  border-bottom: 1px solid var(--pip-border);
  padding-bottom: 8px;
  margin-bottom: 12px;
  text-shadow: var(--pip-glow);
}

.section-title::before {
  content: '// ';
  color: var(--pip-green-dim);
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

thead th {
  font-family: 'Orbitron', sans-serif;
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--pip-green-dim);
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--pip-border);
}

tbody td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--pip-green-dark);
  white-space: nowrap;
}

tbody tr:hover {
  background: var(--pip-panel);
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--pip-green);
  box-shadow: 0 0 6px var(--pip-green);
  vertical-align: middle;
}

.hash-cell {
  font-size: 11px;
  color: var(--pip-green-dim);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Footer */
.footer {
  text-align: center;
  padding: 20px;
  border-top: 1px solid var(--pip-border);
  margin-top: 15px;
  font-size: 11px;
  color: var(--pip-green-dim);
}

.footer .payout {
  color: var(--pip-green);
  font-size: 12px;
  margin-bottom: 5px;
  word-break: break-all;
}

.no-data {
  text-align: center;
  padding: 30px;
  color: var(--pip-green-dim);
  font-style: italic;
}

/* Hashrate graph */
.graph-container {
  position: relative;
  height: 180px;
  border: 1px solid var(--pip-border);
  background: var(--pip-panel);
  margin-bottom: 25px;
  padding: 0;
}

.graph-container canvas {
  display: block;
  width: 100%;
  height: 100%;
}

.graph-label {
  position: absolute;
  top: 8px;
  right: 12px;
  font-family: 'Orbitron', sans-serif;
  font-size: 13px;
  color: var(--pip-green);
  text-shadow: var(--pip-glow);
  pointer-events: none;
}

/* Connection Info */
.connect-box {
  background: var(--pip-panel);
  border: 1px solid var(--pip-green);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 20px;
  box-shadow: var(--pip-glow);
}
.connect-box .section-title { margin-bottom: 10px; }
.connect-row {
  display: flex;
  align-items: center;
  margin: 6px 0;
  font-size: 14px;
  gap: 10px;
  flex-wrap: wrap;
}
.connect-label {
  color: var(--pip-green-dim);
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  min-width: 90px;
  text-transform: uppercase;
}
.connect-value {
  color: var(--pip-green);
  font-family: 'Share Tech Mono', monospace;
  font-size: 15px;
  background: rgba(0,0,0,0.4);
  padding: 4px 12px;
  border-radius: 4px;
  border: 1px solid var(--pip-border);
  user-select: all;
  cursor: pointer;
}
.connect-value:hover {
  background: var(--pip-panel);
  border-color: var(--pip-green);
}
.connect-hint {
  color: var(--pip-green-dim);
  font-size: 11px;
  font-style: italic;
}

/* Block Found Notification */
.block-notification {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%) scale(0);
  background: var(--pip-bg);
  border: 3px solid var(--pip-green);
  padding: 30px 50px;
  z-index: 10000;
  text-align: center;
  box-shadow: var(--pip-glow), inset 0 0 30px var(--pip-green-dark);
  animation: blockFoundPop 3s ease-out forwards;
}

.block-notification::before {
  content: '';
  position: absolute;
  top: -3px; left: -3px; right: -3px; bottom: -3px;
  border: 1px solid var(--pip-green-dim);
  pointer-events: none;
}

.block-notification .vault-icon {
  font-size: 48px;
  margin-bottom: 10px;
  animation: iconPulse 0.5s ease-in-out infinite alternate;
}

.block-notification h2 {
  font-family: 'Orbitron', sans-serif;
  font-size: 24px;
  letter-spacing: 4px;
  color: var(--pip-green);
  text-shadow: var(--pip-glow);
  margin-bottom: 10px;
}

.block-notification .block-height {
  font-family: 'Orbitron', sans-serif;
  font-size: 36px;
  color: var(--pip-amber);
  text-shadow: 0 0 10px rgba(255, 193, 7, 0.5);
}

.block-notification .worker-name {
  font-size: 14px;
  color: var(--pip-green-dim);
  margin-top: 10px;
}

@keyframes blockFoundPop {
  0% { transform: translate(-50%, -50%) scale(0); opacity: 0; }
  15% { transform: translate(-50%, -50%) scale(1.1); opacity: 1; }
  25% { transform: translate(-50%, -50%) scale(1); }
  75% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
  100% { transform: translate(-50%, -50%) scale(0.8); opacity: 0; }
}

@keyframes iconPulse {
  from { text-shadow: var(--pip-glow); }
  to { text-shadow: var(--pip-glow), 0 0 50px var(--pip-green-dark); }
}

/* Stat value flash on change */
.stat-flash {
  animation: valFlash 0.6s ease;
}
@keyframes valFlash {
  0% { text-shadow: var(--pip-glow), 0 0 15px var(--pip-green-dim); }
  100% { text-shadow: var(--pip-glow); }
}

/* Smooth table row transitions */
tbody tr {
  transition: background 0.3s ease;
}

/* VR badge */
.vr-badge {
  display: inline-block;
  font-size: 9px;
  font-family: 'Orbitron', sans-serif;
  background: var(--pip-panel);
  border: 1px solid var(--pip-green-dim);
  color: var(--pip-green);
  padding: 1px 4px;
  margin-left: 6px;
  vertical-align: middle;
  letter-spacing: 1px;
}

/* Graph tooltip */
.graph-tooltip {
  position: absolute;
  background: rgba(11,12,10,0.92);
  border: 1px solid var(--pip-green);
  color: var(--pip-green);
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  padding: 4px 8px;
  pointer-events: none;
  white-space: nowrap;
  z-index: 10;
  box-shadow: var(--pip-glow);
  display: none;
}

/* Settings gear */
.settings-btn {
  position: absolute;
  top: 12px;
  right: 12px;
  width: 32px;
  height: 32px;
  background: none;
  border: 1px solid var(--pip-border);
  color: var(--pip-green-dim);
  font-size: 18px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.2s, border-color 0.2s, transform 0.3s;
  z-index: 10;
}
.settings-btn:hover {
  color: var(--pip-green);
  border-color: var(--pip-green);
  transform: rotate(30deg);
}

/* Settings panel */
.settings-panel {
  position: absolute;
  top: 48px;
  right: 12px;
  background: var(--pip-bg);
  border: 1px solid var(--pip-border);
  padding: 12px 14px;
  z-index: 20;
  display: none;
  box-shadow: 0 0 15px rgba(0,0,0,0.6);
}
.settings-panel.open { display: block; }
.settings-panel-title {
  font-family: 'Orbitron', sans-serif;
  font-size: 9px;
  letter-spacing: 2px;
  color: var(--pip-green-dim);
  margin-bottom: 8px;
  text-transform: uppercase;
}
.theme-swatches {
  display: flex;
  gap: 8px;
}
.theme-swatch {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  border: 2px solid rgba(255,255,255,0.15);
  cursor: pointer;
  transition: transform 0.15s, border-color 0.2s, box-shadow 0.2s;
  position: relative;
}
.theme-swatch:hover {
  transform: scale(1.2);
}
.theme-swatch.active {
  border-color: #fff;
  box-shadow: 0 0 8px currentColor;
}

/* Hash background canvas */
#hashBg {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: -1;
  pointer-events: none;
}

/* Responsive */
@media (max-width: 700px) {
  .stats-bar { grid-template-columns: repeat(2, 1fr); gap: 10px; }
  .header h1 { font-size: 18px; letter-spacing: 2px; }
  table { font-size: 11px; }
  thead th, tbody td { padding: 6px 6px; }
  .connect-row { flex-direction: column; align-items: flex-start; gap: 2px; }
}
</style>
</head>
<body>
<canvas id="hashBg"></canvas>
<div class="container">
  <div class="header">
    <button class="settings-btn" id="settingsBtn" title="Settings">&#9881;</button>
    <div class="settings-panel" id="settingsPanel">
      <div class="settings-panel-title">Accent Color</div>
      <div class="theme-swatches" id="themeSwatches"></div>
      <a href="/settings" style="display:block;margin-top:10px;color:var(--pip-green-dim);font-size:12px;text-decoration:none;border-top:1px solid var(--pip-border);padding-top:8px;transition:color 0.2s" onmouseover="this.style.color='var(--pip-green)'" onmouseout="this.style.color='var(--pip-green-dim)'" >&#9881; Server Settings</a>
    </div>
    <h1>C.A.P.S. S.M.S.D.</h1>
    <div class="header-acronym">Cryptocurrency Acquisition & Processing System - Stratum Mining Services Dashboard</div>
    <div class="subtitle">BLOCK HEIGHT: <span id="blockHeight">---</span> | PORT: <span id="stratumPort">---</span></div>
  </div>

  <div class="stats-bar">
    <div class="stat-card">
      <div class="stat-label">Miners Online</div>
      <div class="stat-value" id="statMiners">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Shares Accepted</div>
      <div class="stat-value" id="statAccepted">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Shares Rejected</div>
      <div class="stat-value" id="statRejected" style="color: var(--pip-green)">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Blocks Found</div>
      <div class="stat-value" id="statBlocks">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Uptime</div>
      <div class="stat-value" id="statUptime">---</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Net Difficulty</div>
      <div class="stat-value" id="statNetDiff">---</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Net Hashrate</div>
      <div class="stat-value" id="statNetHash">---</div>
    </div>
  </div>

  <div class="connect-box">
    <div class="section-title">Connect Your Miner</div>
    <div class="connect-row">
      <span class="connect-label">Stratum URL</span>
      <span class="connect-value" id="stratumUrl" title="Click to select">---</span>
      <span class="connect-hint">click to select, then copy</span>
    </div>
    <div class="connect-row">
      <span class="connect-label">Worker</span>
      <span class="connect-value">anything</span>
      <span class="connect-hint">worker name can be any text</span>
    </div>
    <div class="connect-row">
      <span class="connect-label">Password</span>
      <span class="connect-value">x</span>
      <span class="connect-hint">password is not checked</span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Pool Hashrate</div>
    <div class="graph-container">
      <canvas id="hashrateGraph"></canvas>
      <div class="graph-label" id="currentHashrate">0 H/s</div>
      <div class="graph-tooltip" id="graphTooltip"></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Connected Miners</div>
    <table>
      <thead>
        <tr>
          <th></th>
          <th>Worker</th>
          <th>User Agent</th>
          <th>IP</th>
          <th>Difficulty</th>
          <th>Accepted</th>
          <th>Rejected</th>
          <th>Connected</th>
          <th>Last Share</th>
        </tr>
      </thead>
      <tbody id="minersTable">
        <tr><td colspan="9" class="no-data">No miners connected</td></tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-title">Recent Blocks Found</div>
    <table>
      <thead>
        <tr>
          <th>Height</th>
          <th>Hash</th>
          <th>Found By</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody id="blocksTable">
        <tr><td colspan="4" class="no-data">No blocks found yet</td></tr>
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div class="payout">PAYOUT: <span id="payoutAddr">---</span></div>
    <div><span id="footerCoin">CAPS</span> Stratum Server &bull; Vault-Tec Industries</div>
  </div>
</div>

<script>
/* ---- Theme system ---- */
var THEMES = {
  green:  { primary: '#14fe17', dim: '#0a8f0c', dark: '#063f07' },
  amber:  { primary: '#ffb000', dim: '#8f6a00', dark: '#3f2f00' },
  cyan:   { primary: '#00d4ff', dim: '#007a8f', dark: '#003540' },
  red:    { primary: '#ff3d3d', dim: '#8f2222', dark: '#3f0f0f' },
  violet: { primary: '#b44aff', dim: '#6a2e8f', dark: '#2f1440' },
  white:  { primary: '#e0e0e0', dim: '#808080', dark: '#404040' }
};

function hexToRgb(hex) {
  var r = parseInt(hex.slice(1,3), 16);
  var g = parseInt(hex.slice(3,5), 16);
  var b = parseInt(hex.slice(5,7), 16);
  return { r: r, g: g, b: b };
}

function applyTheme(name) {
  var t = THEMES[name];
  if (!t) t = THEMES.green;
  var root = document.documentElement.style;
  var c = hexToRgb(t.primary);
  root.setProperty('--pip-green', t.primary);
  root.setProperty('--pip-green-dim', t.dim);
  root.setProperty('--pip-green-dark', t.dark);
  root.setProperty('--pip-panel', 'rgba(' + c.r + ',' + c.g + ',' + c.b + ',0.05)');
  root.setProperty('--pip-border', 'rgba(' + c.r + ',' + c.g + ',' + c.b + ',0.3)');
  root.setProperty('--pip-glow', '0 0 10px rgba(' + c.r + ',' + c.g + ',' + c.b + ',0.3)');
  root.setProperty('--pip-scanline', 'rgba(' + c.r + ',' + c.g + ',' + c.b + ',0.03)');
  try { localStorage.setItem('caps-theme', name); } catch(e) {}
  try { fetch('/api/preferences',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({theme:name})}); } catch(e) {}
  // Update swatch active state
  var swatches = document.querySelectorAll('.theme-swatch');
  swatches.forEach(function(sw) {
    sw.classList.toggle('active', sw.dataset.theme === name);
  });
}

(function initThemeUI() {
  var container = document.getElementById('themeSwatches');
  var btn = document.getElementById('settingsBtn');
  var panel = document.getElementById('settingsPanel');
  if (!container || !btn || !panel) return;

  // Build swatches
  var names = Object.keys(THEMES);
  names.forEach(function(name) {
    var swatch = document.createElement('div');
    swatch.className = 'theme-swatch';
    swatch.dataset.theme = name;
    swatch.style.background = THEMES[name].primary;
    swatch.title = name.charAt(0).toUpperCase() + name.slice(1);
    swatch.addEventListener('click', function() {
      applyTheme(name);
    });
    container.appendChild(swatch);
  });

  // Toggle panel
  btn.addEventListener('click', function(e) {
    e.stopPropagation();
    panel.classList.toggle('open');
  });
  document.addEventListener('click', function(e) {
    if (!panel.contains(e.target) && e.target !== btn) {
      panel.classList.remove('open');
    }
  });

  // Load saved theme: try server first, fall back to localStorage
  var localTheme = null;
  try { localTheme = localStorage.getItem('caps-theme'); } catch(e) {}
  applyTheme(localTheme || 'green');
  fetch('/api/preferences').then(function(r){return r.json();}).then(function(p){
    if (p.theme && p.theme !== (localTheme || 'green')) applyTheme(p.theme);
  }).catch(function(){});
})();

/* ---- Hash background animation ---- */
(function initHashBg() {
  var canvas = document.getElementById('hashBg');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var W, H, dpr;
  var fragments = [];
  var HEX = '0123456789abcdef';
  var FRAG_COUNT = 25;
  var MERGE_INTERVAL = 5000;
  var BLOCK_INTERVAL = 20000;
  var lastMerge = 0;
  var lastBlock = 0;
  var blockFlashes = [];
  var frameSkip = false;
  var running = true;

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function randHex(len) {
    var s = '';
    for (var i = 0; i < len; i++) s += HEX[Math.floor(Math.random() * 16)];
    return s;
  }

  var globalPulse = 0;
  var exploding = 0;
  var explosionParticles = [];

  function createFragment() {
    var len = 8 + Math.floor(Math.random() * 9);
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: -(0.1 + Math.random() * 0.2),
      text: randHex(len),
      opacity: 0.06 + Math.random() * 0.04,
      baseOpacity: 0,
      size: 10 + Math.floor(Math.random() * 4),
      mergeCount: 0,
      pulse: 0
    };
  }

  // Called from refresh() when new shares arrive
  window.hashBgPulse = function() {
    globalPulse = 1.0;
  };

  // Called from refresh() on rejected share — explode outward from center
  window.hashBgExplode = function() {
    exploding = 1.0;
    var cx = W / 2, cy = H / 2;
    // Blast all fragments outward from center
    for (var i = 0; i < fragments.length; i++) {
      var f = fragments[i];
      var dx = f.x - cx, dy = f.y - cy;
      var dist = Math.sqrt(dx * dx + dy * dy) || 1;
      f.vx = (dx / dist) * (3 + Math.random() * 3);
      f.vy = (dy / dist) * (3 + Math.random() * 3);
      f.pulse = 1.0;
    }
    // Spawn red explosion particles from center
    for (var i = 0; i < 20; i++) {
      var angle = Math.random() * Math.PI * 2;
      var speed = 2 + Math.random() * 4;
      explosionParticles.push({
        x: cx, y: cy,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        life: 1.0,
        text: randHex(4 + Math.floor(Math.random() * 5))
      });
    }
  };

  function init() {
    resize();
    fragments = [];
    for (var i = 0; i < FRAG_COUNT; i++) fragments.push(createFragment());
    fragments.forEach(function(f) { f.baseOpacity = f.opacity; });
    lastMerge = performance.now();
    lastBlock = performance.now();
  }

  function getThemeColor() {
    var c = getComputedStyle(document.documentElement).getPropertyValue('--pip-green').trim();
    return c || '#14fe17';
  }

  function update(now) {
    // Decay global pulse (share flash)
    if (globalPulse > 0) {
      globalPulse *= 0.97;
      if (globalPulse < 0.005) globalPulse = 0;
    }

    // Decay explosion state
    if (exploding > 0) {
      exploding *= 0.97;
      if (exploding < 0.005) exploding = 0;
    }

    // Move fragments
    for (var i = 0; i < fragments.length; i++) {
      var f = fragments[i];
      // Drag fragments back to normal drift after explosion
      if (exploding > 0) {
        f.vx *= 0.97;
        f.vy *= 0.97;
      } else {
        // Gently restore normal drift speeds
        var targetVx = (Math.random() - 0.5) * 0.3;
        var targetVy = -(0.1 + Math.random() * 0.2);
        if (Math.abs(f.vx) > 0.5) f.vx *= 0.95;
        if (Math.abs(f.vy) > 0.5) f.vy *= 0.95;
      }
      f.x += f.vx;
      f.y += f.vy;
      // Wrap around edges
      if (f.x < -100) f.x = W + 50;
      if (f.x > W + 100) f.x = -50;
      if (f.y < -30) f.y = H + 20;
      if (f.y > H + 30) f.y = -20;
      // Decay per-fragment pulse (merge flash)
      if (f.pulse > 0) {
        f.pulse *= 0.95;
        if (f.pulse < 0.001) f.pulse = 0;
      }
      // Combine base + merge pulse + global share pulse
      f.opacity = f.baseOpacity + f.pulse * 0.15 + globalPulse * 0.12;
    }

    // Update explosion particles
    for (var i = explosionParticles.length - 1; i >= 0; i--) {
      var ep = explosionParticles[i];
      ep.x += ep.vx;
      ep.y += ep.vy;
      ep.vx *= 0.98;
      ep.vy *= 0.98;
      ep.life -= 0.02;
      if (ep.life <= 0) explosionParticles.splice(i, 1);
    }

    // Merge check
    if (now - lastMerge > MERGE_INTERVAL && fragments.length >= 2) {
      lastMerge = now;
      // Find two closest fragments
      var bestDist = Infinity, ai = -1, bi = -1;
      for (var i = 0; i < fragments.length; i++) {
        for (var j = i + 1; j < fragments.length; j++) {
          var dx = fragments[i].x - fragments[j].x;
          var dy = fragments[i].y - fragments[j].y;
          var d = dx * dx + dy * dy;
          if (d < bestDist) { bestDist = d; ai = i; bi = j; }
        }
      }
      if (ai >= 0 && bi >= 0) {
        var a = fragments[ai];
        var b = fragments[bi];
        // Merge: a absorbs b
        a.text = (a.text + b.text).substring(0, 16);
        a.mergeCount++;
        a.pulse = 1;
        a.x = (a.x + b.x) / 2;
        a.y = (a.y + b.y) / 2;
        // Replace b with a new fragment
        fragments[bi] = createFragment();
        fragments[bi].baseOpacity = fragments[bi].opacity;
      }
    }

    // Block formation check
    if (now - lastBlock > BLOCK_INTERVAL) {
      lastBlock = now;
      // Find a fragment with enough merges
      for (var i = 0; i < fragments.length; i++) {
        if (fragments[i].mergeCount >= 3) {
          blockFlashes.push({
            x: fragments[i].x,
            y: fragments[i].y,
            life: 1.0
          });
          // Reset the fragment
          fragments[i] = createFragment();
          fragments[i].baseOpacity = fragments[i].opacity;
          break;
        }
      }
    }

    // Decay block flashes
    for (var i = blockFlashes.length - 1; i >= 0; i--) {
      blockFlashes[i].life -= 0.015;
      if (blockFlashes[i].life <= 0) blockFlashes.splice(i, 1);
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    var color = getThemeColor();
    var rgb = hexToRgb(color);
    // Blend toward red during explosion
    var dr = rgb.r + (255 - rgb.r) * exploding;
    var dg = rgb.g * (1 - exploding * 0.85);
    var db = rgb.b * (1 - exploding * 0.85);

    // Draw fragments
    for (var i = 0; i < fragments.length; i++) {
      var f = fragments[i];
      ctx.font = f.size + 'px "Share Tech Mono", monospace';
      var fo = exploding > 0 ? Math.min(f.opacity + exploding * 0.2, 0.5) : f.opacity;
      ctx.fillStyle = 'rgba(' + Math.round(dr) + ',' + Math.round(dg) + ',' + Math.round(db) + ',' + fo.toFixed(3) + ')';
      ctx.fillText(f.text, f.x, f.y);
    }

    // Draw explosion particles (always red)
    for (var i = 0; i < explosionParticles.length; i++) {
      var ep = explosionParticles[i];
      ctx.font = '11px "Share Tech Mono", monospace';
      ctx.fillStyle = 'rgba(255,61,61,' + (ep.life * 0.4).toFixed(3) + ')';
      ctx.fillText(ep.text, ep.x, ep.y);
    }

    // Draw block flashes
    for (var i = 0; i < blockFlashes.length; i++) {
      var bf = blockFlashes[i];
      var a = bf.life * 0.2;
      ctx.strokeStyle = 'rgba(' + rgb.r + ',' + rgb.g + ',' + rgb.b + ',' + a.toFixed(3) + ')';
      ctx.lineWidth = 1.5;
      var s = 20 + (1 - bf.life) * 15;
      ctx.strokeRect(bf.x - s, bf.y - s * 0.6, s * 2, s * 1.2);
      // Inner glow text
      ctx.fillStyle = 'rgba(' + rgb.r + ',' + rgb.g + ',' + rgb.b + ',' + (a * 0.8).toFixed(3) + ')';
      ctx.font = '9px "Orbitron", sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('BLOCK', bf.x, bf.y + 3);
      ctx.textAlign = 'left';
    }
  }

  function loop(ts) {
    if (!running) return;
    if (document.hidden) { requestAnimationFrame(loop); return; }
    // Throttle to ~30fps
    frameSkip = !frameSkip;
    if (frameSkip) { requestAnimationFrame(loop); return; }
    update(ts);
    draw();
    requestAnimationFrame(loop);
  }

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', function() {
    if (!document.hidden && running) requestAnimationFrame(loop);
  });

  init();
  requestAnimationFrame(loop);
})();

function formatTime(ts) {
  var d = new Date(ts * 1000);
  return d.toLocaleString();
}

function truncHash(h) {
  if (!h || h.length < 16) return h || '';
  return h.substring(0, 10) + '...' + h.substring(h.length - 10);
}

function formatSI(val) {
  var units = ['', 'K', 'M', 'G', 'T', 'P'];
  var idx = 0;
  var v = val;
  while (v >= 1000 && idx < units.length - 1) { v /= 1000; idx++; }
  return v.toFixed(2) + ' ' + units[idx];
}

function formatHashrate(hr) {
  var units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s'];
  var idx = 0;
  var v = hr;
  while (v >= 1000 && idx < units.length - 1) { v /= 1000; idx++; }
  return v.toFixed(2) + ' ' + units[idx];
}

function formatDiff(d) {
  if (d === 0) return '0';
  if (d >= 1) return d.toPrecision(4);
  // For small diffs, show enough digits
  return d.toPrecision(4);
}

/* ---- Stat flash helper ---- */
function updateStat(id, val) {
  var el = document.getElementById(id);
  if (!el) return;
  var s = String(val);
  if (el.textContent !== s) {
    el.textContent = s;
    el.classList.remove('stat-flash');
    void el.offsetWidth;
    el.classList.add('stat-flash');
  }
}

/* ---- Miner table builder ---- */
function buildMinerRow(m) {
  var vrBadge = m.version_rolling ? '<span class="vr-badge">VR</span>' : '';
  var rejStyle = m.rejected > 0 ? ' style="color: var(--pip-red)"' : '';
  return '<tr>' +
    '<td><span class="status-dot"></span></td>' +
    '<td>' + m.worker + vrBadge + '</td>' +
    '<td>' + m.user_agent + '</td>' +
    '<td>' + m.ip + '</td>' +
    '<td>' + formatDiff(m.difficulty) + '</td>' +
    '<td>' + m.shares + '</td>' +
    '<td' + rejStyle + '>' + m.rejected + '</td>' +
    '<td>' + m.connected + '</td>' +
    '<td>' + m.last_share + '</td>' +
    '</tr>';
}

function buildMinersHTML(miners) {
  return miners.map(buildMinerRow).join('');
}

function buildBlocksHTML(blocks) {
  return blocks.map(function(b) {
    return '<tr>' +
      '<td>' + b.height + '</td>' +
      '<td class="hash-cell" title="' + b.hash + '">' + truncHash(b.hash) + '</td>' +
      '<td>' + b.worker + '</td>' +
      '<td>' + formatTime(b.time) + '</td>' +
      '</tr>';
  }).join('');
}

/* ---- Catmull-Rom smooth curve ---- */
function smoothLine(ctx, points) {
  if (points.length < 2) return;
  ctx.moveTo(points[0].x, points[0].y);
  if (points.length === 2) {
    ctx.lineTo(points[1].x, points[1].y);
    return;
  }
  for (var i = 0; i < points.length - 1; i++) {
    var p0 = points[i === 0 ? 0 : i - 1];
    var p1 = points[i];
    var p2 = points[i + 1];
    var p3 = points[i + 2 >= points.length ? points.length - 1 : i + 2];
    var cp1x = p1.x + (p2.x - p0.x) / 6;
    var cp1y = p1.y + (p2.y - p0.y) / 6;
    var cp2x = p2.x - (p3.x - p1.x) / 6;
    var cp2y = p2.y - (p3.y - p1.y) / 6;
    ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
  }
}

/* ---- Graph state ---- */
var graphPoints = [];   // cached {x, y, hr, t} for hover lookup
var graphHoverIdx = -1;
var graphPadL = 80, graphPadR = 15, graphPadT = 10, graphPadB = 25;
var graphPulsePhase = 0;

function getThemeRgb() {
  var hex = getComputedStyle(document.documentElement).getPropertyValue('--pip-green').trim() || '#14fe17';
  return hexToRgb(hex);
}

function drawHashrateGraph(history) {
  var canvas = document.getElementById('hashrateGraph');
  if (!canvas) return;
  var container = canvas.parentElement;
  var dpr = window.devicePixelRatio || 1;
  var w = container.clientWidth;
  var h = container.clientHeight;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  var ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  ctx.clearRect(0, 0, w, h);

  var tc = getThemeRgb();
  var R = tc.r, G = tc.g, B = tc.b;
  var primary = getComputedStyle(document.documentElement).getPropertyValue('--pip-green').trim() || '#14fe17';

  var padL = graphPadL, padR = graphPadR, padT = graphPadT, padB = graphPadB;
  var gw = w - padL - padR;
  var gh = h - padT - padB;

  if (!history || history.length < 2) {
    ctx.fillStyle = 'rgba(' + R + ',' + G + ',' + B + ',0.3)';
    ctx.font = '12px "Share Tech Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for data...', w / 2, h / 2);
    graphPoints = [];
    return;
  }

  var cutoff = history[history.length - 1].t - 1800;
  history = history.filter(function(p) { return p.t >= cutoff; });
  if (history.length < 2) {
    ctx.fillStyle = 'rgba(' + R + ',' + G + ',' + B + ',0.3)';
    ctx.font = '12px "Share Tech Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for data...', w / 2, h / 2);
    graphPoints = [];
    return;
  }

  var hrs = history.map(function(p) { return p.hr; });
  var times = history.map(function(p) { return p.t; });
  var maxHr = Math.max.apply(null, hrs);
  var minHr = Math.min.apply(null, hrs);
  if (maxHr <= 0) maxHr = 1;

  var axisMin = 0;
  if (minHr > maxHr * 0.5) axisMin = minHr * 0.85;
  var axisMax = maxHr * 1.15;

  var tMin = times[0];
  var tMax = times[times.length - 1];
  var tRange = tMax - tMin;
  if (tRange <= 0) tRange = 1;

  // Grid lines
  ctx.strokeStyle = 'rgba(' + R + ',' + G + ',' + B + ',0.1)';
  ctx.lineWidth = 1;
  var gridRows = 4;
  for (var i = 0; i <= gridRows; i++) {
    var gy = padT + (gh / gridRows) * i;
    ctx.beginPath();
    ctx.moveTo(padL, gy);
    ctx.lineTo(padL + gw, gy);
    ctx.stroke();
  }

  // Y-axis labels
  var axisRange = axisMax - axisMin;
  if (axisRange <= 0) axisRange = 1;
  ctx.fillStyle = 'rgba(' + R + ',' + G + ',' + B + ',0.5)';
  ctx.font = '10px "Share Tech Mono", monospace';
  ctx.textAlign = 'right';
  for (var i = 0; i <= gridRows; i++) {
    var val = axisMax - (axisRange * i / gridRows);
    var gy = padT + (gh / gridRows) * i;
    ctx.fillText(formatHashrate(val), padL - 5, gy + 4);
  }

  // X-axis labels
  ctx.textAlign = 'center';
  var now = tMax;
  var xLabels = [
    { offset: 0, label: 'now' },
    { offset: 120, label: '-2m' },
    { offset: 300, label: '-5m' },
    { offset: 600, label: '-10m' },
    { offset: 1200, label: '-20m' },
    { offset: 1800, label: '-30m' }
  ];
  for (var i = 0; i < xLabels.length; i++) {
    var t = now - xLabels[i].offset;
    if (t < tMin) continue;
    var x = padL + ((t - tMin) / tRange) * gw;
    if (x >= padL && x <= padL + gw) {
      ctx.fillText(xLabels[i].label, x, h - 5);
    }
  }

  // Build path points
  var points = [];
  for (var i = 0; i < history.length; i++) {
    var x = padL + ((times[i] - tMin) / tRange) * gw;
    var y = padT + gh - ((hrs[i] - axisMin) / axisRange) * gh;
    points.push({ x: x, y: y, hr: hrs[i], t: times[i] });
  }
  graphPoints = points;

  // Filled area (smooth)
  ctx.beginPath();
  ctx.moveTo(points[0].x, padT + gh);
  ctx.lineTo(points[0].x, points[0].y);
  if (points.length > 2) {
    for (var i = 0; i < points.length - 1; i++) {
      var p0 = points[i === 0 ? 0 : i - 1];
      var p1 = points[i];
      var p2 = points[i + 1];
      var p3 = points[i + 2 >= points.length ? points.length - 1 : i + 2];
      var cp1x = p1.x + (p2.x - p0.x) / 6;
      var cp1y = p1.y + (p2.y - p0.y) / 6;
      var cp2x = p2.x - (p3.x - p1.x) / 6;
      var cp2y = p2.y - (p3.y - p1.y) / 6;
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
    }
  } else {
    ctx.lineTo(points[1].x, points[1].y);
  }
  ctx.lineTo(points[points.length - 1].x, padT + gh);
  ctx.closePath();
  var grad = ctx.createLinearGradient(0, padT, 0, padT + gh);
  grad.addColorStop(0, 'rgba(' + R + ',' + G + ',' + B + ',0.25)');
  grad.addColorStop(1, 'rgba(' + R + ',' + G + ',' + B + ',0.02)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Line with glow (smooth)
  ctx.shadowColor = 'rgba(' + R + ',' + G + ',' + B + ',0.6)';
  ctx.shadowBlur = 6;
  ctx.strokeStyle = primary;
  ctx.lineWidth = 2;
  ctx.beginPath();
  smoothLine(ctx, points);
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Glowing dot at latest point
  var last = points[points.length - 1];
  graphPulsePhase = (graphPulsePhase + 0.15) % (2 * Math.PI);
  var pulseR = 4 + Math.sin(graphPulsePhase) * 2;
  ctx.beginPath();
  ctx.arc(last.x, last.y, pulseR, 0, 2 * Math.PI);
  ctx.fillStyle = primary;
  ctx.shadowColor = 'rgba(' + R + ',' + G + ',' + B + ',0.8)';
  ctx.shadowBlur = 10;
  ctx.fill();
  ctx.shadowBlur = 0;

  // Hover crosshair + highlight
  if (graphHoverIdx >= 0 && graphHoverIdx < points.length) {
    var hp = points[graphHoverIdx];
    // Vertical crosshair
    ctx.strokeStyle = 'rgba(' + R + ',' + G + ',' + B + ',0.4)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(hp.x, padT);
    ctx.lineTo(hp.x, padT + gh);
    ctx.stroke();
    ctx.setLineDash([]);

    // Highlight dot
    ctx.beginPath();
    ctx.arc(hp.x, hp.y, 5, 0, 2 * Math.PI);
    ctx.fillStyle = primary;
    ctx.shadowColor = 'rgba(' + R + ',' + G + ',' + B + ',0.9)';
    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.shadowBlur = 0;
  }
}

/* ---- Graph hover ---- */
(function() {
  var canvas = document.getElementById('hashrateGraph');
  var tooltip = document.getElementById('graphTooltip');
  if (!canvas || !tooltip) return;

  canvas.addEventListener('mousemove', function(e) {
    var rect = canvas.getBoundingClientRect();
    var mx = e.clientX - rect.left;
    if (graphPoints.length < 2) { graphHoverIdx = -1; tooltip.style.display = 'none'; return; }

    // Find nearest point by x
    var best = -1, bestDist = Infinity;
    for (var i = 0; i < graphPoints.length; i++) {
      var dx = Math.abs(graphPoints[i].x - mx);
      if (dx < bestDist) { bestDist = dx; best = i; }
    }
    if (bestDist > 30) { graphHoverIdx = -1; tooltip.style.display = 'none'; return; }
    graphHoverIdx = best;

    var p = graphPoints[best];
    var ago = Math.round(graphPoints[graphPoints.length - 1].t - p.t);
    var label = ago === 0 ? 'now' : ago + 's ago';
    tooltip.textContent = formatHashrate(p.hr) + '  (' + label + ')';
    tooltip.style.display = 'block';

    // Position tooltip near the point
    var tx = p.x + 12;
    var ty = p.y - 20;
    // Keep tooltip on screen
    var tw = tooltip.offsetWidth;
    var container = canvas.parentElement;
    if (tx + tw > container.clientWidth - 5) tx = p.x - tw - 12;
    if (ty < 5) ty = 5;
    tooltip.style.left = tx + 'px';
    tooltip.style.top = ty + 'px';
  });

  canvas.addEventListener('mouseleave', function() {
    graphHoverIdx = -1;
    tooltip.style.display = 'none';
  });
})();

/* ---- Targeted DOM update state ---- */
var prevMinerKeys = '';
var prevBlockCount = 0;
var lastBlockCount = 0;
var lastAccepted = -1;
var lastRejected = -1;

async function refresh() {
  try {
    var r = await fetch('/api/stats');
    var d = await r.json();

    // Header info (no flash needed)
    document.getElementById('blockHeight').textContent = d.server.block_height;
    document.getElementById('stratumPort').textContent = d.server.stratum_port;

    // Pulse hash background on new shares
    if (lastAccepted >= 0 && d.stats.accepted > lastAccepted && window.hashBgPulse) {
      window.hashBgPulse();
    }
    // Explode hash background on rejected share
    if (lastRejected >= 0 && d.stats.rejected > lastRejected && window.hashBgExplode) {
      window.hashBgExplode();
    }
    lastRejected = d.stats.rejected;
    lastAccepted = d.stats.accepted;

    // Stat cards with flash
    updateStat('statMiners', d.stats.miners);
    updateStat('statAccepted', d.stats.accepted.toLocaleString());
    updateStat('statRejected', d.stats.rejected);
    updateStat('statBlocks', d.stats.blocks);
    updateStat('statUptime', d.server.uptime);
    updateStat('statNetDiff', d.stats.net_difficulty ? formatSI(d.stats.net_difficulty) : '---');
    updateStat('statNetHash', d.stats.net_hashrate ? formatHashrate(d.stats.net_hashrate) : '---');

    // Color rejected stat red if > 0
    var rejEl = document.getElementById('statRejected');
    if (rejEl) rejEl.style.color = d.stats.rejected > 0 ? 'var(--pip-red)' : 'var(--pip-green)';

    // Block notification
    if (lastBlockCount > 0 && d.stats.blocks > lastBlockCount && d.recent_blocks.length > 0) {
      var latestBlock = d.recent_blocks[0];
      showBlockNotification(latestBlock.height, latestBlock.worker);
    }
    lastBlockCount = d.stats.blocks;

    document.getElementById('payoutAddr').textContent = d.server.payout_address;
    if (d.server.coin_ticker) {
      document.getElementById('footerCoin').textContent = d.server.coin_ticker;
    }
    if (d.server.stratum_url) {
      document.getElementById('stratumUrl').textContent = d.server.stratum_url;
      document.getElementById('stratumUrl').title = d.server.stratum_url;
    }

    // Hashrate graph
    drawHashrateGraph(d.hashrate_history);
    document.getElementById('currentHashrate').textContent = formatHashrate(d.stats.current_hashrate || 0);

    // ---- Miners table: targeted update ----
    var mt = document.getElementById('minersTable');
    if (d.miners.length === 0) {
      if (prevMinerKeys !== '') {
        mt.innerHTML = '<tr><td colspan="9" class="no-data">No miners connected</td></tr>';
        prevMinerKeys = '';
      }
    } else {
      var newKeys = d.miners.map(function(m) { return m.worker + '|' + m.ip; }).join('||');
      if (newKeys !== prevMinerKeys) {
        // Full rebuild: miners joined/left
        prevMinerKeys = newKeys;
        mt.innerHTML = buildMinersHTML(d.miners);
      } else {
        // In-place update of changing cells only
        var rows = mt.querySelectorAll('tr');
        d.miners.forEach(function(m, i) {
          if (!rows[i]) return;
          var cells = rows[i].querySelectorAll('td');
          if (cells.length < 9) return;
          // cells: 0=dot, 1=worker+VR, 2=agent, 3=ip, 4=diff, 5=accepted, 6=rejected, 7=connected, 8=last_share
          var newDiff = formatDiff(m.difficulty);
          if (cells[4].textContent !== newDiff) cells[4].textContent = newDiff;
          var newShares = String(m.shares);
          if (cells[5].textContent !== newShares) cells[5].textContent = newShares;
          var newRej = String(m.rejected);
          if (cells[6].textContent !== newRej) {
            cells[6].textContent = newRej;
            cells[6].style.color = m.rejected > 0 ? 'var(--pip-red)' : '';
          }
          var newConn = m.connected;
          if (cells[7].textContent !== newConn) cells[7].textContent = newConn;
          var newLs = m.last_share;
          if (cells[8].textContent !== newLs) cells[8].textContent = newLs;
        });
      }
    }

    // ---- Blocks table: only rebuild on change ----
    var bt = document.getElementById('blocksTable');
    if (d.recent_blocks.length === 0) {
      if (prevBlockCount !== 0) {
        bt.innerHTML = '<tr><td colspan="4" class="no-data">No blocks found yet</td></tr>';
        prevBlockCount = 0;
      }
    } else if (d.recent_blocks.length !== prevBlockCount) {
      prevBlockCount = d.recent_blocks.length;
      bt.innerHTML = buildBlocksHTML(d.recent_blocks);
    }
  } catch (e) {
    console.error('Dashboard refresh failed:', e);
  }
}

function showBlockNotification(height, worker) {
  var existing = document.querySelector('.block-notification');
  if (existing) existing.remove();

  var notification = document.createElement('div');
  notification.className = 'block-notification';
  notification.innerHTML =
    '<div class="vault-icon">⚛</div>' +
    '<h2>BLOCK FOUND!</h2>' +
    '<div class="block-height">#' + height + '</div>' +
    '<div class="worker-name">Discovered by: ' + worker + '</div>';
  document.body.appendChild(notification);

  setTimeout(function() {
    if (notification.parentNode) notification.remove();
  }, 3500);
}

refresh().then(function() {
  // Initialize lastBlockCount after first fetch
});
setInterval(refresh, 2000);
</script>
</body>
</html>
"""

SETTINGS_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Server Settings - Stratum Mining Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
:root {
  --pip-green: #14fe17;
  --pip-green-dim: #0a8f0c;
  --pip-green-dark: #063f07;
  --pip-bg: #0b0c0a;
  --pip-panel: rgba(20, 254, 23, 0.05);
  --pip-border: rgba(20, 254, 23, 0.3);
  --pip-glow: 0 0 10px rgba(20, 254, 23, 0.3);
  --pip-scanline: rgba(20, 254, 23, 0.03);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background:
    repeating-linear-gradient(0deg, transparent, transparent 3px, var(--pip-scanline) 3px, var(--pip-scanline) 4px),
    var(--pip-bg);
  color: var(--pip-green);
  font-family: 'Share Tech Mono', monospace;
  min-height: 100vh;
  padding: 20px;
}
.container {
  max-width: 720px;
  margin: 0 auto;
}
.back-link {
  color: var(--pip-green-dim);
  text-decoration: none;
  font-size: 13px;
  display: inline-block;
  margin-bottom: 12px;
  transition: color 0.2s;
}
.back-link:hover { color: var(--pip-green); }
h1 {
  font-family: 'Orbitron', sans-serif;
  font-size: 22px;
  text-align: center;
  margin-bottom: 6px;
  text-shadow: var(--pip-glow);
}
.subtitle {
  text-align: center;
  font-size: 11px;
  color: var(--pip-green-dim);
  margin-bottom: 20px;
}
.section {
  border: 1px solid var(--pip-border);
  margin-bottom: 16px;
  padding: 14px 16px;
  background: var(--pip-panel);
}
.section-title {
  font-family: 'Orbitron', sans-serif;
  font-size: 12px;
  letter-spacing: 2px;
  margin-bottom: 12px;
  text-transform: uppercase;
  color: var(--pip-green);
  border-bottom: 1px solid var(--pip-border);
  padding-bottom: 6px;
}
.field {
  display: flex;
  align-items: center;
  margin-bottom: 10px;
}
.field label {
  width: 170px;
  font-size: 12px;
  color: var(--pip-green-dim);
  flex-shrink: 0;
}
.field input, .field select {
  flex: 1;
  background: rgba(0,0,0,0.5);
  border: 1px solid var(--pip-border);
  color: var(--pip-green);
  font-family: 'Share Tech Mono', monospace;
  font-size: 13px;
  padding: 6px 10px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.field input:focus, .field select:focus {
  border-color: var(--pip-green);
  box-shadow: var(--pip-glow);
}
.field select { cursor: pointer; }
.field select option { background: #111; color: var(--pip-green); }
.pw-wrap {
  flex: 1;
  display: flex;
  position: relative;
}
.pw-wrap input { flex: 1; padding-right: 36px; }
.pw-toggle {
  position: absolute;
  right: 4px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--pip-green-dim);
  cursor: pointer;
  font-size: 14px;
  padding: 4px;
}
.pw-toggle:hover { color: var(--pip-green); }
.save-area {
  text-align: center;
  margin-top: 20px;
}
.save-btn {
  font-family: 'Orbitron', sans-serif;
  font-size: 14px;
  letter-spacing: 3px;
  padding: 12px 40px;
  background: transparent;
  border: 2px solid var(--pip-green);
  color: var(--pip-green);
  cursor: pointer;
  text-transform: uppercase;
  transition: background 0.2s, box-shadow 0.2s;
}
.save-btn:hover {
  background: rgba(20, 254, 23, 0.1);
  box-shadow: var(--pip-glow);
}
.status-msg {
  margin-top: 12px;
  font-size: 13px;
  min-height: 20px;
}
.status-msg.ok { color: var(--pip-green); }
.status-msg.err { color: #ff3d3d; }
.help-toggle {
  display: block;
  width: 100%;
  margin-top: 28px;
  padding: 10px;
  background: transparent;
  border: 1px solid var(--pip-border);
  color: var(--pip-green-dim);
  font-family: 'Orbitron', sans-serif;
  font-size: 12px;
  letter-spacing: 2px;
  cursor: pointer;
  text-transform: uppercase;
  transition: color 0.2s, border-color 0.2s;
}
.help-toggle:hover { color: var(--pip-green); border-color: var(--pip-green); }
.help-content {
  display: none;
  border: 1px solid var(--pip-border);
  border-top: none;
  padding: 16px 18px;
  background: var(--pip-panel);
  font-size: 12px;
  line-height: 1.7;
  color: var(--pip-green-dim);
}
.help-content.open { display: block; }
.help-content h3 {
  font-family: 'Orbitron', sans-serif;
  font-size: 12px;
  color: var(--pip-green);
  letter-spacing: 1px;
  margin: 16px 0 6px 0;
  border-bottom: 1px solid var(--pip-border);
  padding-bottom: 4px;
}
.help-content h3:first-child { margin-top: 0; }
.help-content code {
  background: rgba(0,0,0,0.4);
  padding: 1px 5px;
  font-size: 12px;
  color: var(--pip-green);
}
.help-content pre {
  background: rgba(0,0,0,0.5);
  border: 1px solid var(--pip-border);
  padding: 10px 12px;
  margin: 6px 0 10px 0;
  overflow-x: auto;
  font-size: 11px;
  line-height: 1.5;
  color: var(--pip-green);
}
.help-content ol, .help-content ul { margin: 6px 0 10px 20px; }
.help-content li { margin-bottom: 4px; }
.help-content .note {
  border-left: 3px solid var(--pip-green-dim);
  padding: 6px 10px;
  margin: 8px 0;
  background: rgba(0,0,0,0.3);
}
</style>
<script>
var THEMES_INIT = {
  green:  { primary: '#14fe17', dim: '#0a8f0c', dark: '#063f07' },
  amber:  { primary: '#ffb000', dim: '#8f6a00', dark: '#3f2f00' },
  cyan:   { primary: '#00d4ff', dim: '#007a8f', dark: '#003540' },
  red:    { primary: '#ff3d3d', dim: '#8f2222', dark: '#3f0f0f' },
  violet: { primary: '#b44aff', dim: '#6a2e8f', dark: '#2f1440' },
  white:  { primary: '#e0e0e0', dim: '#808080', dark: '#404040' }
};
function setThemeVars(name) {
  var c = THEMES_INIT[name] || THEMES_INIT.green;
  function hexToRgb(h) {
    var r = parseInt(h.slice(1,3),16), g = parseInt(h.slice(3,5),16), b = parseInt(h.slice(5,7),16);
    return r+','+g+','+b;
  }
  var s = document.documentElement.style;
  s.setProperty('--pip-green', c.primary);
  s.setProperty('--pip-green-dim', c.dim);
  s.setProperty('--pip-green-dark', c.dark);
  s.setProperty('--pip-panel', 'rgba('+hexToRgb(c.primary)+',0.05)');
  s.setProperty('--pip-border', 'rgba('+hexToRgb(c.primary)+',0.3)');
  s.setProperty('--pip-glow', '0 0 10px rgba('+hexToRgb(c.primary)+',0.3)');
  s.setProperty('--pip-scanline', 'rgba('+hexToRgb(c.primary)+',0.03)');
}
// Apply localStorage immediately (no flash), then override from server if different
var _initTheme = (function(){ try { return localStorage.getItem('caps-theme'); } catch(e) { return null; } })() || 'green';
setThemeVars(_initTheme);
</script>
</head>
<body>
<div class="container">
  <a href="/" class="back-link">&larr; Back to Dashboard</a>
  <h1>SERVER SETTINGS</h1>
  <div class="subtitle">STRATUM MINING SERVICES CONFIGURATION</div>

  <div class="section">
    <div class="section-title">Coin Preset</div>
    <div class="field">
      <label>Load Preset</label>
      <select id="presetSelect">
        <option value="">-- Custom --</option>
        <option value="caps">Caps</option>
        <option value="bitcoin">Bitcoin</option>
        <option value="bitcoin_cash">Bitcoin Cash</option>
        <option value="namecoin">Namecoin</option>
        <option value="peercoin">Peercoin</option>
        <option value="digibyte">DigiByte</option>
        <option value="bitcoin_ii">Bitcoin II</option>
        <option value="bitcoin_silver">Bitcoin Silver</option>
      </select>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Coin</div>
    <div class="field"><label>Coin Name</label><input id="coin_name" type="text"></div>
    <div class="field"><label>Ticker Symbol</label><input id="coin_ticker" type="text"></div>
    <div class="field"><label>Bech32 HRP</label><input id="bech32_hrp" type="text" placeholder="e.g. caps, bc (leave empty if none)"></div>
    <div class="field"><label>P2PKH Version</label><input id="p2pkh_version" type="number" min="0" max="255"></div>
    <div class="field"><label>P2SH Version</label><input id="p2sh_version" type="number" min="0" max="255"></div>
    <div class="field"><label>Coinbase Message</label><input id="coinbase_message" type="text"></div>
  </div>

  <div class="section">
    <div class="section-title">Network / RPC</div>
    <div class="field"><label>RPC Host</label><input id="rpc_host" type="text"></div>
    <div class="field"><label>RPC Port</label><input id="rpc_port" type="number" min="1" max="65535"></div>
    <div class="field"><label>RPC User</label><input id="rpc_user" type="text"></div>
    <div class="field">
      <label>RPC Password</label>
      <div class="pw-wrap">
        <input id="rpc_password" type="password" placeholder="(unchanged)">
        <button class="pw-toggle" id="pwToggle" type="button" title="Show/Hide">&#128065;</button>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Mining</div>
    <div class="field"><label>Payout Address</label><input id="payout_address" type="text"></div>
    <div class="field"><label>Stratum Port</label><input id="stratum_port" type="number" min="1" max="65535"></div>
    <div class="field"><label>Default Difficulty</label><input id="difficulty" type="text"></div>
    <div class="field"><label>Poll Interval (sec)</label><input id="poll_interval" type="number" min="1"></div>
  </div>

  <div class="section">
    <div class="section-title">Dashboard</div>
    <div class="field"><label>Dashboard Port</label><input id="dashboard_port" type="number" min="1" max="65535"></div>
  </div>

  <div class="save-area">
    <button class="save-btn" id="saveBtn">SAVE &amp; RESTART</button>
    <div class="status-msg" id="statusMsg"></div>
  </div>

  <button class="help-toggle" id="helpToggle">&#9881; SETUP GUIDE &#9660;</button>
  <div class="help-content" id="helpContent">

    <h3>Quick Start</h3>
    <ol>
      <li>Install and fully sync a coin node (e.g. <code>capsd</code>, <code>bitcoind</code>, <code>digibyted</code>)</li>
      <li>Enable RPC in the node's config file (see examples below)</li>
      <li>Select the matching <strong>Coin Preset</strong> above to fill in address parameters</li>
      <li>Enter your node's <strong>RPC credentials</strong> (host, port, user, password)</li>
      <li>Set your <strong>Payout Address</strong> &mdash; this is where mined coins go</li>
      <li>Click <strong>SAVE &amp; RESTART</strong></li>
    </ol>

    <h3>Node Config File</h3>
    <p>Each coin node needs RPC enabled. Edit the node's config file and add:</p>
    <pre>server=1
rpcuser=your_rpc_username
rpcpassword=your_rpc_password
rpcallowip=127.0.0.1
rpcport=10567</pre>

    <p>Config file locations by OS:</p>
    <ul>
      <li><strong>Windows:</strong> <code>%APPDATA%\CoinName\coinname.conf</code></li>
      <li><strong>Linux:</strong> <code>~/.coinname/coinname.conf</code></li>
      <li><strong>macOS:</strong> <code>~/Library/Application Support/CoinName/coinname.conf</code></li>
    </ul>

    <h3>Config Examples by Coin</h3>

    <p><strong>Caps</strong> &mdash; <code>caps.conf</code> (default data dir: <code>Caps</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=10567</pre>

    <p><strong>Bitcoin</strong> &mdash; <code>bitcoin.conf</code> (default data dir: <code>Bitcoin</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=8332</pre>

    <p><strong>Bitcoin Cash</strong> &mdash; <code>bitcoin.conf</code> (default data dir: <code>Bitcoin</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=8332</pre>
    <div class="note">BCH addresses can use CashAddr format (<code>bitcoincash:qr...</code>) or legacy Base58 format. Both are supported.</div>

    <p><strong>Namecoin</strong> &mdash; <code>namecoin.conf</code> (default data dir: <code>Namecoin</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=8336</pre>

    <p><strong>Peercoin</strong> &mdash; <code>peercoin.conf</code> (default data dir: <code>Peercoin</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=9902</pre>

    <p><strong>DigiByte</strong> &mdash; <code>digibyte.conf</code> (default data dir: <code>DigiByte</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=14022
algo=sha256d</pre>
    <div class="note">DigiByte is multi-algo. Make sure your node and miners are configured for the SHA-256d algorithm.</div>

    <p><strong>Bitcoin II</strong> &mdash; <code>bitcoin2.conf</code> (default data dir: <code>BitcoinII</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=8337</pre>
    <div class="note">Bitcoin II uses the same address format as Bitcoin (bc1... / 1... / 3...). Double-check you are using a BC2 address, not a BTC address.</div>

    <p><strong>Bitcoin Silver</strong> &mdash; <code>bitcoinsilver.conf</code> (default data dir: <code>BitcoinSilver</code>)</p>
    <pre>server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=127.0.0.1
rpcport=10567</pre>

    <h3>Custom / Unlisted Coins</h3>
    <p>Any SHA-256d coin with a Bitcoin-compatible RPC interface will work. To find the right values for a coin not listed above:</p>
    <ol>
      <li>Look in the coin's <code>src/chainparams.cpp</code> or <code>src/kernel/chainparams.cpp</code> on GitHub</li>
      <li>Find <code>base58Prefixes[PUBKEY_ADDRESS]</code> &rarr; this is the <strong>P2PKH Version</strong> byte</li>
      <li>Find <code>base58Prefixes[SCRIPT_ADDRESS]</code> &rarr; this is the <strong>P2SH Version</strong> byte</li>
      <li>Find <code>bech32_hrp</code> &rarr; this is the <strong>Bech32 HRP</strong> (leave empty if the coin has no segwit)</li>
      <li>Find the RPC port in <code>src/chainparamsbase.cpp</code></li>
    </ol>

    <h3>Connecting Miners</h3>
    <p>Point your miners at:</p>
    <pre>stratum+tcp://YOUR_IP:STRATUM_PORT</pre>
    <p>The exact URL is shown on the dashboard. For miners on the same machine, use <code>127.0.0.1</code>. For LAN miners, use your computer's local IP. Any worker name and password will be accepted.</p>

    <h3>Troubleshooting</h3>
    <ul>
      <li><strong>Miner can't connect to stratum</strong> &mdash; This is almost always <strong>Windows Firewall</strong> blocking the port. Open an <strong>Administrator</strong> command prompt and run:
        <pre>netsh advfirewall firewall add rule name="Stratum Mining" dir=in action=allow protocol=TCP localport=10333</pre>
        Replace <code>10333</code> with your stratum port. You may also need to allow the dashboard port (default <code>8080</code>):
        <pre>netsh advfirewall firewall add rule name="Stratum Dashboard" dir=in action=allow protocol=TCP localport=8080</pre>
      </li>
      <li><strong>"Cannot connect to node RPC"</strong> &mdash; Check that the node is running, fully synced, and RPC is enabled with matching credentials</li>
      <li><strong>"Failed to get block template"</strong> &mdash; The node may still be syncing. Wait until it catches up to the chain tip</li>
      <li><strong>Miners connect but get no work</strong> &mdash; Verify the payout address is valid for the selected coin</li>
      <li><strong>Address decode error</strong> &mdash; Make sure Bech32 HRP and version bytes match the coin. Use a preset if available</li>
    </ul>

  </div>
</div>

<script>
var PRESETS = {
  caps:         { coin_name:'Caps',         coin_ticker:'CAPS', bech32_hrp:'caps', p2pkh_version:28,  p2sh_version:29,  rpc_port:10567, stratum_port:10333, coinbase_message:'/Caps Stratum Pool/' },
  bitcoin:      { coin_name:'Bitcoin',      coin_ticker:'BTC',  bech32_hrp:'bc',   p2pkh_version:0,   p2sh_version:5,   rpc_port:8332,  stratum_port:3333,  coinbase_message:'/Stratum Pool/' },
  bitcoin_cash: { coin_name:'Bitcoin Cash', coin_ticker:'BCH',  bech32_hrp:'',     p2pkh_version:0,   p2sh_version:5,   rpc_port:8332,  stratum_port:3333,  coinbase_message:'/Stratum Pool/' },
  namecoin:     { coin_name:'Namecoin',     coin_ticker:'NMC',  bech32_hrp:'nc',   p2pkh_version:52,  p2sh_version:13,  rpc_port:8336,  stratum_port:3335,  coinbase_message:'/Stratum Pool/' },
  peercoin:     { coin_name:'Peercoin',     coin_ticker:'PPC',  bech32_hrp:'',     p2pkh_version:55,  p2sh_version:117, rpc_port:9902,  stratum_port:3336,  coinbase_message:'/Stratum Pool/' },
  digibyte:     { coin_name:'DigiByte',     coin_ticker:'DGB',  bech32_hrp:'dgb',  p2pkh_version:30,  p2sh_version:63,  rpc_port:14022, stratum_port:8881,  coinbase_message:'/Stratum Pool/' },
  bitcoin_ii:   { coin_name:'Bitcoin II',   coin_ticker:'BC2',  bech32_hrp:'bc',   p2pkh_version:0,   p2sh_version:5,   rpc_port:8337,  stratum_port:7041,  coinbase_message:'/Stratum Pool/' },
  bitcoin_silver:{ coin_name:'Bitcoin Silver',coin_ticker:'BTCS', bech32_hrp:'bs',  p2pkh_version:26,  p2sh_version:5,   rpc_port:10567, stratum_port:3334,  coinbase_message:'/Stratum Pool/' }
};

var FIELDS = ['coin_name','coin_ticker','bech32_hrp','p2pkh_version','p2sh_version','coinbase_message',
              'rpc_host','rpc_port','rpc_user','rpc_password','payout_address','stratum_port',
              'difficulty','poll_interval','dashboard_port'];
var passwordOriginal = '';

function setField(id, val) {
  var el = document.getElementById(id);
  if (el) el.value = (val === null || val === undefined) ? '' : val;
}
function getField(id) { var el = document.getElementById(id); return el ? el.value : ''; }

// Load current config
fetch('/api/config').then(function(r){ return r.json(); }).then(function(cfg){
  FIELDS.forEach(function(f){
    if (f === 'rpc_password') {
      passwordOriginal = cfg.rpc_password || '';
      setField('rpc_password', cfg.rpc_password_set ? '****' : '');
    } else {
      setField(f, cfg[f]);
    }
  });
});

// Sync theme from server (override localStorage if server has a saved preference)
fetch('/api/preferences').then(function(r){return r.json();}).then(function(p){
  if (p.theme && p.theme !== _initTheme) {
    setThemeVars(p.theme);
    try { localStorage.setItem('caps-theme', p.theme); } catch(e) {}
  }
}).catch(function(){});

// Preset selector
document.getElementById('presetSelect').addEventListener('change', function(){
  var p = PRESETS[this.value];
  if (!p) return;
  ['coin_name','coin_ticker','bech32_hrp','p2pkh_version','p2sh_version','coinbase_message','rpc_port','stratum_port'].forEach(function(f){
    setField(f, p[f]);
  });
});

// Password show/hide toggle
document.getElementById('pwToggle').addEventListener('click', function(){
  var inp = document.getElementById('rpc_password');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

// Help toggle
document.getElementById('helpToggle').addEventListener('click', function(){
  var content = document.getElementById('helpContent');
  var open = content.classList.toggle('open');
  this.innerHTML = open ? '&#9881; SETUP GUIDE &#9650;' : '&#9881; SETUP GUIDE &#9660;';
});

// Save
document.getElementById('saveBtn').addEventListener('click', function(){
  var msg = document.getElementById('statusMsg');
  msg.className = 'status-msg';
  msg.textContent = 'Saving...';

  var data = {};
  FIELDS.forEach(function(f){ data[f] = getField(f); });
  // Coerce numeric fields
  ['rpc_port','stratum_port','dashboard_port','p2pkh_version','p2sh_version','poll_interval'].forEach(function(f){
    if (data[f] !== '') data[f] = parseInt(data[f], 10);
  });
  if (data.difficulty !== '') data.difficulty = parseFloat(data.difficulty);

  // Client-side validation
  var errors = [];
  if (!data.rpc_host) errors.push('RPC Host is required');
  if (!data.rpc_port) errors.push('RPC Port is required');
  if (!data.rpc_user) errors.push('RPC User is required');
  if (!data.payout_address) errors.push('Payout Address is required');
  if (errors.length) {
    msg.className = 'status-msg err';
    msg.textContent = errors.join('; ');
    return;
  }

  fetch('/api/settings', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(data)
  }).then(function(r){ return r.json().then(function(j){ return {ok:r.ok, body:j}; }); })
    .then(function(res){
      if (res.ok) {
        msg.className = 'status-msg ok';
        msg.textContent = 'Settings saved! Restarting server...';
        setTimeout(function(){ window.location.href = '/'; }, 5000);
      } else {
        msg.className = 'status-msg err';
        msg.textContent = (res.body.errors || ['Unknown error']).join('; ');
      }
    })
    .catch(function(e){
      msg.className = 'status-msg err';
      msg.textContent = 'Network error: ' + e.message;
    });
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------
class StratumDB:
    """Thin async wrapper around sqlite3 for persisting pool data.

    All queries run via ``run_in_executor`` so the asyncio event loop is
    never blocked.  WAL journal mode allows concurrent readers/writer.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()
        # Dedicated single-thread pool (sqlite3 connections aren't thread-safe
        # even with check_same_thread=False when writes overlap)
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="db")

    # -- schema -------------------------------------------------------------

    def _create_tables(self):
        c = self._conn
        c.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL    NOT NULL,
                worker      TEXT    NOT NULL,
                difficulty  REAL    NOT NULL,
                job_height  INTEGER NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS blocks_found (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                height    INTEGER NOT NULL,
                hash      TEXT    NOT NULL,
                worker    TEXT    NOT NULL,
                timestamp REAL    NOT NULL,
                accepted  INTEGER NOT NULL DEFAULT 1
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS hashrate_samples (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL    NOT NULL,
                hashrate  REAL    NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS pool_stats (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                total_accepted  INTEGER NOT NULL DEFAULT 0,
                total_rejected  INTEGER NOT NULL DEFAULT 0,
                total_blocks    INTEGER NOT NULL DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS preferences (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        # Ensure the single stats row exists
        c.execute("INSERT OR IGNORE INTO pool_stats (id, total_accepted, total_rejected, total_blocks) VALUES (1,0,0,0)")
        c.commit()

    # -- write helpers (called via run_in_executor) -------------------------

    def _record_share(self, timestamp, worker, difficulty, job_height):
        self._conn.execute(
            "INSERT INTO shares (timestamp, worker, difficulty, job_height) VALUES (?,?,?,?)",
            (timestamp, worker, difficulty, job_height),
        )
        self._conn.execute(
            "UPDATE pool_stats SET total_accepted = total_accepted + 1 WHERE id = 1"
        )
        self._conn.commit()

    def _record_block(self, height, block_hash, worker, timestamp, accepted=1):
        self._conn.execute(
            "INSERT INTO blocks_found (height, hash, worker, timestamp, accepted) VALUES (?,?,?,?,?)",
            (height, block_hash, worker, timestamp, accepted),
        )
        self._conn.execute(
            "UPDATE pool_stats SET total_blocks = total_blocks + 1 WHERE id = 1"
        )
        self._conn.commit()

    def _record_hashrate_sample(self, timestamp, hashrate):
        self._conn.execute(
            "INSERT INTO hashrate_samples (timestamp, hashrate) VALUES (?,?)",
            (timestamp, hashrate),
        )
        self._conn.commit()

    def _save_pool_stats(self, accepted, rejected, blocks):
        self._conn.execute(
            "UPDATE pool_stats SET total_accepted=?, total_rejected=?, total_blocks=? WHERE id=1",
            (accepted, rejected, blocks),
        )
        self._conn.commit()

    def _cleanup_old_data(self, share_days=7, hashrate_days=2):
        now = time.time()
        self._conn.execute("DELETE FROM shares WHERE timestamp < ?", (now - share_days * 86400,))
        self._conn.execute("DELETE FROM hashrate_samples WHERE timestamp < ?", (now - hashrate_days * 86400,))
        self._conn.commit()

    def _set_preference(self, key, value):
        self._conn.execute(
            "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    # -- read helpers -------------------------------------------------------

    def load_preferences(self):
        rows = self._conn.execute("SELECT key, value FROM preferences").fetchall()
        return {r[0]: r[1] for r in rows}

    def get_preference(self, key, default=None):
        row = self._conn.execute(
            "SELECT value FROM preferences WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

    def load_pool_stats(self):
        row = self._conn.execute(
            "SELECT total_accepted, total_rejected, total_blocks FROM pool_stats WHERE id=1"
        ).fetchone()
        if row:
            return {"accepted": row[0], "rejected": row[1], "blocks": row[2]}
        return {"accepted": 0, "rejected": 0, "blocks": 0}

    def load_recent_blocks(self, limit=20):
        rows = self._conn.execute(
            "SELECT height, hash, worker, timestamp FROM blocks_found ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"height": r[0], "hash": r[1], "worker": r[2], "time": r[3]}
            for r in reversed(rows)
        ]

    def load_hashrate_history(self, limit=200):
        rows = self._conn.execute(
            "SELECT timestamp, hashrate FROM hashrate_samples ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [(r[0], r[1]) for r in reversed(rows)]

    # -- async wrappers -----------------------------------------------------

    async def record_share(self, timestamp, worker, difficulty, job_height):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._record_share, timestamp, worker, difficulty, job_height)

    async def record_block(self, height, block_hash, worker, timestamp, accepted=1):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._record_block, height, block_hash, worker, timestamp, accepted)

    async def record_hashrate_sample(self, timestamp, hashrate):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._record_hashrate_sample, timestamp, hashrate)

    async def save_pool_stats(self, accepted, rejected, blocks):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._save_pool_stats, accepted, rejected, blocks)

    async def cleanup_old_data(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._cleanup_old_data)

    async def set_preference(self, key, value):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._set_preference, key, value)


# ---------------------------------------------------------------------------
# Stratum Server
# ---------------------------------------------------------------------------
class StratumServer:
    def __init__(self, config):
        self.config = config
        self.rpc = RPCClient(
            config["rpc_host"],
            config["rpc_port"],
            config["rpc_user"],
            config["rpc_password"],
        )
        self.listen_port = config.get("stratum_port", 10333)
        self.payout_address = config["payout_address"]
        self.default_difficulty = config.get("difficulty", 0.001)
        self.poll_interval = config.get("poll_interval", 15)

        # Vardiff configuration
        vd = config.get("vardiff", {})
        self.vardiff_config = {
            "min_diff": vd.get("min_diff", 0.0001),
            "max_diff": vd.get("max_diff", 65536),
            "target_shares_per_min": vd.get("target_shares_per_min", 6),
            "retarget_interval": vd.get("retarget_interval", 90),
            "tolerance": vd.get("tolerance", 0.3),
        }

        # Coin-specific settings (backward-compatible defaults for Caps)
        self.coin_name = config.get("coin_name", "Caps")
        self.coin_ticker = config.get("coin_ticker", "CAPS")
        self.bech32_hrp = config.get("bech32_hrp", "caps")
        self.p2pkh_version = config.get("p2pkh_version", 28)
        self.p2sh_version = config.get("p2sh_version", 29)
        self.coinbase_message = config.get("coinbase_message", "/Caps Stratum Pool/")

        # BIP 310 version rolling — server-allowed mask
        self.allowed_version_mask = int(config.get("version_rolling_mask", "1fffe000"), 16)

        self.payout_script = address_to_script(
            self.payout_address, self.bech32_hrp,
            self.p2pkh_version, self.p2sh_version
        )
        self.extranonce1_size = 4

        self.miners: list[MinerSession] = []
        self.current_job: Job = None
        self.jobs: OrderedDict = OrderedDict()  # job_id -> Job, keep last N
        self.max_jobs = 10
        self.current_prev_hash = None
        self.last_notify_time = 0  # timestamp of last mining.notify sent
        self.notify_min_interval = config.get("notify_min_interval", 30)  # seconds

        self.stats = {"accepted": 0, "rejected": 0, "blocks": 0, "start_time": time.time()}
        self.recent_blocks = []  # last 20 found blocks
        self.dashboard_port = config.get("dashboard_port", 8080)

        # Hashrate tracking
        self.share_log = []          # [(timestamp, difficulty), ...] per accepted share
        self.hashrate_history = []   # [(timestamp, hashrate), ...] periodic snapshots

        # Cached network stats (updated by background task, never in HTTP handler)
        self._cached_net_difficulty = 0
        self._cached_net_hashrate = 0
        self._cached_local_ip = self._detect_local_ip()

        # SQLite persistence
        db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        self.db = StratumDB(os.path.join(db_dir, "stratum.db"))

    # -------------------------------------------------------------------
    @staticmethod
    def _detect_local_ip() -> str:
        """Detect local LAN IP once (no repeated socket calls)."""
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _request_restart(self):
        """Schedule a server restart after a short delay (let HTTP response flush).

        The launcher's monitor loop will auto-restart the process.
        When running directly (not via launcher), the process just exits.
        """
        import threading

        def _do_restart():
            time.sleep(1)
            log.info("Restarting server (settings changed)...")
            os._exit(0)

        t = threading.Thread(target=_do_restart, daemon=True)
        t.start()

    async def _run_forever(self, name, coro_func):
        """Run an async task forever, restarting on error."""
        while True:
            try:
                await coro_func()
            except asyncio.CancelledError:
                return
            except Exception as e:
                log.error("Background task '%s' crashed: %s — restarting in 5s", name, e)
                await asyncio.sleep(5)

    def find_job(self, job_id):
        return self.jobs.get(job_id)

    def remove_miner(self, miner):
        if miner in self.miners:
            self.miners.remove(miner)
        # Cancel the miner's handle task and abort the transport.
        # On Windows ProactorEventLoop, closing a socket with pending IOCP
        # reads can freeze the event loop.  Cancelling the task first ensures
        # the pending read is cancelled before the socket is closed.
        if miner._task and not miner._task.done():
            miner._task.cancel()
        try:
            miner.writer.transport.abort()
        except Exception:
            pass

    @staticmethod
    def diff_to_target(difficulty: float) -> int:
        """Convert mining difficulty to a uint256 target value.
        Difficulty 1 target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        """
        diff1 = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        if difficulty <= 0:
            return diff1
        return int(diff1 / difficulty)

    async def update_job(self):
        """Fetch a new block template and create a job."""
        log.debug("update_job: fetching template...")
        template = await self.rpc.acall(
            "getblocktemplate", [{"rules": ["segwit"]}]
        )
        if template is None:
            log.warning("Failed to get block template from node")
            return False
        log.debug("update_job: got template height=%d", template.get("height", 0))

        new_prev = template["previousblockhash"]
        new_height = template["height"]

        # Only create new job if the block changed or it's the first job
        if self.current_prev_hash == new_prev and self.current_job is not None:
            # Update curtime on existing job
            self.current_job.curtime = template["curtime"]
            return False

        log.info("New block template: height=%d, txs=%d, value=%.8f %s",
                 new_height, len(template.get("transactions", [])),
                 template["coinbasevalue"] / 1e8, self.coin_ticker)

        job = Job(template, self.payout_script, self.extranonce1_size,
                  self.coinbase_message)
        self.current_job = job
        self.current_prev_hash = new_prev

        # Store job for share validation
        self.jobs[job.job_id] = job
        while len(self.jobs) > self.max_jobs:
            self.jobs.popitem(last=False)

        # Notify miners of the new job.  If blocks arrive faster than
        # notify_min_interval we still send the job (to keep the connection
        # alive and give the miner work) but use clean_jobs=False so the
        # miner doesn't have to throw away in-flight hashes every few seconds.
        # clean_jobs=True is reserved for the first job or when enough time
        # has elapsed for the miner to have been working on the old job.
        now = time.time()
        elapsed = now - self.last_notify_time

        if elapsed >= self.notify_min_interval or self.last_notify_time == 0:
            await self._notify_miners(job, clean_jobs=True)
        else:
            await self._notify_miners(job, clean_jobs=False)

        return True

    async def _notify_miners(self, job: Job, clean_jobs: bool = True):
        """Push a mining.notify to every connected miner (concurrently)."""
        params = job.get_notify_params(clean_jobs=clean_jobs)
        miners_snapshot = list(self.miners)
        if not miners_snapshot:
            self.last_notify_time = time.time()
            return

        log.info("_notify_miners: sending to %d miners (clean=%s)", len(miners_snapshot), clean_jobs)

        async def _notify_one(miner):
            try:
                await asyncio.wait_for(
                    miner.send_method("mining.notify", params), timeout=5
                )
                return True
            except Exception as e:
                log.warning("_notify_one failed for %s: %s", miner.worker_name, e)
                return False

        results = await asyncio.gather(
            *[_notify_one(m) for m in miners_snapshot],
            return_exceptions=True,
        )
        dead = 0
        for miner, ok in zip(miners_snapshot, results):
            if ok is not True:
                dead += 1
                self.remove_miner(miner)
        if dead:
            log.info("_notify_miners: removed %d dead miners", dead)
        self.last_notify_time = time.time()

    async def _hashrate_sampler(self):
        """Sample pool hashrate every 10 seconds from recent shares."""
        while True:
            await asyncio.sleep(10)
            now = time.time()
            window = 60  # look at shares in last 60 seconds
            cutoff = now - window
            total_diff = sum(d for t, d in self.share_log if t >= cutoff)
            hashrate = (total_diff * (2**32)) / window
            self.hashrate_history.append((now, hashrate))
            # Trim share_log older than 120s
            self.share_log = [(t, d) for t, d in self.share_log if t >= now - 120]
            # Keep last 200 hashrate entries (~33 min)
            if len(self.hashrate_history) > 200:
                self.hashrate_history = self.hashrate_history[-200:]
            # Persist sample to DB (fire-and-forget)
            asyncio.ensure_future(self.db.record_hashrate_sample(now, hashrate))

    async def poll_loop(self):
        """Periodically poll the node for new block templates."""
        while True:
            try:
                await self.update_job()

                # Heartbeat: if no notify was sent recently (no new blocks),
                # resend the current job with an updated ntime and
                # clean_jobs=False.  This keeps the TCP connection alive and
                # prevents firmware miners (NerdMiner) from assuming the pool
                # is dead and reconnecting.
                if self.current_job and self.miners:
                    elapsed = time.time() - self.last_notify_time
                    if elapsed >= self.poll_interval:
                        # Don't override curtime with system clock — it may
                        # drift behind the node's minimum accepted time.
                        # update_job() already refreshes curtime from the
                        # node's template above.
                        await self._notify_miners(self.current_job, clean_jobs=False)

            except Exception as e:
                log.error("Error updating job: %s", e)
            await asyncio.sleep(self.poll_interval)

    async def handle_client(self, reader, writer):
        # Enable TCP keepalive to prevent Windows from killing idle connections
        sock = writer.get_extra_info("socket")
        if sock is not None:
            import socket
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Windows-specific: keepalive interval and timeout (in ms)
            try:
                sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 5000))
            except (AttributeError, OSError):
                pass
        miner = MinerSession(reader, writer, self)
        # Store the task handle so we can cancel it on forceful disconnect
        miner._task = asyncio.current_task()
        self.miners.append(miner)
        await miner.handle()

    async def start(self):
        # Install global exception handler so unhandled task errors are logged
        loop = asyncio.get_event_loop()
        def _exc_handler(loop, context):
            msg = context.get("message", "Unhandled async exception")
            exc = context.get("exception")
            log.error("ASYNC ERROR: %s — %s", msg, exc)
        loop.set_exception_handler(_exc_handler)

        log.info("=" * 60)
        log.info("C.A.P.S. S.M.S.D.")
        log.info("Cryptocurrency Acquisition & Processing System")
        log.info("Stratum Mining Services Dashboard")
        log.info("=" * 60)
        log.info("Payout address: %s", self.payout_address)
        log.info("Default difficulty: %s", self.default_difficulty)
        log.info("RPC endpoint: %s:%s", self.config["rpc_host"], self.config["rpc_port"])

        # Test RPC connection
        info = self.rpc.call("getblockchaininfo")
        if info is None:
            log.error("Cannot connect to %s node RPC. Is the node running?", self.coin_name)
            log.error("Check rpc_host, rpc_port, rpc_user, rpc_password in config.json")
            return

        log.info("Connected to %s node: chain=%s, blocks=%d", self.coin_name,
                 info.get("chain", "?"), info.get("blocks", 0))

        # Restore persisted stats from SQLite
        saved = self.db.load_pool_stats()
        self.stats["accepted"] = saved["accepted"]
        self.stats["rejected"] = saved["rejected"]
        self.stats["blocks"] = saved["blocks"]
        self.recent_blocks = self.db.load_recent_blocks()
        self.hashrate_history = self.db.load_hashrate_history()
        log.info("Restored from DB: accepted=%d blocks=%d hashrate_samples=%d",
                 saved["accepted"], saved["blocks"], len(self.hashrate_history))

        # Get initial job
        await self.update_job()
        if self.current_job is None:
            log.error("Failed to get initial block template. Ensure the node is fully synced.")
            return

        # Start background tasks (auto-restart on crash)
        asyncio.ensure_future(self._run_forever("poll_loop", self.poll_loop))
        asyncio.ensure_future(self._run_forever("hashrate_sampler", self._hashrate_sampler))
        asyncio.ensure_future(self._run_forever("network_stats", self._network_stats_updater))
        asyncio.ensure_future(self._run_forever("db_cleanup", self._db_cleanup_loop))
        asyncio.ensure_future(self._run_forever("watchdog", self._event_loop_watchdog))

        # Start stratum listener
        server = await asyncio.start_server(
            self.handle_client, "0.0.0.0", self.listen_port
        )
        log.info("Stratum server listening on port %d", self.listen_port)
        log.info("Miners can connect to: stratum+tcp://%s:%d",
                 self._cached_local_ip, self.listen_port)

        # Show all available LAN IPs so users can try alternatives
        try:
            import socket as _sock
            all_ips = []
            for info in _sock.getaddrinfo(_sock.gethostname(), None, _sock.AF_INET):
                ip = info[4][0]
                if ip not in all_ips and ip != "127.0.0.1":
                    all_ips.append(ip)
            if len(all_ips) > 1:
                log.info("All LAN IPs: %s (try each if miners can't connect)",
                         ", ".join(all_ips))
        except Exception:
            pass

        # Start dashboard HTTP server on a separate thread so it never
        # competes with the asyncio event loop.
        try:
            self._start_dashboard_thread()
            log.info("Dashboard available at: http://%s:%d",
                     self._cached_local_ip, self.dashboard_port)
        except OSError as e:
            log.warning("Could not start dashboard on port %d: %s", self.dashboard_port, e)

        if sys.platform == "win32":
            log.info("NOTE: If miners can't connect, check Windows Firewall.")
            log.info("  Run as Admin: netsh advfirewall firewall add rule "
                     'name="Stratum" dir=in action=allow protocol=TCP localport=%d',
                     self.listen_port)

        log.info("=" * 60)

        # Stats printer
        asyncio.ensure_future(self._run_forever("stats", self.stats_loop))

        async with server:
            await server.serve_forever()

    # -------------------------------------------------------------------
    # Web Dashboard (threaded HTTP server — fully isolated from event loop)
    # -------------------------------------------------------------------
    def _start_dashboard_thread(self):
        """Start a stdlib HTTP server on a daemon thread."""
        import http.server
        import threading

        stratum_server = self  # capture for the handler closure

        class Handler(http.server.BaseHTTPRequestHandler):
            def _send_json(self, code, data):
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def _send_html(self, html):
                body = html.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/api/stats":
                    self._send_json(200, stratum_server._get_dashboard_data())
                elif self.path == "/api/config":
                    try:
                        cfg = load_config()
                    except Exception:
                        cfg = {}
                    # Fill defaults for new fields
                    defaults = {
                        "coin_name": "Caps", "coin_ticker": "CAPS",
                        "bech32_hrp": "caps", "p2pkh_version": 28,
                        "p2sh_version": 29, "coinbase_message": "/Caps Stratum Pool/",
                        "rpc_host": "127.0.0.1", "rpc_port": 10567,
                        "rpc_user": "", "payout_address": "",
                        "stratum_port": 10333, "dashboard_port": 8080,
                        "difficulty": 0.001, "poll_interval": 15,
                    }
                    for k, v in defaults.items():
                        cfg.setdefault(k, v)
                    # Mask password
                    has_pw = bool(cfg.get("rpc_password"))
                    cfg["rpc_password"] = "****" if has_pw else ""
                    cfg["rpc_password_set"] = has_pw
                    self._send_json(200, cfg)
                elif self.path == "/api/preferences":
                    self._send_json(200, stratum_server.db.load_preferences())
                elif self.path == "/settings":
                    self._send_html(SETTINGS_HTML)
                elif self.path == "/":
                    self._send_html(DASHBOARD_HTML)
                else:
                    self.send_error(404)

            def do_POST(self):
                if self.path == "/api/settings":
                    try:
                        length = int(self.headers.get("Content-Length", 0))
                        raw = self.rfile.read(length)
                        data = json.loads(raw.decode("utf-8"))
                    except Exception:
                        self._send_json(400, {"errors": ["Invalid JSON body"]})
                        return

                    errors = validate_settings(data)
                    if errors:
                        self._send_json(400, {"errors": errors})
                        return

                    # Preserve existing password if masked or empty
                    pw = data.get("rpc_password", "")
                    if pw == "****" or pw == "":
                        try:
                            existing = load_config()
                            data["rpc_password"] = existing.get("rpc_password", "")
                        except Exception:
                            pass

                    # Coerce types for config.json
                    for k in ("rpc_port", "stratum_port", "dashboard_port",
                              "p2pkh_version", "p2sh_version", "poll_interval"):
                        if k in data and data[k] != "":
                            try:
                                data[k] = int(data[k])
                            except (ValueError, TypeError):
                                pass
                    if "difficulty" in data and data["difficulty"] != "":
                        try:
                            data["difficulty"] = float(data["difficulty"])
                        except (ValueError, TypeError):
                            pass

                    # Remove transient keys
                    data.pop("rpc_password_set", None)

                    try:
                        with open(CONFIG_PATH, "w") as f:
                            json.dump(data, f, indent=2)
                    except Exception as e:
                        self._send_json(500, {"errors": [f"Failed to write config: {e}"]})
                        return

                    self._send_json(200, {"ok": True})
                    stratum_server._request_restart()
                elif self.path == "/api/preferences":
                    try:
                        length = int(self.headers.get("Content-Length", 0))
                        raw = self.rfile.read(length)
                        data = json.loads(raw.decode("utf-8"))
                    except Exception:
                        self._send_json(400, {"error": "Invalid JSON"})
                        return
                    allowed = {"theme"}
                    for key, value in data.items():
                        if key in allowed and isinstance(value, str) and len(value) < 64:
                            stratum_server.db._set_preference(key, value)
                    self._send_json(200, {"ok": True})
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # suppress per-request logging

        srv = http.server.ThreadingHTTPServer(("0.0.0.0", self.dashboard_port), Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

    def _get_dashboard_data(self) -> dict:
        """Collect live stats for the dashboard API.

        Pure in-memory read — no I/O, no RPC, no await.  Network stats
        are refreshed by the ``_network_stats_updater`` background task.
        """
        now = time.time()
        uptime = int(now - self.stats["start_time"])
        hours, rem = divmod(uptime, 3600)
        mins, secs = divmod(rem, 60)

        miners_list = []
        for m in self.miners:
            if not m.authorized:
                continue  # hide miners that haven't completed handshake
            connected_secs = int(now - m.connected_at)
            ch, cr = divmod(connected_secs, 3600)
            cm, cs = divmod(cr, 60)
            miners_list.append({
                "worker": m.worker_name,
                "user_agent": m.user_agent,
                "ip": f"{m.addr[0]}:{m.addr[1]}" if m.addr else "unknown",
                "difficulty": m.difficulty,
                "shares": m.shares_accepted,
                "rejected": m.shares_rejected,
                "connected": f"{ch}h {cm}m {cs}s",
                "last_share": (
                    f"{int(now - m.last_share_time)}s ago"
                    if m.last_share_time else "never"
                ),
                "version_rolling": bool(m.version_rolling_mask),
            })

        block_height = self.current_job.height if self.current_job else 0
        current_hashrate = self.hashrate_history[-1][1] if self.hashrate_history else 0

        return {
            "server": {
                "uptime": f"{hours}h {mins}m {secs}s",
                "payout_address": self.payout_address,
                "stratum_port": self.listen_port,
                "block_height": block_height,
                "local_ip": self._cached_local_ip,
                "stratum_url": f"stratum+tcp://{self._cached_local_ip}:{self.listen_port}",
                "coin_ticker": self.coin_ticker,
            },
            "stats": {
                "miners": len(miners_list),
                "accepted": self.stats["accepted"],
                "rejected": self.stats["rejected"],
                "blocks": self.stats["blocks"],
                "current_hashrate": current_hashrate,
                "net_difficulty": self._cached_net_difficulty,
                "net_hashrate": self._cached_net_hashrate,
            },
            "miners": miners_list,
            "recent_blocks": list(reversed(self.recent_blocks)),
            "hashrate_history": [
                {"t": t, "hr": hr} for t, hr in self.hashrate_history
            ],
        }

    async def _network_stats_updater(self):
        """Fetch network difficulty/hashrate via RPC every 30s into cache."""
        while True:
            try:
                mining_info = await self.rpc.acall("getmininginfo")
                if mining_info:
                    self._cached_net_difficulty = mining_info.get("difficulty", 0)
                    self._cached_net_hashrate = mining_info.get("networkhashps", 0)
                if not self._cached_net_hashrate:
                    nh = await self.rpc.acall("getnetworkhashps")
                    if nh:
                        self._cached_net_hashrate = nh
            except Exception:
                pass
            await asyncio.sleep(30)

    async def _db_cleanup_loop(self):
        """Hourly cleanup of old shares and hashrate samples."""
        while True:
            await asyncio.sleep(3600)
            try:
                await self.db.cleanup_old_data()
                log.info("DB cleanup: removed old shares and hashrate samples")
            except Exception as e:
                log.warning("DB cleanup error: %s", e)

    async def _event_loop_watchdog(self):
        """Log a warning if the event loop is unresponsive."""
        tick = 0
        while True:
            t0 = time.time()
            await asyncio.sleep(2)
            elapsed = time.time() - t0
            tick += 1
            if tick % 5 == 0:  # every 10s
                log.info("HEARTBEAT tick=%d miners=%d accepted=%d loop_ok=%.2fs",
                         tick, len(self.miners), self.stats["accepted"], elapsed)
            if elapsed > 5:
                log.warning("EVENT LOOP STALL: slept 2s but %.1fs elapsed!", elapsed)

    async def stats_loop(self):
        """Print stats every 60 seconds."""
        while True:
            await asyncio.sleep(60)
            uptime = int(time.time() - self.stats["start_time"])
            hours, rem = divmod(uptime, 3600)
            mins, secs = divmod(rem, 60)
            log.info(
                "Stats: miners=%d accepted=%d rejected=%d blocks=%d uptime=%dh%dm%ds",
                len(self.miners),
                self.stats["accepted"],
                self.stats["rejected"],
                self.stats["blocks"],
                hours, mins, secs,
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not os.path.exists(CONFIG_PATH):
        log.error("Config file not found: %s", CONFIG_PATH)
        log.error("Please create config.json (see config.json.example)")
        sys.exit(1)

    config = load_config()

    # Validate required fields
    required = ["rpc_host", "rpc_port", "rpc_user", "rpc_password", "payout_address"]
    for field in required:
        if field not in config:
            log.error("Missing required config field: %s", field)
            sys.exit(1)

    server = StratumServer(config)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        log.info("Shutting down...")


if __name__ == "__main__":
    main()
