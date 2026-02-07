#!/usr/bin/env python3
"""
Caps Stratum v1 Mining Server
Asyncio-based Stratum server for SHA-256d mining on the Caps network.
Supports Nerdminer, cgminer, and other Stratum v1 compatible miners.
"""

import asyncio
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


def address_to_script(address: str) -> bytes:
    """Convert a Caps address to its output script (P2PKH or P2SH)."""
    import base64

    # Try bech32 first
    if address.lower().startswith("caps1"):
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

    # Base58Check decode
    raw = base58_decode_check(address)
    if raw is None:
        raise ValueError(f"Cannot decode address: {address}")

    version = raw[0]
    payload = raw[1:]
    if version == 0x1C:  # P2PKH (Caps mainnet)
        return bytes([0x76, 0xA9, 0x14]) + payload + bytes([0x88, 0xAC])
    elif version == 0x1D:  # P2SH (Caps mainnet)
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
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                if data.get("error"):
                    log.error("RPC error: %s", data["error"])
                    return None
                return data.get("result")
        except Exception as e:
            log.error("RPC call %s failed: %s", method, e)
            return None

    async def acall(self, method, params=None):
        """Async wrapper — runs the blocking HTTP call in a thread so the
        asyncio event loop stays responsive for miner I/O."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._call_sync, method, params)

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

    def __init__(self, template: dict, payout_script: bytes, extranonce1_size: int):
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
        coinbase_message = b"/Caps Stratum Pool/"
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
        self.connected_at = time.time()
        self.shares_accepted = 0
        self.last_share_time = None

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
                data = await self.reader.read(4096)
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
            self.writer.close()

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
                # Accept version rolling — the miner will modify version bits
                # to expand nonce space. We store the mask so we can apply it
                # when reconstructing block headers for submission.
                mask = ext_params.get("version-rolling.mask", "1fffe000")
                self.version_rolling_mask = int(mask, 16)
                result["version-rolling"] = True
                result["version-rolling.mask"] = mask
                log.info("Version rolling enabled for %s (mask: %s)", self.addr, mask)
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

        # Pick difficulty based on miner type
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
        """Honor the miner's suggested difficulty if reasonable."""
        if params and isinstance(params[0], (int, float)) and params[0] > 0:
            suggested = params[0]
            self.difficulty = suggested
            log.info("Miner %s suggested difficulty %s, accepted", self.worker_name, suggested)
            await self.send_method("mining.set_difficulty", [self.difficulty])

    async def handle_authorize(self, msg_id, params):
        self.worker_name = params[0] if params else "unknown"
        self.authorized = True
        log.info("Miner authorized: %s", self.worker_name)
        await self.send_result(msg_id, True)

    async def handle_submit(self, msg_id, params):
        """Handle mining.submit.

        Standard:        [worker, job_id, extranonce2, ntime, nonce]
        Version-rolling: [worker, job_id, extranonce2, ntime, nonce, version]
        """
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

        # Skip if we already found a block for this job
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
            header_version = job.version ^ rolled_bits
        else:
            header_version = job.version

        self.server.stats["accepted"] += 1
        self.shares_accepted += 1
        self.last_share_time = time.time()
        self.server.share_log.append((time.time(), self.difficulty))
        await self.send_result(msg_id, True)

        # Persist share to DB (fire-and-forget)
        asyncio.ensure_future(self.server.db.record_share(
            time.time(), self.worker_name, self.difficulty, job.height
        ))

        # Build header using correct byte ordering:
        # - ntime: BE hex → LE bytes (reversed)
        # - nonce: reversed (miners send in display order, header needs LE)
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
                result = await self.server.rpc.acall("submitblock", [block_hex])
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
                asyncio.ensure_future(self.server.update_job())
        except Exception as e:
            log.debug("Block check failed: %s", e)

    async def send_result(self, msg_id, result, error=None):
        msg = {"id": msg_id, "result": result, "error": error}
        await self._send(msg)

    async def send_method(self, method, params):
        msg = {"id": None, "method": method, "params": params}
        await self._send(msg)

    async def _send(self, msg):
        try:
            data = json.dumps(msg) + "\n"
            self.writer.write(data.encode())
            await self.writer.drain()
        except (ConnectionError, OSError):
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
  --pip-amber: #ffc107;
  --pip-red: #ff3d3d;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background: var(--pip-bg);
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
    rgba(0, 0, 0, 0.15) 2px,
    rgba(0, 0, 0, 0.15) 4px
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
  text-shadow: var(--pip-glow), 0 0 20px rgba(20, 254, 23, 0.2);
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
  grid-template-columns: repeat(3, 1fr);
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
  border-bottom: 1px solid rgba(20, 254, 23, 0.08);
  white-space: nowrap;
}

tbody tr:hover {
  background: rgba(20, 254, 23, 0.06);
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
  background: rgba(20,254,23,0.06);
  border: 1px solid var(--pip-green);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 20px;
  box-shadow: 0 0 12px rgba(20,254,23,0.08);
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
  color: rgba(20,254,23,0.6);
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
  border: 1px solid rgba(20,254,23,0.2);
  user-select: all;
  cursor: pointer;
}
.connect-value:hover {
  background: rgba(20,254,23,0.12);
  border-color: var(--pip-green);
}
.connect-hint {
  color: rgba(20,254,23,0.4);
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
  box-shadow: 0 0 50px rgba(20, 254, 23, 0.5), inset 0 0 30px rgba(20, 254, 23, 0.1);
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
  from { text-shadow: 0 0 10px rgba(20, 254, 23, 0.5); }
  to { text-shadow: 0 0 30px rgba(20, 254, 23, 0.9), 0 0 50px rgba(20, 254, 23, 0.5); }
}

/* Responsive */
@media (max-width: 700px) {
  .stats-bar { grid-template-columns: repeat(2, 1fr); }
  .header h1 { font-size: 18px; letter-spacing: 2px; }
  table { font-size: 11px; }
  thead th, tbody td { padding: 6px 6px; }
  .connect-row { flex-direction: column; align-items: flex-start; gap: 2px; }
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
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
          <th>Shares</th>
          <th>Connected</th>
          <th>Last Share</th>
        </tr>
      </thead>
      <tbody id="minersTable">
        <tr><td colspan="8" class="no-data">No miners connected</td></tr>
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
    <div>CAPS Stratum Server &bull; Vault-Tec Industries</div>
  </div>
</div>

<script>
function formatTime(ts) {
  const d = new Date(ts * 1000);
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

  // Clear
  ctx.clearRect(0, 0, w, h);

  var padL = 80, padR = 15, padT = 10, padB = 25;
  var gw = w - padL - padR;
  var gh = h - padT - padB;

  if (!history || history.length < 2) {
    ctx.fillStyle = 'rgba(20,254,23,0.3)';
    ctx.font = '12px "Share Tech Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for data...', w / 2, h / 2);
    return;
  }

  // Only show last 30 min of data to avoid ramp-up compression
  var cutoff = history[history.length - 1].t - 1800;
  history = history.filter(function(p) { return p.t >= cutoff; });
  if (history.length < 2) {
    ctx.fillStyle = 'rgba(20,254,23,0.3)';
    ctx.font = '12px "Share Tech Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for data...', w / 2, h / 2);
    return;
  }

  var hrs = history.map(function(p) { return p.hr; });
  var times = history.map(function(p) { return p.t; });
  var maxHr = Math.max.apply(null, hrs);
  var minHr = Math.min.apply(null, hrs);
  if (maxHr <= 0) maxHr = 1;

  // Use a floor-to-ceiling range so axis labels match the visible line
  // Add 15% headroom above max and floor at 0 if min is close to 0
  var axisMin = 0;
  if (minHr > maxHr * 0.5) axisMin = minHr * 0.85;  // zoom in if line is stable
  var axisMax = maxHr * 1.15;

  var tMin = times[0];
  var tMax = times[times.length - 1];
  var tRange = tMax - tMin;
  if (tRange <= 0) tRange = 1;

  // Grid lines
  ctx.strokeStyle = 'rgba(20,254,23,0.1)';
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
  ctx.fillStyle = 'rgba(20,254,23,0.5)';
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
    points.push({ x: x, y: y });
  }

  // Filled area
  ctx.beginPath();
  ctx.moveTo(points[0].x, padT + gh);
  for (var i = 0; i < points.length; i++) {
    ctx.lineTo(points[i].x, points[i].y);
  }
  ctx.lineTo(points[points.length - 1].x, padT + gh);
  ctx.closePath();
  var grad = ctx.createLinearGradient(0, padT, 0, padT + gh);
  grad.addColorStop(0, 'rgba(20,254,23,0.25)');
  grad.addColorStop(1, 'rgba(20,254,23,0.02)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Line with glow
  ctx.shadowColor = 'rgba(20,254,23,0.6)';
  ctx.shadowBlur = 6;
  ctx.strokeStyle = '#14fe17';
  ctx.lineWidth = 2;
  ctx.beginPath();
  for (var i = 0; i < points.length; i++) {
    if (i === 0) ctx.moveTo(points[i].x, points[i].y);
    else ctx.lineTo(points[i].x, points[i].y);
  }
  ctx.stroke();
  ctx.shadowBlur = 0;
}

async function refresh() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();

    document.getElementById('blockHeight').textContent = d.server.block_height;
    document.getElementById('stratumPort').textContent = d.server.stratum_port;
    document.getElementById('statMiners').textContent = d.stats.miners;
    document.getElementById('statAccepted').textContent = d.stats.accepted.toLocaleString();
    document.getElementById('statBlocks').textContent = d.stats.blocks;

    // Check for new blocks and show notification
    if (lastBlockCount > 0 && d.stats.blocks > lastBlockCount && d.recent_blocks.length > 0) {
      var latestBlock = d.recent_blocks[0];
      showBlockNotification(latestBlock.height, latestBlock.worker);
    }
    lastBlockCount = d.stats.blocks;
    document.getElementById('statUptime').textContent = d.server.uptime;
    document.getElementById('payoutAddr').textContent = d.server.payout_address;
    document.getElementById('statNetDiff').textContent = d.stats.net_difficulty ? formatSI(d.stats.net_difficulty) : '---';
    document.getElementById('statNetHash').textContent = d.stats.net_hashrate ? formatHashrate(d.stats.net_hashrate) : '---';
    if (d.server.stratum_url) {
      document.getElementById('stratumUrl').textContent = d.server.stratum_url;
      document.getElementById('stratumUrl').title = d.server.stratum_url;
    }

    // Hashrate graph
    drawHashrateGraph(d.hashrate_history);
    document.getElementById('currentHashrate').textContent = formatHashrate(d.stats.current_hashrate || 0);

    // Miners table
    const mt = document.getElementById('minersTable');
    if (d.miners.length === 0) {
      mt.innerHTML = '<tr><td colspan="8" class="no-data">No miners connected</td></tr>';
    } else {
      mt.innerHTML = d.miners.map(m =>
        '<tr>' +
        '<td><span class="status-dot"></span></td>' +
        '<td>' + m.worker + '</td>' +
        '<td>' + m.user_agent + '</td>' +
        '<td>' + m.ip + '</td>' +
        '<td>' + m.difficulty + '</td>' +
        '<td>' + m.shares + '</td>' +
        '<td>' + m.connected + '</td>' +
        '<td>' + m.last_share + '</td>' +
        '</tr>'
      ).join('');
    }

    // Blocks table
    const bt = document.getElementById('blocksTable');
    if (d.recent_blocks.length === 0) {
      bt.innerHTML = '<tr><td colspan="4" class="no-data">No blocks found yet</td></tr>';
    } else {
      bt.innerHTML = d.recent_blocks.map(b =>
        '<tr>' +
        '<td>' + b.height + '</td>' +
        '<td class="hash-cell" title="' + b.hash + '">' + truncHash(b.hash) + '</td>' +
        '<td>' + b.worker + '</td>' +
        '<td>' + formatTime(b.time) + '</td>' +
        '</tr>'
      ).join('');
    }
  } catch (e) {
    console.error('Dashboard refresh failed:', e);
  }
}

var lastBlockCount = 0;

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

    # -- read helpers -------------------------------------------------------

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
        await loop.run_in_executor(None, self._record_share, timestamp, worker, difficulty, job_height)

    async def record_block(self, height, block_hash, worker, timestamp, accepted=1):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._record_block, height, block_hash, worker, timestamp, accepted)

    async def record_hashrate_sample(self, timestamp, hashrate):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._record_hashrate_sample, timestamp, hashrate)

    async def save_pool_stats(self, accepted, rejected, blocks):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._save_pool_stats, accepted, rejected, blocks)

    async def cleanup_old_data(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._cleanup_old_data)


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

        self.payout_script = address_to_script(self.payout_address)
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

    def find_job(self, job_id):
        return self.jobs.get(job_id)

    def remove_miner(self, miner):
        if miner in self.miners:
            self.miners.remove(miner)

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
        template = await self.rpc.acall(
            "getblocktemplate", [{"rules": ["segwit"]}]
        )
        if template is None:
            log.warning("Failed to get block template from node")
            return False

        new_prev = template["previousblockhash"]
        new_height = template["height"]

        # Only create new job if the block changed or it's the first job
        if self.current_prev_hash == new_prev and self.current_job is not None:
            # Update curtime on existing job
            self.current_job.curtime = template["curtime"]
            return False

        log.info("New block template: height=%d, txs=%d, value=%.8f CAPS",
                 new_height, len(template.get("transactions", [])),
                 template["coinbasevalue"] / 1e8)

        job = Job(template, self.payout_script, self.extranonce1_size)
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
        """Push a mining.notify to every connected miner."""
        params = job.get_notify_params(clean_jobs=clean_jobs)
        for miner in list(self.miners):
            try:
                await miner.send_method("mining.notify", params)
            except Exception:
                pass
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
        self.miners.append(miner)
        await miner.handle()

    async def start(self):
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
            log.error("Cannot connect to Caps node RPC. Is the node running?")
            log.error("Check rpc_host, rpc_port, rpc_user, rpc_password in config.json")
            return

        log.info("Connected to Caps node: chain=%s, blocks=%d",
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

        # Start polling loop
        asyncio.ensure_future(self.poll_loop())

        # Start hashrate sampler
        asyncio.ensure_future(self._hashrate_sampler())

        # Start background network stats updater (avoids RPC in HTTP handler)
        asyncio.ensure_future(self._network_stats_updater())

        # Start DB cleanup loop (hourly)
        asyncio.ensure_future(self._db_cleanup_loop())

        # Start stratum listener
        server = await asyncio.start_server(
            self.handle_client, "0.0.0.0", self.listen_port
        )
        log.info("Stratum server listening on port %d", self.listen_port)
        log.info("Miners can connect to: stratum+tcp://<your-ip>:%d", self.listen_port)

        # Start dashboard HTTP server
        try:
            dashboard_server = await asyncio.start_server(
                self._handle_http, "0.0.0.0", self.dashboard_port
            )
            log.info("Dashboard available at: http://localhost:%d", self.dashboard_port)
        except OSError as e:
            log.warning("Could not start dashboard on port %d: %s", self.dashboard_port, e)
            dashboard_server = None

        log.info("=" * 60)

        # Stats printer
        asyncio.ensure_future(self.stats_loop())

        if dashboard_server:
            async with server, dashboard_server:
                await asyncio.gather(
                    server.serve_forever(),
                    dashboard_server.serve_forever(),
                )
        else:
            async with server:
                await server.serve_forever()

    # -------------------------------------------------------------------
    # Web Dashboard
    # -------------------------------------------------------------------
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
            connected_secs = int(now - m.connected_at)
            ch, cr = divmod(connected_secs, 3600)
            cm, cs = divmod(cr, 60)
            miners_list.append({
                "worker": m.worker_name,
                "user_agent": m.user_agent,
                "ip": f"{m.addr[0]}:{m.addr[1]}" if m.addr else "unknown",
                "difficulty": m.difficulty,
                "shares": m.shares_accepted,
                "connected": f"{ch}h {cm}m {cs}s",
                "last_share": (
                    f"{int(now - m.last_share_time)}s ago"
                    if m.last_share_time else "never"
                ),
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
            },
            "stats": {
                "miners": len(self.miners),
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

    async def _handle_http(self, reader, writer):
        """Minimal async HTTP handler for the dashboard."""
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not request_line:
                return

            # Read remaining headers (discard)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in (b"\r\n", b"\n", b""):
                    break

            request_str = request_line.decode("utf-8", errors="replace").strip()
            parts = request_str.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            if method == "GET" and path == "/api/stats":
                body = json.dumps(self._get_dashboard_data()).encode("utf-8")
                header = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(header.encode() + body)
            elif method == "GET" and path == "/":
                body = DASHBOARD_HTML.encode("utf-8")
                header = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(header.encode() + body)
            else:
                body = b"404 Not Found"
                header = (
                    "HTTP/1.1 404 Not Found\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(header.encode() + body)

            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

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
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Shutting down...")


if __name__ == "__main__":
    main()
