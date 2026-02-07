#!/usr/bin/env python3
"""
CapsMinePack Launcher
=====================
Self-contained orchestrator that starts a Caps GUI wallet + stratum mining
server with zero manual configuration.  Works on Windows and Linux.

Usage:  python launcher.py
"""

import base64
import json
import os
import platform
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(SCRIPT_DIR, "bin")
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
STRATUM_DIR = os.path.join(SCRIPT_DIR, "stratum")

STATE_FILE = os.path.join(DATA_DIR, ".minepack_state.json")
CONF_FILE = os.path.join(DATA_DIR, "caps.conf")
STRATUM_CONFIG = os.path.join(STRATUM_DIR, "config.json")

P2P_PORT = 12566
RPC_PORT = 10567
STRATUM_PORT = 10333
DASHBOARD_PORT = 8080

IS_WINDOWS = platform.system() == "Windows"
EXE = ".exe" if IS_WINDOWS else ""

CAPS_QT = os.path.join(BIN_DIR, f"caps-qt{EXE}")
CAPSD = os.path.join(BIN_DIR, f"capsd{EXE}")
CAPS_CLI = os.path.join(BIN_DIR, f"caps-cli{EXE}")

RPC_POLL_TIMEOUT = 120   # seconds to wait for RPC to come up
SHUTDOWN_TIMEOUT = 60     # seconds to wait for graceful stop

WALLET_NAME = "mining"

# ---------------------------------------------------------------------------
# Terminal colours (ANSI)
# ---------------------------------------------------------------------------
_colour_ok = False


def _init_colours():
    """Enable ANSI colours.  On Windows 10+ we flip the console mode flag."""
    global _colour_ok
    if IS_WINDOWS:
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            k32.GetConsoleMode(handle, ctypes.byref(mode))
            k32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            _colour_ok = True
        except Exception:
            _colour_ok = False
    else:
        _colour_ok = sys.stdout.isatty()


def _c(code, text):
    if _colour_ok:
        return f"\033[{code}m{text}\033[0m"
    return text


def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1", t)
def dim(t):    return _c("2", t)


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
def _ts():
    return time.strftime("%H:%M:%S")


def info(msg):
    print(f"{dim(_ts())}  {green('[OK]')}  {msg}")


def warn(msg):
    print(f"{dim(_ts())}  {yellow('[!!]')}  {msg}")


def err(msg):
    print(f"{dim(_ts())}  {red('[ERR]')} {msg}")


def step(n, total, msg):
    tag = cyan(f"[{n}/{total}]")
    print(f"{dim(_ts())}  {tag}  {msg}")


def banner():
    print()
    print(bold("  ========================================"))
    print(bold("    CapsMinePack  -  One-Click Mining"))
    print(bold("  ========================================"))
    print()


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def get_local_ip():
    """Get the LAN IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Windows firewall
# ---------------------------------------------------------------------------
def setup_firewall_rules():
    """Add Windows Firewall rules for Caps ports so users don't get prompted."""
    if not IS_WINDOWS:
        return

    rules = [
        ("Caps Node P2P", P2P_PORT),
        ("Caps Stratum Mining", STRATUM_PORT),
        ("Caps Dashboard", DASHBOARD_PORT),
    ]

    for name, port in rules:
        # Check if rule already exists
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
            capture_output=True, text=True
        )
        if check.returncode == 0 and name in check.stdout:
            continue

        # Try to add the rule (requires admin — will silently fail if not admin)
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={name}", "dir=in", "action=allow", "protocol=TCP",
             f"localport={port}", "profile=private,public"],
            capture_output=True, text=True
        )

    # Check if we actually got them added
    check = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=Caps Node P2P"],
        capture_output=True, text=True
    )
    return check.returncode == 0 and "Caps Node P2P" in check.stdout


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------
def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return None


def save_state(state):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------
def generate_rpc_creds():
    return secrets.token_hex(16), secrets.token_hex(32)


def write_caps_conf(rpc_user, rpc_password):
    os.makedirs(DATA_DIR, exist_ok=True)
    conf = (
        "# Auto-generated by CapsMinePack launcher\n"
        "server=1\n"
        f"rpcuser={rpc_user}\n"
        f"rpcpassword={rpc_password}\n"
        "rpcallowip=127.0.0.1\n"
        f"rpcport={RPC_PORT}\n"
        "listen=1\n"
        f"port={P2P_PORT}\n"
        "printtoconsole=0\n"
        "dbcache=256\n"
        "# Seed nodes for peer discovery\n"
        "addnode=174.4.45.33:12566\n"
    )
    with open(CONF_FILE, "w") as f:
        f.write(conf)


def write_stratum_config(rpc_user, rpc_password, mining_address):
    os.makedirs(STRATUM_DIR, exist_ok=True)
    cfg = {
        "rpc_host": "127.0.0.1",
        "rpc_port": RPC_PORT,
        "rpc_user": rpc_user,
        "rpc_password": rpc_password,
        "payout_address": mining_address,
        "stratum_port": STRATUM_PORT,
        "dashboard_port": DASHBOARD_PORT,
        "difficulty": 0.001,
        "poll_interval": 15,
    }
    with open(STRATUM_CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# Binary checks
# ---------------------------------------------------------------------------
def check_binaries():
    """Check that required binaries exist. Prefers caps-qt (GUI) over capsd."""
    has_qt = os.path.isfile(CAPS_QT)
    has_daemon = os.path.isfile(CAPSD)
    has_cli = os.path.isfile(CAPS_CLI)

    if not has_cli:
        err(f"Missing caps-cli{EXE} in bin/")
        err(f"Place compiled binaries in: {BIN_DIR}")
        sys.exit(1)

    if not has_qt and not has_daemon:
        err(f"Missing caps-qt{EXE} or capsd{EXE} in bin/")
        err(f"Place compiled binaries in: {BIN_DIR}")
        sys.exit(1)

    return has_qt


# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------
def start_node(use_gui):
    """Start the Caps node (GUI or daemon)."""
    if use_gui:
        args = [CAPS_QT, f"-datadir={DATA_DIR}"]
    else:
        args = [CAPSD, f"-datadir={DATA_DIR}"]
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs,
    )
    return proc


def run_cli(*cli_args):
    """Run caps-cli and return (returncode, stdout, stderr)."""
    args = [CAPS_CLI, f"-datadir={DATA_DIR}", f"-rpcport={RPC_PORT}"]
    args.extend(cli_args)
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def start_stratum():
    """Start the stratum server as a subprocess."""
    stratum_script = os.path.join(STRATUM_DIR, "stratum_server.py")
    if not os.path.isfile(stratum_script):
        err(f"Stratum server not found: {stratum_script}")
        sys.exit(1)
    args = [sys.executable, stratum_script]
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(
        args,
        cwd=STRATUM_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )
    return proc


# ---------------------------------------------------------------------------
# RPC readiness polling
# ---------------------------------------------------------------------------
def rpc_call(rpc_user, rpc_password, method, params=None):
    """Make a JSON-RPC call to the node.  Returns result or raises."""
    url = f"http://127.0.0.1:{RPC_PORT}"
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }).encode()
    auth = base64.b64encode(f"{rpc_user}:{rpc_password}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        if data.get("error"):
            raise RuntimeError(data["error"])
        return data.get("result")


def wait_for_rpc(rpc_user, rpc_password, timeout=RPC_POLL_TIMEOUT):
    """Poll getblockchaininfo until the node RPC is responsive."""
    start = time.time()
    delay = 1.0
    while time.time() - start < timeout:
        try:
            result = rpc_call(rpc_user, rpc_password, "getblockchaininfo")
            return result
        except Exception:
            pass
        time.sleep(delay)
        delay = min(delay * 1.5, 5.0)  # exponential backoff, cap at 5s
    return None


def wait_for_sync(rpc_user, rpc_password):
    """Wait until the node is out of Initial Block Download and ready to mine."""
    last_height = -1
    last_log = 0
    while True:
        try:
            bc = rpc_call(rpc_user, rpc_password, "getblockchaininfo")
        except Exception:
            time.sleep(5)
            continue

        ibd = bc.get("initialblockdownload", False)
        height = bc.get("blocks", 0)
        headers = bc.get("headers", 0)
        progress = bc.get("verificationprogress", 0)

        # If not in IBD, we're good
        if not ibd:
            return bc

        # Log progress periodically
        now = time.time()
        if now - last_log >= 10:
            if headers > 0:
                info(f"Syncing... block {height}/{headers} ({progress*100:.1f}%)")
            else:
                info(f"Syncing... block {height}, waiting for peers...")
            last_log = now

        if height > last_height:
            last_height = height

        time.sleep(3)


def wait_for_ready(rpc_user, rpc_password):
    """Wait until getblocktemplate actually works (node synced + has connections)."""
    attempts = 0
    while True:
        try:
            rpc_call(rpc_user, rpc_password, "getblocktemplate", [{"rules": ["segwit"]}])
            return True
        except Exception as e:
            err_msg = str(e)
            attempts += 1
            if attempts % 10 == 1:
                if "downloading" in err_msg.lower() or "ibd" in err_msg.lower():
                    info("Node still syncing, waiting for block download to complete...")
                elif "not connected" in err_msg.lower() or "no connections" in err_msg.lower():
                    info("Waiting for peer connections...")
                else:
                    info(f"Waiting for node to be ready for mining... ({err_msg[:80]})")
            time.sleep(5)


# ---------------------------------------------------------------------------
# Wallet management
# ---------------------------------------------------------------------------
def ensure_wallet(rpc_user, rpc_password):
    """Create or load the mining wallet, return True on success."""
    # Try creating
    rc, out, stderr = run_cli("createwallet", WALLET_NAME)
    if rc == 0:
        info(f"Created wallet: {WALLET_NAME}")
        return True
    # Already exists -- try loading
    if "already exists" in stderr.lower() or "already exists" in out.lower():
        rc2, out2, stderr2 = run_cli("loadwallet", WALLET_NAME)
        if rc2 == 0 or "already loaded" in stderr2.lower() or "already loaded" in out2.lower():
            info(f"Loaded existing wallet: {WALLET_NAME}")
            return True
    # Already loaded is also fine
    if "already loaded" in stderr.lower() or "already loaded" in out.lower():
        info(f"Wallet already loaded: {WALLET_NAME}")
        return True
    err(f"Failed to create/load wallet: {stderr or out}")
    return False


def generate_address():
    """Generate a new bech32 mining address."""
    rc, out, stderr = run_cli(f"-rpcwallet={WALLET_NAME}", "getnewaddress", "", "bech32")
    if rc == 0 and out:
        return out
    err(f"Failed to generate address: {stderr or out}")
    return None


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------
_node_proc = None
_stratum_proc = None
_shutting_down = False
_using_gui = False


def shutdown(signum=None, frame=None):
    global _shutting_down
    if _shutting_down:
        return
    _shutting_down = True
    print()
    warn("Shutting down...")

    # Stop stratum first
    if _stratum_proc and _stratum_proc.poll() is None:
        info("Stopping stratum server...")
        _stratum_proc.terminate()
        try:
            _stratum_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _stratum_proc.kill()
        info("Stratum server stopped.")

    # Stop node gracefully via CLI
    if _node_proc and _node_proc.poll() is None:
        info("Stopping Caps node (caps-cli stop)...")
        try:
            run_cli("stop")
        except Exception:
            pass
        # Wait for node to exit
        try:
            _node_proc.wait(timeout=SHUTDOWN_TIMEOUT)
            info("Caps node stopped.")
        except subprocess.TimeoutExpired:
            warn("Node did not stop in time, force killing...")
            _node_proc.kill()
            _node_proc.wait(timeout=5)
            info("Caps node force-killed.")

    info("Goodbye!")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Stratum output reader (non-blocking, prints stratum logs)
# ---------------------------------------------------------------------------
def drain_stratum_output(proc):
    """Read available output from the stratum subprocess (non-blocking)."""
    import select
    if proc.stdout is None:
        return
    if IS_WINDOWS:
        pass
    else:
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], 0)
            if not ready:
                break
            line = proc.stdout.readline()
            if not line:
                break
            print(dim("  [stratum] ") + line.decode("utf-8", errors="replace").rstrip())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global _node_proc, _stratum_proc, _using_gui

    _init_colours()
    banner()

    # Install signal handlers
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Check binaries exist — prefer GUI if available
    has_gui = check_binaries()
    _using_gui = has_gui

    if _using_gui:
        info(f"Found caps-qt{EXE} - will launch GUI wallet")
    else:
        info(f"No caps-qt{EXE} found - using headless daemon (capsd)")

    # --- Firewall setup (Windows) ---
    if IS_WINDOWS:
        info("Configuring Windows Firewall rules...")
        fw_ok = setup_firewall_rules()
        if fw_ok:
            info("Firewall rules added for ports "
                 f"{P2P_PORT}, {STRATUM_PORT}, {DASHBOARD_PORT}")
        else:
            warn("Could not add firewall rules automatically.")
            warn("If Windows shows a firewall prompt, click 'Allow Access'.")
            warn("Or run this launcher as Administrator to set rules automatically.")
        print()

    state = load_state()
    is_first_run = state is None

    if is_first_run:
        total_steps = 8
        # ----- FIRST RUN -----
        info("First run detected - setting up...")
        print()

        # Step 1: Generate RPC credentials
        step(1, total_steps, "Generating secure RPC credentials...")
        rpc_user, rpc_password = generate_rpc_creds()
        info(f"RPC user: {rpc_user[:8]}...")

        # Step 2: Write caps.conf
        step(2, total_steps, "Writing node configuration...")
        write_caps_conf(rpc_user, rpc_password)
        info(f"Config written to: {CONF_FILE}")

        # Step 3: Start node (GUI or daemon)
        if _using_gui:
            step(3, total_steps, "Launching Caps GUI wallet...")
        else:
            step(3, total_steps, "Starting Caps node...")
        _node_proc = start_node(_using_gui)
        info(f"Node started (PID {_node_proc.pid})")
        if _using_gui:
            info("The Caps wallet window should appear shortly.")
            info("You can use the GUI to manage your wallet, view transactions, etc.")

        # Step 4: Wait for RPC
        step(4, total_steps, "Waiting for node RPC to become available...")
        blockchain_info = wait_for_rpc(rpc_user, rpc_password)
        if blockchain_info is None:
            err(f"Node RPC did not respond within {RPC_POLL_TIMEOUT}s")
            err(f"Check {os.path.join(DATA_DIR, 'debug.log')} for details")
            if _node_proc.poll() is not None:
                err(f"Node process exited with code {_node_proc.returncode}")
            shutdown()
            return
        info(f"Node RPC online! chain={blockchain_info.get('chain', '?')}, "
             f"blocks={blockchain_info.get('blocks', 0)}")

        # Step 5: Wait for sync to complete
        step(5, total_steps, "Waiting for blockchain sync to complete...")
        if blockchain_info.get("initialblockdownload", False):
            info("Node is syncing the blockchain, this may take a while...")
            if _using_gui:
                info("You can watch sync progress in the GUI status bar too.")
            blockchain_info = wait_for_sync(rpc_user, rpc_password)
        info(f"Blockchain synced! height={blockchain_info.get('blocks', 0)}")

        # Step 6: Create wallet
        step(6, total_steps, "Creating mining wallet...")
        if not ensure_wallet(rpc_user, rpc_password):
            shutdown()
            return

        # Step 7: Generate mining address
        step(7, total_steps, "Generating mining address...")
        mining_address = generate_address()
        if not mining_address:
            shutdown()
            return
        info(f"Mining address: {green(mining_address)}")

        # Save state
        state = {
            "rpc_user": rpc_user,
            "rpc_password": rpc_password,
            "mining_address": mining_address,
        }
        save_state(state)

        # Step 8: Write stratum config, wait for mining readiness, start stratum
        step(8, total_steps, "Starting stratum mining server...")
        write_stratum_config(rpc_user, rpc_password, mining_address)
        info("Verifying node is ready for mining...")
        wait_for_ready(rpc_user, rpc_password)
        _stratum_proc = start_stratum()
        info(f"Stratum server started (PID {_stratum_proc.pid})")

    else:
        total_steps = 4
        # ----- SUBSEQUENT RUN -----
        rpc_user = state["rpc_user"]
        rpc_password = state["rpc_password"]
        mining_address = state["mining_address"]

        info("Existing configuration found, resuming...")
        info(f"Mining address: {green(mining_address)}")
        print()

        # Ensure caps.conf still exists (might have been deleted)
        if not os.path.exists(CONF_FILE):
            write_caps_conf(rpc_user, rpc_password)

        # Step 1: Start node
        if _using_gui:
            step(1, total_steps, "Launching Caps GUI wallet...")
        else:
            step(1, total_steps, "Starting Caps node...")
        _node_proc = start_node(_using_gui)
        info(f"Node started (PID {_node_proc.pid})")
        if _using_gui:
            info("The Caps wallet window should appear shortly.")

        # Step 2: Wait for RPC
        step(2, total_steps, "Waiting for node RPC...")
        blockchain_info = wait_for_rpc(rpc_user, rpc_password)
        if blockchain_info is None:
            err(f"Node RPC did not respond within {RPC_POLL_TIMEOUT}s")
            err(f"Check {os.path.join(DATA_DIR, 'debug.log')} for details")
            shutdown()
            return
        info(f"Node RPC online! chain={blockchain_info.get('chain', '?')}, "
             f"blocks={blockchain_info.get('blocks', 0)}")

        # Step 3: Wait for sync + load wallet
        step(3, total_steps, "Waiting for blockchain sync...")
        if blockchain_info.get("initialblockdownload", False):
            info("Node is syncing the blockchain, this may take a while...")
            blockchain_info = wait_for_sync(rpc_user, rpc_password)
        info(f"Blockchain synced! height={blockchain_info.get('blocks', 0)}")

        # Load wallet
        ensure_wallet(rpc_user, rpc_password)

        # Step 4: Start stratum server
        step(4, total_steps, "Starting stratum mining server...")
        write_stratum_config(rpc_user, rpc_password, mining_address)
        info("Verifying node is ready for mining...")
        wait_for_ready(rpc_user, rpc_password)
        _stratum_proc = start_stratum()
        info(f"Stratum server started (PID {_stratum_proc.pid})")

    # ----- RUNNING -----
    local_ip = get_local_ip()

    print()
    print(bold("  ========================================"))
    print(bold("    All systems operational!"))
    print(bold("  ========================================"))
    print()

    if _using_gui:
        info("Caps GUI wallet is running - use it to manage your wallet,")
        info("  view transactions, and check your balance.")
        print()

    info(f"Mining address:  {green(mining_address)}")
    print()

    print(bold("  --- Connect Your Miners ---"))
    print()
    info(f"  Stratum URL:   {bold(f'stratum+tcp://{local_ip}:{STRATUM_PORT}')}")
    info(f"  Worker:        {dim('anything (e.g. worker1)')}")
    info(f"  Password:      {dim('anything (e.g. x)')}")
    print()

    print(bold("  --- Web Dashboard ---"))
    print()
    info(f"  Local:         http://localhost:{DASHBOARD_PORT}")
    info(f"  Network:       http://{local_ip}:{DASHBOARD_PORT}")
    print()

    print(bold("  --- Ports ---"))
    print()
    info(f"  {P2P_PORT}  P2P        {dim('(other Caps nodes)')}")
    info(f"  {RPC_PORT}  RPC        {dim('(localhost only)')}")
    info(f"  {STRATUM_PORT}  Stratum    {dim('(miners connect here)')}")
    info(f"  {DASHBOARD_PORT}   Dashboard  {dim('(web browser)')}")
    print()

    info(f"Node log: {os.path.join(DATA_DIR, 'debug.log')}")
    print()

    if _using_gui:
        info(dim("Close the Caps wallet window or press Ctrl+C here to stop."))
    else:
        info(dim("Press Ctrl+C to stop everything."))
    print()

    # Monitor loop -- check both processes, shut down if either crashes
    try:
        while True:
            time.sleep(2)

            # Check node (GUI or daemon)
            if _node_proc and _node_proc.poll() is not None:
                if _using_gui:
                    # User closed the GUI window -- that's a normal exit
                    info("Caps wallet closed.")
                    shutdown()
                    return
                else:
                    err(f"Caps node exited unexpectedly (code {_node_proc.returncode})")
                    err(f"Check {os.path.join(DATA_DIR, 'debug.log')} for details")
                    shutdown()
                    return

            # Check stratum — auto-restart if it crashes
            if _stratum_proc and _stratum_proc.poll() is not None:
                err(f"Stratum server exited unexpectedly (code {_stratum_proc.returncode})")
                if _stratum_proc.stdout:
                    remaining = _stratum_proc.stdout.read()
                    if remaining:
                        for line in remaining.decode("utf-8", errors="replace").splitlines()[-5:]:
                            err(f"  {line}")
                warn("Restarting stratum server in 3 seconds...")
                time.sleep(3)
                _stratum_proc = start_stratum()
                info(f"Stratum server restarted (PID {_stratum_proc.pid})")

            # Drain stratum output on non-Windows
            if not IS_WINDOWS and _stratum_proc:
                drain_stratum_output(_stratum_proc)

    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
