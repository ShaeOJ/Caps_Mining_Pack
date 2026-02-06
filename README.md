# CAPS MINING PACK

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗    ████████╗███████╗ ██████╗       ║
║   ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝    ╚══██╔══╝██╔════╝██╔════╝       ║
║   ██║   ██║███████║██║   ██║██║     ██║          ██║   █████╗  ██║            ║
║   ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║          ██║   ██╔══╝  ██║            ║
║    ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║          ██║   ███████╗╚██████╗       ║
║     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝          ╚═╝   ╚══════╝ ╚═════╝       ║
║                                                                               ║
║                    C A P S   M I N I N G   P A C K                            ║
║                                                                               ║
║           "Preparing for the future... one block at a time."                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## VAULT-TEC APPROVED MINING SOLUTION

Welcome, Vault Dweller! You have been selected to participate in Vault-Tec's
revolutionary **CAPS Mining Initiative**. This self-contained mining package
provides everything you need to secure your future in the post-apocalyptic economy.

---

## FEATURES

```
┌─────────────────────────────────────────────────────────────────┐
│  [✓] One-Click Deployment    - No manual configuration needed  │
│  [✓] Built-in Stratum Pool   - Mine solo or with your vault    │
│  [✓] Web Dashboard           - Monitor your operations         │
│  [✓] Auto Wallet Creation    - Secure your CAPS automatically  │
│  [✓] Windows & Linux Support - Works in any vault              │
└─────────────────────────────────────────────────────────────────┘
```

---

## REQUIREMENTS

Before emerging from your vault, ensure you have:

- **Python 3.8+** installed
- **Caps Node Binaries** (`caps-qt.exe` or `capsd.exe` + `caps-cli.exe`)
- **A functioning terminal** (Command Prompt, PowerShell, or Bash)

---

## INSTALLATION

### Step 1: Acquire the Package

```bash
git clone https://github.com/ShaeOJ/Caps_Mining_Pack.git
cd Caps_Mining_Pack
```

### Step 2: Obtain Node Binaries

Place your compiled Caps binaries in the `bin/` directory:

```
Caps_Mining_Pack/
├── bin/
│   ├── caps-qt.exe      (GUI wallet - preferred)
│   ├── capsd.exe        (Headless daemon - alternative)
│   └── caps-cli.exe     (CLI tool - required)
├── stratum/
│   └── stratum_server.py
└── launcher.py
```

### Step 3: Launch the System

```bash
python launcher.py
```

That's it! The launcher will:
1. Start the Caps node
2. Create a mining wallet (if needed)
3. Generate a payout address
4. Launch the Stratum mining server
5. Open the web dashboard

---

## CONNECTING MINERS

Once the system is running, connect your mining hardware:

```
┌──────────────────────────────────────────────────────────────────┐
│                     STRATUM CONNECTION                           │
├──────────────────────────────────────────────────────────────────┤
│  URL:       stratum+tcp://<YOUR-IP>:10333                        │
│  Username:  <anything>.<worker_name>                             │
│  Password:  x                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### Supported Mining Hardware

| Device Type     | Difficulty | Status        |
|-----------------|------------|---------------|
| NerdMiner       | 0.001      | SUPPORTED     |
| BitAxe          | Auto       | SUPPORTED     |
| ASIC Miners     | Auto       | SUPPORTED     |
| GPU Miners      | Auto       | SUPPORTED     |

---

## WEB DASHBOARD

Access your mining operations at:

```
http://localhost:8080
```

The dashboard displays:
- **Block Height** - Current chain height
- **Connected Miners** - Active workers
- **Pool Hashrate** - Combined mining power
- **Network Hashrate** - Total network power
- **Blocks Found** - Your discoveries
- **Hashrate Graph** - Visual performance history

---

## NETWORK PORTS

```
┌─────────────────────────────────────────────────────────────────┐
│  PORT      │  SERVICE           │  PURPOSE                      │
├─────────────────────────────────────────────────────────────────┤
│  12566     │  P2P Network       │  Node-to-node communication   │
│  10567     │  RPC (localhost)   │  Node control interface       │
│  10333     │  Stratum           │  Miner connections            │
│  8080      │  Dashboard         │  Web monitoring interface     │
└─────────────────────────────────────────────────────────────────┘
```

---

## DIRECTORY STRUCTURE

```
Caps_Mining_Pack/
├── bin/                    # Node binaries (user-provided)
│   ├── caps-qt.exe
│   ├── capsd.exe
│   └── caps-cli.exe
├── data/                   # Runtime data (auto-generated)
│   ├── blocks/            # Blockchain data
│   ├── chainstate/        # UTXO database
│   ├── wallets/           # Your wallets
│   └── caps.conf          # Node configuration
├── stratum/
│   ├── stratum_server.py  # Mining pool server
│   └── config.json        # Pool configuration
├── launcher.py            # One-click launcher
└── README.md              # This document
```

---

## TROUBLESHOOTING

### "Cannot connect to RPC"
The node is still starting. Wait 30-60 seconds and try again.

### "Failed to get block template"
The node is still syncing. Wait for initial block download to complete.

### "Miner keeps disconnecting"
Check your firewall settings. Ensure port 10333 is open.

### "No blocks being found"
- Verify your miner is submitting shares (check dashboard)
- Ensure difficulty is appropriate for your hardware
- Confirm the node is fully synced

---

## SECURITY NOTICE

```
╔═══════════════════════════════════════════════════════════════════╗
║  VAULT-TEC SECURITY ADVISORY                                      ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  • Keep your wallet files backed up in a secure location          ║
║  • Do not expose RPC port (10567) to the public internet          ║
║  • The Stratum port (10333) can be exposed for remote miners      ║
║  • Dashboard (8080) should remain on localhost or secured LAN     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## LICENSE

This project is released under the MIT License.

---

## CREDITS

```
Developed with assistance from Claude (Anthropic)
Vault-Tec styling inspired by the Fallout universe
CAPS cryptocurrency - SHA256 proof-of-work
```

---

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     "Remember: In the wasteland, CAPS are king. Start mining today!"         ║
║                                                                               ║
║                         - Your friends at Vault-Tec                           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```
