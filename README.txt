CapsMinePack - One-Click Caps Mining
=====================================

Extract, run, mine.  No manual configuration required.


PREREQUISITES
-------------
- Python 3.6 or newer  (https://www.python.org/downloads/)
- capsd and caps-cli binaries placed in the bin/ folder


QUICK START
-----------
1. Place capsd(.exe) and caps-cli(.exe) into the bin/ folder.
2. Open a terminal in this directory.
3. Run:  python launcher.py
4. On first run the launcher will:
   - Generate secure RPC credentials
   - Write the node configuration
   - Start the Caps node
   - Create a mining wallet and address
   - Start the stratum mining server
5. Connect your miner (see below).
6. Press Ctrl+C to stop everything cleanly.


CONNECTING A MINER
------------------
Point any Stratum v1 miner at:

    stratum+tcp://<your-ip>:10333

Worker name and password can be anything (e.g. worker1 / x).

Supported miners: cgminer, bfgminer, NerdMiner, or any SHA-256d
Stratum v1 compatible software/hardware.


DASHBOARD
---------
Open a browser to:

    http://localhost:8080

Live stats: connected miners, hashrate graph, shares, blocks found.


PORTS / FIREWALL
----------------
Open these ports if mining from other machines:

    12566  -  P2P (other Caps nodes)
    10333  -  Stratum (miners connect here)
    8080   -  Dashboard (web browser, optional)
    10567  -  RPC (localhost only, do NOT expose)


CHECKING YOUR BALANCE
---------------------
While the launcher is running, open another terminal and run:

    bin/caps-cli -datadir=./data -rpcport=10567 -rpcwallet=mining getbalance

Or view recent transactions:

    bin/caps-cli -datadir=./data -rpcport=10567 -rpcwallet=mining listtransactions


TROUBLESHOOTING
---------------
- Node log:  data/debug.log
- Stratum output appears in the launcher terminal.
- If the node won't start, check that port 12566 is not already in use.
- If the launcher says "Missing binaries", make sure capsd and caps-cli
  are in the bin/ folder and are executable.
- On Linux you may need:  chmod +x bin/capsd bin/caps-cli
- To reset everything, delete the data/ folder and re-run.


FILE LAYOUT
-----------
CapsMinePack/
  launcher.py          Main launcher script
  README.txt           This file
  bin/                 Node binaries (you supply these)
    capsd(.exe)
    caps-cli(.exe)
  stratum/
    stratum_server.py  Stratum mining server
    config.json        Auto-generated on first run
  data/                Created at runtime
    caps.conf          Auto-generated node config
    debug.log          Node log
    .minepack_state.json  Saved credentials and mining address
