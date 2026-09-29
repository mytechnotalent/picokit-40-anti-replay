![picokit-40-anti-replay](https://raw.githubusercontent.com/mytechnotalent/picokit-40-anti-replay/main/picokit-40-anti-replay.png)

<br>

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/reverse-engineering)
## FREE Embedded Hacking Course [HERE](https://github.com/mytechnotalent/Embedded-Hacking)

<br>

# PICOKIT-40 ANTI REPLAY

### Per-Node Monotonic Sequence, Replay Window, and a Rejected Replay
#### Lesson 40 of the Picokit Series

<br>

***
**LEGAL DISCLAIMER:**
The information, tools, and code provided in this repository and course are strictly for educational, research, and defensive purposes only.

You are explicitly prohibited from using any materials contained herein to access, test, modify, or exploit any device, network, or system that you do not own 100% or for which you do not have explicit, documented, and legally binding authorization to interact with.

By using this repository and course, you acknowledge and agree that:

1. Any illegal, unauthorized, or malicious use of this information is solely your responsibility.
2. The author(s) and contributor(s) of this repository and course shall not be held liable for any damages, legal repercussions, criminal charges, or unauthorized actions resulting from the use, misuse, or abuse of the contents herein.
3. You will comply with all applicable local, state, national, and international laws regarding cybersecurity and computer fraud.

**IF YOU DO NOT AGREE WITH THESE TERMS, DO NOT USE THIS REPOSITORY AND COURSE.**
***

<br>
<br>

## Overview

The fortieth Picokit lesson. Every frame carries a per-node monotonic sequence
number, and the node keeps a thirty-two deep sliding replay window. On each
heartbeat the node registers the current sequence, offers the same sequence a
second time, and proves the window rejects it as a replay. The authenticated
heartbeat reports the replay verdict.

<br>

## What it teaches

- A per-node monotonic sequence carried inside the sealed heartbeat.
- A sliding replay window with a high mark and a bitmap of recent sequences.
- Rejecting a sequence equal to the high mark or older than the window.
- Reporting the replay verdict in the authenticated heartbeat.

<br>

## Hardware

| Peripheral | Pico 2 pin | Role |
| --- | --- | --- |
| Red / Yellow / Green | GP16 / GP18 / GP17 | annunciator status |
| Onboard LED | GP25 | heartbeat, one blink per transmit |
| RYLR998 | GP8 TX / GP9 RX | LoRa heartbeat |
| Debug Probe | SWCLK/SWDIO/GND, GP0/GP1 | SWD and the console |

<br>

## How it works

The node runs `monitor_step` in a loop. Every 5 seconds it accepts the current
sequence into the replay window and then offers the same sequence again; the
second offer is rejected as a replay. The verdict is carried in the heartbeat
body `{"n":40,"s":<seq>,"r":<1=replayed>}` sealed with the field key and sent
over LoRa.

<br>

## Build and flash

```bash
cd firmware
cmake -S . -B build -G Ninja -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-arm-s
cmake --build build
openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg \
  -c "program build/picokit_40_anti_replay.elf verify reset exit"
```

<br>

## Watch the node

Open the console at 115200 and reset:

```text
BOOT
=== PICOKIT-40 ANTI REPLAY // MONOTONIC SEQ + REPLAY WINDOW ===
SEQ 1 replayed=1
SEQ 2 replayed=1
RX from 0x0001, N bytes
```

<br>

## The gateway

```bash
cd gateway
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 listen.py --port /dev/cu.usbserial-A50285BI --hub 0001 --network 18 --db gateway.db
```

It prints `OK node=40 rssi=...` per authenticated heartbeat. The terminal
dashboard `python3 tui.py --db gateway.db` and the web dashboard
`python3 web/app.py --db gateway.db` show the same rows.

<br>

## Verify

```bash
python3 .opencode/skill/embedded-c-standard/audit_c_standard.py
python3 .opencode/skill/embedded-python-standard/audit_python_standard.py
python3 .opencode/skill/iot-readme-standard/validate_readme.py
python3 .opencode/skill/iot-banner-standard/validate_banner.py
python3 scripts/run_tests.py
python3 scripts/check_coverage.py
```

<br>

# Next
[picokit-41-provisioning](https://github.com/mytechnotalent/picokit-41-provisioning)

<br>

# License
[MIT License](https://github.com/mytechnotalent/picokit-40-anti-replay/blob/main/LICENSE)
