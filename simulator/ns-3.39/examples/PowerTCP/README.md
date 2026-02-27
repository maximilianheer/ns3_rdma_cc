# PowerTCP Simulations

To avoid any directory conflicts, first open `config.sh` and set the value of `NS3` to the FULL path to the current directory. Both Incast and Fairness simulations take only about a few minutes. So you can play around easily. Documentation on workload simulations coming soon.

## Incast

- **Simulations:** Run `./script-burst.sh yes no` in your terminal to launch one-shot simulations for PowerTCP, Theta-PowerTCP, HPCC, TIMELY and DCQCN in a 10:1 incast scenario. The simulation data is written to `dump_burst/` folder in this directory. 
- **Parse results:** Just run `./results-burst.sh` and the results are written to `results_burst/` folder. 
- **Generate plots:** Run `python3 plot-burst.py`. You will need to open `plot-burst.py` and change some paths at the top of the script. Note: script, results, plot. This is the order to run the scripts.

## Fairness

- **Simulations:** Run `./script-fairness.sh` in your terminal to launch fairness test for PowerTCP, Theta-PowerTCP, HPCC, TIMELY and DCQCN. The simulation data is written to `dump_fairness/`. 
- **Parse results:** Run `./results-fairness.sh` and the results can be found in `results_fairness/`. 
- **Generate plots:** Run `python3 plot-fairness.py` to generate figures (pdf and png).


## Workload

- **Simulations:** Run `./script-workload.sh` in your terminal to launch workload tests for PowerTCP, Theta-PowerTCP, HPCC, TIMELY and DCQCN. The simulation data is written to `dump_workload/`. The script launches simulations for the following cases:
	- varying loads; no incast traffic
	- 80% load, 2MB request size and varying request rates
	- 80% load, 4/second request rate and varying request sizes 
- **Parse results:** Run `./results-workload.sh` and the results can be found in `results_workload/`. 
- **Generate plots:** Run `python3 plot-workload.py` to generate figures (pdf and png).

**IMPORTANT to note:** These simulations take a very long time. The scripts are written to launch **38** simulations in parallel. Please adjust this number based on your cpu. Below are the lines to change (they appear multiple times in the script. Pay attention!).

```bash
while [[ $(ps aux|grep "powertcp-evaluation-workload-optimized"|wc -l) -gt 38 ]];do
	echo "Waiting for cpu cores.... $N-th experiment "
	sleep 60
done
```

## Simple DCQCN example

`rdma-simple-dcqcn.cc` is a minimal, self-contained simulation — no topology, flow, or config files required. It models a single RDMA WRITE between two endpoints connected through one switch at 100 Gbps with DCQCN congestion control.

**Topology**
```
serverA (node 0) ── 100G / 1µs ── switch (node 2) ── 100G / 1µs ── serverB (node 1)
```

**Build and run** (from the `ns-3.39/` root):
```bash
mkdir -p mix
./ns3 build rdma-simple-dcqcn
./ns3 run rdma-simple-dcqcn
```

**Outputs** are written to the `mix/` directory:

*Flow completion time* — `mix/fct-simple.txt`, one line per completed QP:
```
<sip_hex> <dip_hex> <sport> <dport> <size_bytes> <start_ns> <fct_ns> <standalone_fct_ns>
```

*Congestion control state* — `mix/dcqcn-state.csv`, sampled every 5 µs on the sender:

| Column | Description |
|---|---|
| `time_ns` | Simulation time (ns) |
| `rate_bps` | Current sending rate (bps) |
| `target_rate_bps` | DCQCN target rate (bps) |
| `alpha` | Congestion estimate α ∈ [0, 1] — tracks ECN fraction via EWMA |
| `rp_stage` | Rate-increase stage (0 = fast recovery, 1+ = active/hyper increase) |
| `decrease_cnp` | 1 if a CNP arrived since the last rate-decrease check interval |
| `alpha_cnp` | 1 if a CNP arrived in the current alpha-update slot |

Quick plot with Python:
```python
import pandas as pd, matplotlib.pyplot as plt
df = pd.read_csv("mix/dcqcn-state.csv")
fig, axes = plt.subplots(3, 1, sharex=True)
df.plot(x="time_ns", y="rate_bps",        ax=axes[0], legend=True)
df.plot(x="time_ns", y="alpha",            ax=axes[1], legend=True)
df.plot(x="time_ns", y="rp_stage",         ax=axes[2], legend=True)
plt.xlabel("Time (ns)"); plt.tight_layout(); plt.savefig("dcqcn-state.png")
```

*Packet captures* — two files, both on the switch:

| File | What you see |
|---|---|
| `mix/rdma-simple-2-1.pcap` | Switch transmitting **toward serverA** — ACKs, CNPs, PFC |
| `mix/rdma-simple-2-2.pcap` | Switch transmitting **toward serverB** — RDMA Write data |

> **Why only the switch?**  `QbbNetDevice::Receive()` on server (host) nodes dispatches RDMA packets (`ip.proto` 0x11/0xFC/0xFD/0xFE/0xFF) directly to the RDMA driver callback without calling `m_promiscSnifferTrace`.  RDMA TX on servers similarly calls `TransmitStart` directly from the RDMA queue dequeue path, also bypassing the sniffer.  The switch is the only place where `m_promiscSnifferTrace` fires for all RDMA packet types — it captures every packet the switch transmits out of each port.

Inspect with tcpdump:
```bash
tcpdump -r mix/rdma-simple-2-2.pcap -nn   # data packets
tcpdump -r mix/rdma-simple-2-1.pcap -nn   # ACKs and CNPs
```
To disable pcap (faster runs), comment out the two `qbb.EnablePcap` lines in `rdma-simple-dcqcn.cc`.

**Wireshark dissector**

`rdma-ns3-dissector.lua` teaches Wireshark to decode all five custom packet types that the simulator uses in place of real RoCE.  The simulator does **not** use standard IB/RoCE headers — it encodes packet roles in the IPv4 Protocol field and carries control state in small custom L4 headers, all on top of ordinary IP.

| IPv4 Protocol | Meaning |
|---|---|
| `0x11` (UDP) | RDMA Write data — SeqTsHeader(seq, pg) + optional INT + payload |
| `0xFC` | ACK |
| `0xFD` | NACK |
| `0xFF` | CNP — Congestion Notification Packet (triggers DCQCN rate reduction) |
| `0xFE` | PFC — Priority Flow Control pause frame |

*Install the dissector* (one-time, pick whichever is convenient):
```bash
# Option A – user plugin directory (persists across sessions)
mkdir -p ~/.local/lib/wireshark/plugins
cp rdma-ns3-dissector.lua ~/.local/lib/wireshark/plugins/

# Option B – pass directly when launching
wireshark --lua-script rdma-ns3-dissector.lua -r mix/rdma-simple-0-1.pcap
tshark   --lua-script rdma-ns3-dissector.lua -r mix/rdma-simple-0-1.pcap -V
```

*INT header mode preference* — the simulator embeds per-hop telemetry (INT) in data and ACK packets; its size depends on the CC algorithm:

| CC mode | INT mode | Bytes appended |
|---|---|---|
| DCQCN (`cc_mode=1`) | **NONE** | 0 (default) |
| HPCC / PowerTCP (`cc_mode=3`) | NORMAL | 42 |
| TIMELY (`cc_mode=7`) | TS | 8 |
| HPCC-PINT (`cc_mode=10`) | PINT | 1–2 |

Set the matching mode in Wireshark via **Edit → Preferences → Protocols → ns3 RDMA/DCQCN Simulator → INT Header mode**.  For the simple DCQCN example the default (NONE) is correct and no change is needed.

*Useful tshark one-liners after installing the plugin:*
```bash
# Show RDMA data packets with sequence numbers (switch → serverB)
tshark --lua-script rdma-ns3-dissector.lua \
       -r mix/rdma-simple-2-2.pcap \
       -Y "rdma_ns3_data" -T fields \
       -e ip.src -e ip.dst -e rdma_ns3_data.seq -e rdma_ns3_data.pg

# Show ACKs and their sequence numbers (switch → serverA)
tshark --lua-script rdma-ns3-dissector.lua \
       -r mix/rdma-simple-2-1.pcap \
       -Y "rdma_ns3_ack" -T fields \
       -e rdma_ns3_ack.sport -e rdma_ns3_ack.seq

# Show CNPs (congestion signals, switch → serverA)
tshark --lua-script rdma-ns3-dissector.lua \
       -r mix/rdma-simple-2-1.pcap \
       -Y "rdma_ns3_cnp" -T fields -e ip.src -e rdma_ns3_cnp.ecnBits
```

**Tunable parameters** are constants at the top of `rdma-simple-dcqcn.cc`:

| Constant | Default | Description |
|---|---|---|
| `FLOW_SIZE_BYTES` | 10 000 000 | Size of the RDMA WRITE (bytes) |
| `SIM_STOP_S` | 0.05 | Simulation stop time (seconds) |
| `KMIN_100G` / `KMAX_100G` | 400 / 1600 KB | ECN marking thresholds |
| `PMAX_100G` | 0.2 | Maximum ECN marking probability |
| `SWITCH_BUF_MB` | 4 | Switch buffer size (MB) |
| `RP_TIMER` | 900 µs | DCQCN rate-increase timer |
| `ALPHA_RESUME` | 55 | DCQCN alpha resume interval |

## Incast DCQCN example

`rdma-incast-dcqcn.cc` deliberately creates congestion so you can observe DCQCN rate reductions in the CSV output.  N senders (default 4) all write simultaneously to a single receiver over a shared 100 Gbps bottleneck link, providing 4× oversubscription.

**Topology**
```
sender0 ─┐
sender1 ─┼── switch ─── receiver
sender2 ─┤
sender3 ─┘
(all links 100G / 1µs)
```

**What creates congestion:** 4 × 100 Gbps offered load into a 100 Gbps bottleneck → queue at the receiver-side switch port fills → ECN marking at Kmin (100 KB) → CNPs → DCQCN rate reduction on every sender.

**Build and run** (from the `ns-3.39/` root):
```bash
mkdir -p mix
./ns3 build rdma-incast-dcqcn
./ns3 run rdma-incast-dcqcn
```

**Outputs**

| File | Contents |
|---|---|
| `mix/fct-incast.txt` | FCT record, one line per completed flow |
| `mix/dcqcn-incast.csv` | Per-sender DCQCN state, sampled every 5 µs |
| `mix/rdma-incast-<sw>-<port>.pcap` | Switch pcap (receiver port + sender-0 port) |

The CSV has one row per sender per sample interval:

| Column | Description |
|---|---|
| `sender_id` | Which sender (0 … N_SENDERS−1) |
| `time_ns` | Simulation time (ns) |
| `rate_bps` | Current sending rate (bps) |
| `target_rate_bps` | DCQCN target rate (bps) |
| `alpha` | Congestion estimate α — rises toward 1 when CNPs arrive |
| `rp_stage` | Rate-increase stage (0 = fast recovery, 1+ = active/hyper increase) |
| `decrease_cnp` | 1 if a CNP arrived since the last rate-decrease check |
| `alpha_cnp` | 1 if a CNP arrived in the current alpha-update slot |

Quick plot with Python — showing all senders overlaid:
```python
import pandas as pd, matplotlib.pyplot as plt
df = pd.read_csv("mix/dcqcn-incast.csv")
fig, axes = plt.subplots(3, 1, sharex=True, figsize=(10, 7))
for sid, grp in df.groupby("sender_id"):
    grp.plot(x="time_ns", y="rate_bps",   ax=axes[0], label=f"sender {sid}")
    grp.plot(x="time_ns", y="alpha",       ax=axes[1], label=f"sender {sid}")
    grp.plot(x="time_ns", y="rp_stage",    ax=axes[2], label=f"sender {sid}")
for ax, title in zip(axes, ["Rate (bps)", "Alpha", "RP stage"]):
    ax.set_ylabel(title); ax.legend(loc="upper right")
plt.xlabel("Time (ns)"); plt.tight_layout()
plt.savefig("dcqcn-incast.png", dpi=150)
```

**Tunable parameters** are constants at the top of `rdma-incast-dcqcn.cc`:

| Constant | Default | Description |
|---|---|---|
| `N_SENDERS` | 4 | Number of competing senders |
| `FLOW_SIZE_BYTES` | 10 000 000 | Size of each RDMA WRITE (bytes) |
| `SIM_STOP_S` | 0.01 | Simulation stop time (10 ms is enough to see convergence) |
| `KMIN_100G` / `KMAX_100G` | 100 / 400 KB | ECN thresholds (lower than simple example to fire quickly) |
| `SWITCH_BUF_MB` | 32 | Large buffer prevents loss; ECN controls the rate instead |