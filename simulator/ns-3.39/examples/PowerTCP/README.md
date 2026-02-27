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

*Packet captures* — one `.pcap` file per interface:

| File | Interface |
|---|---|
| `mix/rdma-simple-0-1.pcap` | serverA NIC — outbound data, inbound ACKs |
| `mix/rdma-simple-1-1.pcap` | serverB NIC — inbound data, outbound ACKs |
| `mix/rdma-simple-2-1.pcap` | Switch port facing serverA |
| `mix/rdma-simple-2-2.pcap` | Switch port facing serverB |

Inspect with tcpdump:
```bash
tcpdump -r mix/rdma-simple-0-1.pcap -nn
```
To disable pcap (faster runs), comment out the `qbb.EnablePcapAll` line in `rdma-simple-dcqcn.cc` or change `PCAP_PREFIX` to an empty string.

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
# Show only RDMA data packets with sequence numbers
tshark --lua-script rdma-ns3-dissector.lua \
       -r mix/rdma-simple-0-1.pcap \
       -Y "rdma_ns3_data" -T fields \
       -e ip.src -e ip.dst -e rdma_ns3_data.seq -e rdma_ns3_data.pg

# Count CNPs (congestion signals sent by the switch)
tshark --lua-script rdma-ns3-dissector.lua \
       -r mix/rdma-simple-2-1.pcap \
       -Y "rdma_ns3_cnp" -T fields -e ip.src -e rdma_ns3_cnp.ecnBits

# Show all ACKs with sequence numbers
tshark --lua-script rdma-ns3-dissector.lua \
       -r mix/rdma-simple-1-1.pcap \
       -Y "rdma_ns3_ack" -T fields \
       -e rdma_ns3_ack.sport -e rdma_ns3_ack.seq
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