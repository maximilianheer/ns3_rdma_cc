/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Minimal RDMA-over-Converged-Ethernet simulation with DCQCN.
 *
 * Topology:
 *   serverA (node 0) ── 100G/1µs ── switch (node 2) ── 100G/1µs ── serverB (node 1)
 *
 * One RDMA WRITE flow: serverA → serverB, 10 MB, starting at t=0.
 * Congestion control: DCQCN (cc_mode = 1).
 * PFC is enabled to provide a lossless fabric.
 *
 * Build:
 *   ./ns3 build rdma-simple-dcqcn
 *
 * Run (from the ns-3.39 root):
 *   mkdir -p mix
 *   ./ns3 run rdma-simple-dcqcn
 *
 * Output:
 *   mix/fct-simple.txt  – per-flow completion time record
 */

#include <iostream>
#include <map>
#include <vector>
#include "ns3/core-module.h"
#include "ns3/qbb-helper.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/packet.h"
#include <ns3/rdma.h>
#include <ns3/rdma-client.h>
#include <ns3/rdma-client-helper.h>
#include <ns3/rdma-driver.h>
#include <ns3/switch-node.h>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("RDMA_SIMPLE_DCQCN");

// ---------------------------------------------------------------------------
// Simulation parameters – tweak here or extend with CommandLine as needed
// ---------------------------------------------------------------------------
const uint32_t CC_MODE         = 1;          // 1 = DCQCN
const uint32_t PACKET_PAYLOAD  = 1000;        // bytes per RDMA packet
const double   PAUSE_TIME      = 5;           // PFC pause quantum (µs)
const double   SIM_STOP_S      = 0.05;        // simulation stop time (s)
const uint64_t FLOW_SIZE_BYTES = 10000000;    // 10 MB RDMA WRITE

// DCQCN knobs (same defaults as HPCC / PowerTCP code-base)
const double   ALPHA_RESUME    = 55;
const double   RP_TIMER        = 900;         // µs
const double   EWMA_GAIN       = 1.0 / 16;
const uint32_t FAST_RECOV      = 5;
const double   RATE_DEC_INTV   = 4;

// ECN thresholds for 100 Gbps links
const uint32_t KMIN_100G       = 400;         // KB
const uint32_t KMAX_100G       = 1600;        // KB
const double   PMAX_100G       = 0.2;
const uint32_t SWITCH_BUF_MB   = 4;

// Output files
const std::string FCT_FILE    = "mix/fct-simple.txt";
const std::string PCAP_PREFIX = "mix/rdma-simple";  // produces mix/rdma-simple-<node>-<dev>.pcap

// ---------------------------------------------------------------------------
// Global state (mirrors the original HPCC/PowerTCP simulation structure)
// ---------------------------------------------------------------------------
NodeContainer n;  // n[0]=serverA, n[1]=serverB, n[2]=switch
std::vector<Ipv4Address> serverAddress;

struct Interface {
    uint32_t idx;
    bool     up;
    uint64_t delay;  // ns
    uint64_t bw;     // bps
    Interface() : idx(0), up(false), delay(0), bw(0) {}
};

map<Ptr<Node>, map<Ptr<Node>, Interface>>            nbr2if;
map<Ptr<Node>, map<Ptr<Node>, vector<Ptr<Node>>>>    nextHop;
map<Ptr<Node>, map<Ptr<Node>, uint64_t>>             pairDelay;
map<Ptr<Node>, map<Ptr<Node>, uint64_t>>             pairTxDelay;
map<uint32_t,  map<uint32_t,  uint64_t>>             pairBw;
map<Ptr<Node>, map<Ptr<Node>, uint64_t>>             pairBdp;
map<uint32_t,  map<uint32_t,  uint64_t>>             pairRtt;

uint64_t maxRtt = 0, maxBdp = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
Ipv4Address node_id_to_ip(uint32_t id)
{
    return Ipv4Address(0x0b000001u
                       + ((id / 256) * 0x00010000u)
                       + ((id % 256) * 0x00000100u));
}

uint32_t ip_to_node_id(Ipv4Address ip)
{
    return (ip.Get() >> 8) & 0xffffu;
}

void qp_finish(FILE *fout, Ptr<RdmaQueuePair> q)
{
    uint32_t sid = ip_to_node_id(q->sip);
    uint32_t did = ip_to_node_id(q->dip);
    uint64_t base_rtt = pairRtt[sid][did];
    uint64_t b        = pairBw[sid][did];

    uint32_t total_bytes =
        q->m_size
        + ((q->m_size - 1) / PACKET_PAYLOAD + 1)
          * (CustomHeader::GetStaticWholeHeaderSize() - IntHeader::GetStaticSize());

    uint64_t standalone_fct = base_rtt + total_bytes * 8000000000lu / b;

    // sip dip sport dport size(B) start_time(ns) fct(ns) standalone_fct(ns)
    fprintf(fout, "%08x %08x %u %u %lu %lu %lu %lu\n",
            q->sip.Get(), q->dip.Get(),
            q->sport, q->dport,
            q->m_size,
            q->startTime.GetTimeStep(),
            (Simulator::Now() - q->startTime).GetTimeStep(),
            standalone_fct);
    fflush(fout);

    Ptr<RdmaDriver> rdma = n.Get(did)->GetObject<RdmaDriver>();
    rdma->m_rdma->DeleteRxQp(q->sip.Get(), q->m_pg, q->sport);
}

// ---------------------------------------------------------------------------
// Routing (copied verbatim from powertcp-evaluation-burst.cc)
// ---------------------------------------------------------------------------
void CalculateRoute(Ptr<Node> host)
{
    vector<Ptr<Node>> q;
    map<Ptr<Node>, int>      dis;
    map<Ptr<Node>, uint64_t> delay, txDelay, bw;

    q.push_back(host);
    dis[host] = 0; delay[host] = 0; txDelay[host] = 0;
    bw[host] = 0xfffffffffffffffflu;

    for (int i = 0; i < (int)q.size(); i++) {
        Ptr<Node> now = q[i];
        int d = dis[now];
        for (auto &kv : nbr2if[now]) {
            if (!kv.second.up) continue;
            Ptr<Node> next = kv.first;
            if (dis.find(next) == dis.end()) {
                dis[next]     = d + 1;
                delay[next]   = delay[now]   + kv.second.delay;
                txDelay[next] = txDelay[now] + PACKET_PAYLOAD * 1000000000lu * 8 / kv.second.bw;
                bw[next]      = min(bw[now], kv.second.bw);
                if (next->GetNodeType()) q.push_back(next);
            }
            if (d + 1 == dis[next])
                nextHop[next][host].push_back(now);
        }
    }
    for (auto &kv : delay)   pairDelay[kv.first][host]   = kv.second;
    for (auto &kv : txDelay) pairTxDelay[kv.first][host] = kv.second;
    for (auto &kv : bw)      pairBw[kv.first->GetId()][host->GetId()] = kv.second;
}

void CalculateRoutes()
{
    for (uint32_t i = 0; i < n.GetN(); i++)
        if (n.Get(i)->GetNodeType() == 0)
            CalculateRoute(n.Get(i));
}

void SetRoutingEntries()
{
    for (auto &i : nextHop) {
        Ptr<Node> node = i.first;
        for (auto &j : i.second) {
            Ptr<Node>   dst     = j.first;
            Ipv4Address dstAddr = dst->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
            for (auto &next : j.second) {
                uint32_t iface = nbr2if[node][next].idx;
                if (node->GetNodeType())
                    DynamicCast<SwitchNode>(node)->AddTableEntry(dstAddr, iface);
                else
                    node->GetObject<RdmaDriver>()->m_rdma->AddTableEntry(dstAddr, iface);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    // -----------------------------------------------------------------------
    // 1. CC-mode global config
    // -----------------------------------------------------------------------
    // DCQCN uses no INT header, so set mode to NONE.
    IntHeader::mode = IntHeader::NONE;

    Config::SetDefault("ns3::QbbNetDevice::PauseTime",  UintegerValue(PAUSE_TIME));
    Config::SetDefault("ns3::QbbNetDevice::QcnEnabled", BooleanValue(true));

    // -----------------------------------------------------------------------
    // 2. Create nodes
    //    Index 0 = serverA (sender), 1 = serverB (receiver), 2 = switch
    // -----------------------------------------------------------------------
    Ptr<Node>       serverA = CreateObject<Node>();
    Ptr<Node>       serverB = CreateObject<Node>();
    Ptr<SwitchNode> sw      = CreateObject<SwitchNode>();

    sw->SetAttribute("EcnEnabled", BooleanValue(true));
    sw->SetNodeType(1);   // 1 = ToR switch

    n.Add(serverA);
    n.Add(serverB);
    n.Add(sw);

    InternetStackHelper internet;
    Ipv4GlobalRoutingHelper globalRoutingHelper;
    internet.SetRoutingHelper(globalRoutingHelper);
    internet.Install(n);

    // Pre-assign server IPs (before link installation, so they become the
    // primary addresses used by the RDMA stack).
    serverAddress.resize(2);
    serverAddress[0] = node_id_to_ip(0);
    serverAddress[1] = node_id_to_ip(1);

    // -----------------------------------------------------------------------
    // 3. Install 100G links
    // -----------------------------------------------------------------------
    QbbHelper qbb;
    qbb.SetDeviceAttribute("DataRate",   StringValue("100Gbps"));
    qbb.SetChannelAttribute("Delay",     StringValue("1us"));

    Ipv4AddressHelper ipv4Hlp;

    // Link A: serverA ── switch
    NetDeviceContainer dA = qbb.Install(serverA, sw);
    {
        Ptr<Ipv4> ip = serverA->GetObject<Ipv4>();
        ip->AddInterface(dA.Get(0));
        ip->AddAddress(1, Ipv4InterfaceAddress(serverAddress[0], Ipv4Mask(0xff000000)));
    }
    ipv4Hlp.SetBase("10.1.1.0", "255.255.255.0");
    ipv4Hlp.Assign(dA);

    // Link B: serverB ── switch
    NetDeviceContainer dB = qbb.Install(serverB, sw);
    {
        Ptr<Ipv4> ip = serverB->GetObject<Ipv4>();
        ip->AddInterface(dB.Get(0));
        ip->AddAddress(1, Ipv4InterfaceAddress(serverAddress[1], Ipv4Mask(0xff000000)));
    }
    ipv4Hlp.SetBase("10.1.2.0", "255.255.255.0");
    ipv4Hlp.Assign(dB);

    // -----------------------------------------------------------------------
    // 4. Populate nbr2if (needed by routing and BDP computation)
    // -----------------------------------------------------------------------
    auto registerLink = [&](NetDeviceContainer &d, Ptr<Node> a, Ptr<Node> b) {
        Ptr<QbbNetDevice> devA = DynamicCast<QbbNetDevice>(d.Get(0));
        Ptr<QbbNetDevice> devB = DynamicCast<QbbNetDevice>(d.Get(1));
        uint64_t delay_ns =
            DynamicCast<QbbChannel>(devA->GetChannel())->GetDelay().GetTimeStep();

        Interface ifA, ifB;
        ifA.idx = devA->GetIfIndex(); ifA.up = true;
        ifA.delay = delay_ns;         ifA.bw  = devA->GetDataRate().GetBitRate();
        ifB.idx = devB->GetIfIndex(); ifB.up = true;
        ifB.delay = delay_ns;         ifB.bw  = devB->GetDataRate().GetBitRate();

        nbr2if[a][b] = ifA;
        nbr2if[b][a] = ifB;
    };

    registerLink(dA, serverA, sw);
    registerLink(dB, serverB, sw);

    // -----------------------------------------------------------------------
    // 5. Configure switch MMU (Dynamic Thresholds + ECN)
    // -----------------------------------------------------------------------
    {
        Ptr<QbbNetDevice> refDev = DynamicCast<QbbNetDevice>(dA.Get(0));
        uint64_t link_bps    = refDev->GetDataRate().GetBitRate();
        uint64_t link_dly_ns =
            DynamicCast<QbbChannel>(refDev->GetChannel())->GetDelay().GetTimeStep();

        sw->m_mmu->SetAlphaIngress(1.0 / 8);
        sw->m_mmu->SetAlphaEgress(UINT16_MAX);

        uint64_t totalHeadroom = 0;
        for (uint32_t j = 1; j < sw->GetNDevices(); j++) {
            for (uint32_t qu = 0; qu < 8; qu++) {
                sw->m_mmu->ConfigEcn(j, KMIN_100G, KMAX_100G, PMAX_100G);
                uint32_t headroom = (uint32_t)(link_bps * link_dly_ns / 8 / 1000000000) * 3;
                sw->m_mmu->SetHeadroom(headroom, j, qu);
                totalHeadroom += headroom;
            }
        }
        uint64_t pool = (uint64_t)SWITCH_BUF_MB * 1024 * 1024;
        sw->m_mmu->SetBufferPool(pool + totalHeadroom);
        sw->m_mmu->SetIngressPool(pool);
        sw->m_mmu->SetEgressLosslessPool(pool);
        sw->m_mmu->node_id = sw->GetId();
    }

    // -----------------------------------------------------------------------
    // 6. Install RDMA driver on servers
    // -----------------------------------------------------------------------
#if ENABLE_QP
    FILE *fct_output = fopen(FCT_FILE.c_str(), "w");
    NS_ASSERT_MSG(fct_output, "Could not open " << FCT_FILE
                  << " – make sure the 'mix/' directory exists.");

    auto installRdma = [&](Ptr<Node> node) {
        Ptr<RdmaHw> rdmaHw = CreateObject<RdmaHw>();
        rdmaHw->SetAttribute("ClampTargetRate",      BooleanValue(false));
        rdmaHw->SetAttribute("AlphaResumInterval",   DoubleValue(ALPHA_RESUME));
        rdmaHw->SetAttribute("RPTimer",              DoubleValue(RP_TIMER));
        rdmaHw->SetAttribute("FastRecoveryTimes",    UintegerValue(FAST_RECOV));
        rdmaHw->SetAttribute("EwmaGain",             DoubleValue(EWMA_GAIN));
        rdmaHw->SetAttribute("RateAI",               DataRateValue(DataRate("50Mb/s")));
        rdmaHw->SetAttribute("RateHAI",              DataRateValue(DataRate("100Mb/s")));
        rdmaHw->SetAttribute("L2BackToZero",         BooleanValue(false));
        rdmaHw->SetAttribute("L2ChunkSize",          UintegerValue(4000));
        rdmaHw->SetAttribute("L2AckInterval",        UintegerValue(1));
        rdmaHw->SetAttribute("CcMode",               UintegerValue(CC_MODE));
        rdmaHw->SetAttribute("RateDecreaseInterval", DoubleValue(RATE_DEC_INTV));
        rdmaHw->SetAttribute("MinRate",              DataRateValue(DataRate("100Mb/s")));
        rdmaHw->SetAttribute("Mtu",                  UintegerValue(PACKET_PAYLOAD));
        rdmaHw->SetAttribute("MiThresh",             UintegerValue(5));
        rdmaHw->SetAttribute("VarWin",               BooleanValue(false));
        rdmaHw->SetAttribute("FastReact",            BooleanValue(true));
        rdmaHw->SetAttribute("MultiRate",            BooleanValue(false));
        rdmaHw->SetAttribute("SampleFeedback",       BooleanValue(false));
        rdmaHw->SetAttribute("TargetUtil",           DoubleValue(0.95));
        rdmaHw->SetAttribute("RateBound",            BooleanValue(true));
        rdmaHw->SetAttribute("DctcpRateAI",          DataRateValue(DataRate("1000Mb/s")));
        // PowerTCP/Theta-PowerTCP are disabled; this is pure DCQCN.
        rdmaHw->SetAttribute("PowerTCPEnabled",      BooleanValue(false));
        rdmaHw->SetAttribute("PowerTCPdelay",        BooleanValue(false));
        rdmaHw->SetPintSmplThresh(1.0);

        Ptr<RdmaDriver> rdma = CreateObject<RdmaDriver>();
        rdma->SetNode(node);
        rdma->SetRdmaHw(rdmaHw);
        node->AggregateObject(rdma);
        rdma->Init();
        rdma->TraceConnectWithoutContext("QpComplete",
                                         MakeBoundCallback(qp_finish, fct_output));
    };

    installRdma(serverA);
    installRdma(serverB);
#endif

    // ACKs go in low-priority queue 3
    RdmaEgressQueue::ack_q_idx = 3;

    // -----------------------------------------------------------------------
    // 7. Routing
    // -----------------------------------------------------------------------
    CalculateRoutes();
    SetRoutingEntries();

    // -----------------------------------------------------------------------
    // 8. Compute BDP / RTT for the single server pair
    // -----------------------------------------------------------------------
    for (uint32_t i = 0; i < 2; i++) {
        for (uint32_t j = 0; j < 2; j++) {
            if (i == j) continue;
            uint64_t delay   = pairDelay[n.Get(i)][n.Get(j)];
            uint64_t txDelay = pairTxDelay[n.Get(i)][n.Get(j)];
            uint64_t rtt     = delay * 2 + txDelay;
            uint64_t bw      = pairBw[i][j];
            uint64_t bdp     = rtt * bw / 1000000000 / 8;
            pairBdp[n.Get(i)][n.Get(j)] = bdp;
            pairRtt[i][j] = rtt;
            if (bdp > maxBdp) maxBdp = bdp;
            if (rtt > maxRtt) maxRtt = rtt;
        }
    }
    printf("maxRtt=%lu ns   maxBdp=%lu bytes\n", maxRtt, maxBdp);

    // -----------------------------------------------------------------------
    // 9. Configure switch CC
    // -----------------------------------------------------------------------
    sw->SetAttribute("CcMode",       UintegerValue(CC_MODE));
    sw->SetAttribute("MaxRtt",       UintegerValue(maxRtt));
    sw->SetAttribute("PowerEnabled", BooleanValue(false));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // -----------------------------------------------------------------------
    // 10. Install the single RDMA WRITE flow: serverA → serverB
    // -----------------------------------------------------------------------
#if ENABLE_QP
    RdmaClientHelper clientHelper(
        3,                // priority group (RDMA uses PG 3)
        serverAddress[0], serverAddress[1],
        10000,            // source port
        10000,            // destination port
        FLOW_SIZE_BYTES,  // bytes to write
        maxBdp,           // window = BDP (bytes)
        maxRtt,           // base RTT (ns)
        Simulator::GetMaximumSimulationTime()
    );
    ApplicationContainer app = clientHelper.Install(serverA);
    app.Start(Seconds(0.0));
#endif

    // -----------------------------------------------------------------------
    // 11. Enable pcap on the switch ports only.
    //
    // QbbNetDevice::Receive() for server (host) nodes dispatches RDMA packets
    // (ip.proto 0x11/0xFC/0xFD/0xFE/0xFF) directly to m_rdmaReceiveCb without
    // firing m_promiscSnifferTrace, so server-NIC pcap files would be empty.
    // On the TX side, RDMA queue-pair dequeues (DequeueAndTransmit) also call
    // TransmitStart directly, again bypassing the sniffer.
    //
    // Switch ports DO fire m_promiscSnifferTrace (line ~387 of qbb-net-device.cc)
    // in DequeueAndTransmit, capturing every packet the switch transmits:
    //   mix/rdma-simple-2-1.pcap  switch → serverA  (ACKs, CNPs, PFC)
    //   mix/rdma-simple-2-2.pcap  switch → serverB  (RDMA data)
    // -----------------------------------------------------------------------
    qbb.EnablePcap(PCAP_PREFIX, dA.Get(1), false);   // switch port → serverA
    qbb.EnablePcap(PCAP_PREFIX, dB.Get(1), false);   // switch port → serverB

    cout << "\nTopology : serverA ── 100G/1µs ── switch ── 100G/1µs ── serverB\n";
    cout << "CC mode  : DCQCN (cc_mode=" << CC_MODE << ")\n";
    cout << "Flow     : RDMA WRITE " << FLOW_SIZE_BYTES / 1e6 << " MB, serverA → serverB\n";
    cout << "Stop at  : " << SIM_STOP_S << " s\n";
    cout << "PCAP     : " << PCAP_PREFIX << "-2-1.pcap (ACKs/CNPs) | "
         << PCAP_PREFIX << "-2-2.pcap (data)\n\n";

    Simulator::Stop(Seconds(SIM_STOP_S));
    Simulator::Run();
    Simulator::Destroy();

    cout << "\nDone. FCT results written to: " << FCT_FILE << "\n";
    return 0;
}
