/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * DCQCN incast simulation – designed to produce visible congestion reactions.
 *
 * Topology (N_SENDERS = 4 by default):
 *
 *   sender0 ─┐
 *   sender1 ─┼── switch ─── receiver
 *   sender2 ─┤
 *   sender3 ─┘
 *
 * All links: 100 G / 1 µs.  N senders each write FLOW_SIZE_BYTES to the
 * same receiver simultaneously, overloading the receiver-side link (total
 * offered load = N × 100 Gbps into a single 100 Gbps bottleneck).
 *
 * ECN marking at the switch triggers CNPs which drive DCQCN rate reduction
 * on every sender.  The DCQCN state (rate, alpha, stage …) is sampled every
 * DCQCN_SAMPLE_NS ns for all senders and written to mix/dcqcn-incast.csv.
 *
 * Build:
 *   ./ns3 build rdma-incast-dcqcn
 *
 * Run (from the ns-3.39 root):
 *   mkdir -p mix
 *   ./ns3 run rdma-incast-dcqcn
 *
 * Outputs:
 *   mix/fct-incast.txt        – one line per completed flow
 *   mix/dcqcn-incast.csv      – per-sender DCQCN state over time
 *   mix/rdma-incast-<n>-<d>.pcap
 */

#include <iostream>
#include <map>
#include <sstream>
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
#include <ns3/rdma-hw.h>
#include <ns3/switch-node.h>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("RDMA_INCAST_DCQCN");

// ---------------------------------------------------------------------------
// Simulation parameters – tweak here
// ---------------------------------------------------------------------------
const uint32_t CC_MODE         = 1;          // 1 = DCQCN
const uint32_t N_SENDERS       = 4;          // fan-in; total offered load = N × 100 Gbps
const uint32_t PACKET_PAYLOAD  = 1000;        // bytes per RDMA packet
const double   PAUSE_TIME      = 5;           // PFC pause quantum (µs)
const double   SIM_STOP_S      = 0.01;        // 10 ms is enough to see DCQCN converge
const uint64_t FLOW_SIZE_BYTES = 10000000;    // 10 MB per sender

// DCQCN knobs
const double   ALPHA_RESUME    = 55;
const double   RP_TIMER        = 900;         // µs
const double   EWMA_GAIN       = 1.0 / 16;
const uint32_t FAST_RECOV      = 5;
const double   RATE_DEC_INTV   = 4;

// ECN thresholds for 100 Gbps links
// Kmin = 100 KB so ECN fires quickly under 4× overload
const uint32_t KMIN_100G       = 100;         // KB  (lower than simple example)
const uint32_t KMAX_100G       = 400;         // KB
const double   PMAX_100G       = 0.2;
const uint32_t SWITCH_BUF_MB   = 32;          // large buffer → no loss, pure DCQCN

// Output files
const std::string FCT_FILE       = "mix/fct-incast.txt";
const std::string PCAP_PREFIX    = "mix/rdma-incast";
const std::string DCQCN_LOG_FILE = "mix/dcqcn-incast.csv";
const uint64_t    DCQCN_SAMPLE_NS = 5000;     // sample every 5 µs

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
// Node layout:  n[0..N_SENDERS-1] = senders
//               n[N_SENDERS]      = receiver
//               n[N_SENDERS+1]    = switch  (SwitchNode)
NodeContainer n;
std::vector<Ipv4Address> serverAddress;  // [0..N_SENDERS-1]=senders, [N_SENDERS]=receiver

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
FILE    *dcqcn_log  = nullptr;
FILE    *fct_output = nullptr;

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

    fprintf(fout, "%08x %08x %u %u %lu %lu %lu %lu\n",
            q->sip.Get(), q->dip.Get(),
            q->sport, q->dport,
            q->m_size,
            q->startTime.GetTimeStep(),
            (Simulator::Now() - q->startTime).GetTimeStep(),
            standalone_fct);
    fflush(fout);

    // Clean up the receiver-side RX QP.
    Ptr<RdmaDriver> rdma = n.Get(did)->GetObject<RdmaDriver>();
    rdma->m_rdma->DeleteRxQp(q->sip.Get(), q->m_pg, q->sport);
}

// ---------------------------------------------------------------------------
// Routing (same as rdma-simple-dcqcn.cc)
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
// Periodic DCQCN state logger – samples all N senders each interval.
//
// CSV columns:
//   sender_id        – which sender (0 .. N_SENDERS-1)
//   time_ns          – simulation time (ns)
//   rate_bps         – current sending rate (bps)
//   target_rate_bps  – DCQCN target rate (bps)
//   alpha            – congestion estimate α ∈ [0,1]
//   rp_stage         – rate-increase stage (0=fast-recovery, 1+=active/hyper)
//   decrease_cnp     – 1 if CNP arrived since last rate-decrease check
//   alpha_cnp        – 1 if CNP arrived in current alpha-update slot
// ---------------------------------------------------------------------------
void LogDcqcnState()
{
    bool any_active = false;
    Ipv4Address receiverAddr = serverAddress[N_SENDERS];

    for (uint32_t i = 0; i < N_SENDERS; i++) {
        Ptr<RdmaDriver>    rdmaS = n.Get(i)->GetObject<RdmaDriver>();
        // All senders use sport=10000, pg=3; each has its own RdmaHw instance
        // so there is no key collision even though dip and sport are the same.
        Ptr<RdmaQueuePair> qp   = rdmaS->m_rdma->GetQp(receiverAddr.Get(), 10000, 3);
        if (qp == nullptr) continue;  // QP removed after flow completion
        any_active = true;

        fprintf(dcqcn_log,
                "%u,%lu,%lu,%lu,%.6f,%u,%d,%d\n",
                i,
                Simulator::Now().GetNanoSeconds(),
                qp->m_rate.GetBitRate(),
                qp->mlx.m_targetRate.GetBitRate(),
                qp->mlx.m_alpha,
                qp->mlx.m_rpTimeStage,
                (int)qp->mlx.m_decrease_cnp_arrived,
                (int)qp->mlx.m_alpha_cnp_arrived);
    }
    fflush(dcqcn_log);

    if (any_active)
        Simulator::Schedule(NanoSeconds(DCQCN_SAMPLE_NS), LogDcqcnState);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    // -----------------------------------------------------------------------
    // 1. CC-mode global config
    // -----------------------------------------------------------------------
    IntHeader::mode = IntHeader::NONE;  // DCQCN uses no INT header

    Config::SetDefault("ns3::QbbNetDevice::PauseTime",  UintegerValue(PAUSE_TIME));
    Config::SetDefault("ns3::QbbNetDevice::QcnEnabled", BooleanValue(true));

    // -----------------------------------------------------------------------
    // 2. Create nodes
    //    n[0 .. N_SENDERS-1] = senders
    //    n[N_SENDERS]        = receiver
    //    n[N_SENDERS+1]      = switch
    // -----------------------------------------------------------------------
    for (uint32_t i = 0; i < N_SENDERS; i++)
        n.Add(CreateObject<Node>());   // senders
    n.Add(CreateObject<Node>());       // receiver

    Ptr<SwitchNode> sw = CreateObject<SwitchNode>();
    sw->SetAttribute("EcnEnabled", BooleanValue(true));
    sw->SetNodeType(1);
    n.Add(sw);

    InternetStackHelper internet;
    Ipv4GlobalRoutingHelper globalRoutingHelper;
    internet.SetRoutingHelper(globalRoutingHelper);
    internet.Install(n);

    // Pre-assign RDMA addresses for all servers.
    serverAddress.resize(N_SENDERS + 1);
    for (uint32_t i = 0; i <= N_SENDERS; i++)
        serverAddress[i] = node_id_to_ip(i);

    // -----------------------------------------------------------------------
    // 3. Install 100G links
    // -----------------------------------------------------------------------
    QbbHelper qbb;
    qbb.SetDeviceAttribute("DataRate",   StringValue("100Gbps"));
    qbb.SetChannelAttribute("Delay",     StringValue("1us"));

    Ipv4AddressHelper ipv4Hlp;

    // Helper lambda – populate nbr2if for a just-installed link.
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

    // sender_i ── switch links
    std::vector<NetDeviceContainer> dSenders(N_SENDERS);
    for (uint32_t i = 0; i < N_SENDERS; i++) {
        dSenders[i] = qbb.Install(n.Get(i), sw);
        {
            Ptr<Ipv4> ip = n.Get(i)->GetObject<Ipv4>();
            ip->AddInterface(dSenders[i].Get(0));
            ip->AddAddress(1, Ipv4InterfaceAddress(serverAddress[i], Ipv4Mask(0xff000000)));
        }
        std::ostringstream base;
        base << "10.1." << (i + 1) << ".0";
        ipv4Hlp.SetBase(base.str().c_str(), "255.255.255.0");
        ipv4Hlp.Assign(dSenders[i]);
        registerLink(dSenders[i], n.Get(i), sw);
    }

    // receiver ── switch link
    NetDeviceContainer dReceiver = qbb.Install(n.Get(N_SENDERS), sw);
    {
        Ptr<Ipv4> ip = n.Get(N_SENDERS)->GetObject<Ipv4>();
        ip->AddInterface(dReceiver.Get(0));
        ip->AddAddress(1, Ipv4InterfaceAddress(serverAddress[N_SENDERS], Ipv4Mask(0xff000000)));
    }
    ipv4Hlp.SetBase("10.1.100.0", "255.255.255.0");
    ipv4Hlp.Assign(dReceiver);
    registerLink(dReceiver, n.Get(N_SENDERS), sw);

    // -----------------------------------------------------------------------
    // 4. Configure switch MMU (Dynamic Thresholds + ECN)
    // -----------------------------------------------------------------------
    {
        Ptr<QbbNetDevice> refDev = DynamicCast<QbbNetDevice>(dSenders[0].Get(0));
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
    // 5. Install RDMA driver on all servers (senders + receiver)
    // -----------------------------------------------------------------------
#if ENABLE_QP
    fct_output = fopen(FCT_FILE.c_str(), "w");
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

    for (uint32_t i = 0; i <= N_SENDERS; i++)
        installRdma(n.Get(i));
#endif

    RdmaEgressQueue::ack_q_idx = 3;

    // -----------------------------------------------------------------------
    // 6. Routing
    // -----------------------------------------------------------------------
    CalculateRoutes();
    SetRoutingEntries();

    // -----------------------------------------------------------------------
    // 7. Compute BDP / RTT for all sender → receiver pairs
    // -----------------------------------------------------------------------
    Ptr<Node> receiver = n.Get(N_SENDERS);
    for (uint32_t i = 0; i < N_SENDERS; i++) {
        Ptr<Node> sender = n.Get(i);
        uint64_t delay   = pairDelay[sender][receiver];
        uint64_t txDelay = pairTxDelay[sender][receiver];
        uint64_t rtt     = delay * 2 + txDelay;
        uint64_t bw      = pairBw[i][N_SENDERS];
        uint64_t bdp     = rtt * bw / 1000000000 / 8;
        pairBdp[sender][receiver] = bdp;
        pairRtt[i][N_SENDERS] = rtt;
        if (bdp > maxBdp) maxBdp = bdp;
        if (rtt > maxRtt) maxRtt = rtt;
    }
    printf("maxRtt=%lu ns   maxBdp=%lu bytes\n", maxRtt, maxBdp);

    // -----------------------------------------------------------------------
    // 8. Configure switch CC
    // -----------------------------------------------------------------------
    sw->SetAttribute("CcMode",       UintegerValue(CC_MODE));
    sw->SetAttribute("MaxRtt",       UintegerValue(maxRtt));
    sw->SetAttribute("PowerEnabled", BooleanValue(false));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // -----------------------------------------------------------------------
    // 9. Install flows: all senders → receiver, start simultaneously
    // -----------------------------------------------------------------------
#if ENABLE_QP
    for (uint32_t i = 0; i < N_SENDERS; i++) {
        RdmaClientHelper clientHelper(
            3,                        // priority group
            serverAddress[i],         // source IP
            serverAddress[N_SENDERS], // destination IP (receiver)
            10000,                    // source port  (same on all senders – each
            10000,                    // dest port     has its own RdmaHw instance)
            FLOW_SIZE_BYTES,
            maxBdp,
            maxRtt,
            Simulator::GetMaximumSimulationTime()
        );
        ApplicationContainer app = clientHelper.Install(n.Get(i));
        app.Start(Seconds(0.0));
    }
#endif

    // -----------------------------------------------------------------------
    // 10. Pcap on key switch ports
    //
    // switch → receiver port  (data from all senders; ECN-marked packets)
    // switch → sender0 port   (CNPs and ACKs flowing back to sender 0)
    // -----------------------------------------------------------------------
    qbb.EnablePcap(PCAP_PREFIX, dReceiver.Get(1),   false);  // switch → receiver
    qbb.EnablePcap(PCAP_PREFIX, dSenders[0].Get(1), false);  // switch → sender 0

    // -----------------------------------------------------------------------
    // 11. DCQCN congestion-state logger
    // -----------------------------------------------------------------------
#if ENABLE_QP
    dcqcn_log = fopen(DCQCN_LOG_FILE.c_str(), "w");
    NS_ASSERT_MSG(dcqcn_log, "Could not open " << DCQCN_LOG_FILE
                  << " – make sure the 'mix/' directory exists.");
    fprintf(dcqcn_log,
            "sender_id,time_ns,rate_bps,target_rate_bps,alpha,rp_stage,decrease_cnp,alpha_cnp\n");
    Simulator::Schedule(NanoSeconds(DCQCN_SAMPLE_NS), LogDcqcnState);
#endif

    cout << "\nTopology : " << N_SENDERS << " senders ── 100G/1µs ── switch ── 100G/1µs ── receiver\n";
    cout << "CC mode  : DCQCN (cc_mode=" << CC_MODE << ")\n";
    cout << "Flows    : " << N_SENDERS << " × " << FLOW_SIZE_BYTES / 1e6
         << " MB (all start at t=0, " << (double)N_SENDERS * 100 << " Gbps offered → 100 Gbps bottleneck)\n";
    cout << "ECN      : Kmin=" << KMIN_100G << " KB  Kmax=" << KMAX_100G << " KB\n";
    cout << "Stop at  : " << SIM_STOP_S << " s\n";
    cout << "CC log   : " << DCQCN_LOG_FILE << " (sampled every " << DCQCN_SAMPLE_NS << " ns)\n\n";

    Simulator::Stop(Seconds(SIM_STOP_S));
    Simulator::Run();
    Simulator::Destroy();

    if (dcqcn_log)  fclose(dcqcn_log);
    if (fct_output) fclose(fct_output);

    cout << "\nDone. FCT results: " << FCT_FILE
         << "\n     CC log:       " << DCQCN_LOG_FILE << "\n";
    return 0;
}
