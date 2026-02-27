-- =============================================================================
-- rdma-ns3-dissector.lua
-- Wireshark Lua dissector for the custom RDMA-over-IP protocol used by the
-- ns-3 HPCC / PowerTCP / DCQCN simulator (QbbNetDevice / CustomHeader).
--
-- INSTALL
--   Linux  : copy to  ~/.local/lib/wireshark/plugins/
--   macOS  : copy to  ~/.wireshark/plugins/  (or  ~/Library/Application Support/Wireshark/plugins/)
--   Windows: copy to  %APPDATA%\Wireshark\plugins\
--
--   Or pass directly on the command line:
--     wireshark --lua-script rdma-ns3-dissector.lua -r mix/rdma-simple-2-2.pcap
--     tshark   --lua-script rdma-ns3-dissector.lua -r mix/rdma-simple-2-1.pcap
--
-- NOTE ON SERVER-NIC PCAP FILES
--   QbbNetDevice::Receive() on host nodes dispatches RDMA packets directly to
--   the RDMA driver callback (m_rdmaReceiveCb) without firing m_promiscSnifferTrace.
--   RDMA TX likewise calls TransmitStart directly, bypassing the sniffer.
--   Therefore server-NIC pcap files (node 0 / node 1) are always empty for RDMA
--   traffic.  Only the SWITCH ports (node 2) produce useful captures:
--     mix/rdma-simple-2-1.pcap  →  switch transmitting toward serverA (ACKs, CNPs, PFC)
--     mix/rdma-simple-2-2.pcap  →  switch transmitting toward serverB (RDMA data)
--
-- PACKET FORMAT REFERENCE (CustomHeader.cc / IntHeader.cc)
-- ─────────────────────────────────────────────────────────
-- pcap link type : DLT_PPP (9)
-- PPP frame      : [2B proto BE] → 0x0021=IPv4
-- IPv4           : standard 20-byte header; IP Protocol field identifies type
--
--  ip.proto=0x11 (UDP)   → RDMA Data
--    UDP header (8B, big-endian fields, handled by Wireshark)
--    seq      4B  big-endian   (WriteHtonU32)
--    pg       2B  big-endian   (WriteHtonU16)
--    INT header              (mode-dependent, see preference)
--    <RDMA payload>
--
--  ip.proto=0xFF (CNP)   → Congestion Notification Packet / QCN
--    qIndex   1B
--    fid      2B  little-endian  (WriteU16)
--    ecnBits  1B
--    qfb      2B  little-endian  (WriteU16)
--    total    2B  little-endian  (WriteU16)
--
--  ip.proto=0xFC (ACK) / 0xFD (NACK)
--    sport    2B  little-endian  (WriteU16)
--    dport    2B  little-endian  (WriteU16)
--    flags    2B  little-endian  (WriteU16)   bit0=CNP
--    pg       2B  little-endian  (WriteU16)
--    seq      4B  little-endian  (WriteU32)
--    INT header              (mode-dependent)
--
--  ip.proto=0xFE (PFC)   → Priority Flow Control
--    time     4B  little-endian  (WriteU32)   simulator time steps
--    qlen     4B  little-endian  (WriteU32)   bytes
--    qIndex   1B
--
-- INT HEADER (appended to Data / ACK / NACK when mode ≠ NONE)
--   NONE   : 0 bytes     (DCQCN, TIMELY)
--   NORMAL : 42 bytes    (HPCC, PowerTCP) — 5 hops × 8B LE + 2B nhop LE
--   TS     : 8 bytes     (TIMELY with timestamps) — uint64 LE
--   PINT   : 1 or 2 bytes LE
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Preferences (attach to a "parent" proto so they appear in Edit→Preferences)
-- ---------------------------------------------------------------------------
local rdma_ns3_prefs = Proto("rdma_ns3", "ns3 RDMA/DCQCN Simulator")
rdma_ns3_prefs.prefs.int_mode = Pref.enum(
    "INT Header mode",
    0,
    "Must match IntHeader::mode used in the simulation "
    .. "(0=NONE for DCQCN/TIMELY, 1=NORMAL for HPCC/PowerTCP, 2=TS, 3=PINT)",
    {
        { "NONE  – 0 bytes  (DCQCN / TIMELY)",          0 },
        { "NORMAL – 42 bytes (HPCC / PowerTCP)",        1 },
        { "TS    – 8 bytes  (TIMELY with timestamps)",  2 },
        { "PINT  – 1 or 2 bytes",                       3 },
    },
    false   -- show as drop-down, not radio buttons
)
rdma_ns3_prefs.prefs.pint_bytes = Pref.uint(
    "PINT bytes (1 or 2)",
    2,
    "Number of bytes in the PINT header (only used when INT mode = PINT)"
)
rdma_ns3_prefs.prefs.rdma_udp_port = Pref.uint(
    "RDMA data UDP port",
    10000,
    "UDP destination port on which RDMA Write data is carried (default 10000)"
)

-- Give the preferences proto a dummy dissector so Wireshark does not warn
function rdma_ns3_prefs.dissector() end

-- Convenience accessors
local function int_mode()   return rdma_ns3_prefs.prefs.int_mode   end
local function pint_bytes() return rdma_ns3_prefs.prefs.pint_bytes end

local function int_size()
    local m = int_mode()
    if     m == 1 then return 42        -- NORMAL: 5*8 + 2
    elseif m == 2 then return 8         -- TS
    elseif m == 3 then return pint_bytes()  -- PINT
    else               return 0         -- NONE
    end
end

-- Line-rate index → human string (IntHop::lineRateValues)
local LINE_RATE = {
    [0]="25 Gbps", [1]="50 Gbps",  [2]="100 Gbps", [3]="200 Gbps",
    [4]="400 Gbps",[5]="0 (rsvd)", [6]="0 (rsvd)", [7]="40 Gbps"
}

-- ECN bits → human string
local ECN_NAMES = {
    [0]="Not ECN-Capable (NotECT)",
    [1]="ECN Capable Transport ECT(1)",
    [2]="ECN Capable Transport ECT(0)",
    [3]="Congestion Encountered (CE)"
}

-- ACK flags (bit 0 = CNP)
local F_ACK_CNP_MASK = 0x0001

-- ---------------------------------------------------------------------------
-- INT header dissector (shared helper)
-- tvb  : packet tvb
-- tree : subtree to add fields into
-- off  : byte offset where INT data starts
-- returns number of bytes consumed
-- ---------------------------------------------------------------------------
-- Field definitions for INT hop (defined here because they are shared)
local f_int_nhop     = ProtoField.uint16("rdma_ns3.int.nhop",          "nhop (hops filled)", base.DEC)
local f_int_ts       = ProtoField.uint64("rdma_ns3.int.ts",            "Timestamp",          base.DEC)
local f_int_pint     = ProtoField.uint16("rdma_ns3.int.pint",          "PINT power",         base.HEX)
local f_int_hop_lr   = ProtoField.uint8 ("rdma_ns3.int.hop.linerate",  "Line rate",          base.DEC, LINE_RATE)
local f_int_hop_time = ProtoField.uint32("rdma_ns3.int.hop.time",      "Time (sim steps)",   base.DEC)
local f_int_hop_byt  = ProtoField.uint32("rdma_ns3.int.hop.bytes",     "Bytes (×128)",       base.DEC)
local f_int_hop_qlen = ProtoField.uint32("rdma_ns3.int.hop.qlen",      "Qlen (×80)",         base.DEC)

local function dissect_int(tvb, tree, off)
    local m = int_mode()
    if m == 0 then return 0 end   -- NONE

    local int_tree = tree:add(tvb(off, int_size()), "INT Header")

    if m == 1 then   -- NORMAL: 5 hops × 8 bytes LE + 2 bytes nhop LE
        for h = 0, 4 do
            local hoff = off + h * 8
            local lo = tvb(hoff,   4):le_uint()   -- buf[0]
            local hi = tvb(hoff+4, 4):le_uint()   -- buf[1]

            -- IntHop bit layout (LSB-first, per C++ struct bit-fields on x86):
            --   buf[0] bits  0- 2 : lineRate (3 bits)
            --   buf[0] bits  3-26 : time     (24 bits)
            --   buf[0] bits 27-31 : bytes[4:0] (low 5 bits of 20-bit field)
            --   buf[1] bits  0-14 : bytes[19:5] (high 15 bits)
            --   buf[1] bits 15-31 : qlen     (17 bits)
            local lr       = bit.band(lo, 0x7)
            local time_val = bit.band(bit.rshift(lo, 3), 0xFFFFFF)
            local bytes_lo = bit.rshift(lo, 27)                        -- 5 low bits
            local bytes_hi = bit.band(hi, 0x7FFF)                     -- 15 high bits
            local bytes_v  = bit.bor(bit.lshift(bytes_hi, 5), bytes_lo)
            local qlen_v   = bit.rshift(hi, 15)

            local rate_str = LINE_RATE[lr] or ("idx "..lr)
            local hop_tree = int_tree:add(tvb(hoff, 8),
                string.format("Hop %d: rate=%s  time=%d  bytes=%d  qlen=%d",
                              h, rate_str,
                              time_val,
                              bytes_v * 128,
                              qlen_v  * 80))
            hop_tree:add(f_int_hop_lr,   tvb(hoff, 1)):set_text(
                string.format("Line rate: %s (idx %d)", rate_str, lr))
            hop_tree:add(f_int_hop_time, tvb(hoff, 4)):set_text(
                string.format("Time: %d simulator steps", time_val))
            hop_tree:add(f_int_hop_byt,  tvb(hoff+4, 4)):set_text(
                string.format("Bytes: %d (raw %d × 128)", bytes_v * 128, bytes_v))
            hop_tree:add(f_int_hop_qlen, tvb(hoff+4, 4)):set_text(
                string.format("Queue length: %d B (raw %d × 80)", qlen_v * 80, qlen_v))
        end
        int_tree:add_le(f_int_nhop, tvb(off + 40, 2))
        return 42

    elseif m == 2 then   -- TS: 8-byte little-endian uint64
        int_tree:add_le(f_int_ts, tvb(off, 8))
        return 8

    elseif m == 3 then   -- PINT
        local pb = pint_bytes()
        int_tree:add_le(f_int_pint, tvb(off, pb))
        return pb
    end
    return 0
end

-- =============================================================================
-- 1. RDMA Data (UDP payload dissector, registered on udp.port)
-- =============================================================================
local rdma_data = Proto("rdma_ns3_data", "ns3 RDMA Write Data")

local f_data_seq = ProtoField.uint32("rdma_ns3_data.seq", "Sequence Number", base.DEC)
local f_data_pg  = ProtoField.uint16("rdma_ns3_data.pg",  "Priority Group",  base.DEC)

rdma_data.fields = { f_data_seq, f_data_pg,
                     f_int_nhop, f_int_ts, f_int_pint,
                     f_int_hop_lr, f_int_hop_time, f_int_hop_byt, f_int_hop_qlen }

function rdma_data.dissector(tvb, pinfo, tree)
    -- tvb here is the UDP *payload* (Wireshark already stripped the UDP header)
    if tvb:len() < 6 then return 0 end

    pinfo.cols.protocol:set("RDMA-DATA")

    local subtree = tree:add(rdma_data, tvb(), "ns3 RDMA Write Data")
    local off = 0

    -- seq and pg are written with WriteHtonU32 / WriteHtonU16 → big-endian
    subtree:add(f_data_seq, tvb(off, 4)); local seq = tvb(off, 4):uint(); off = off + 4
    subtree:add(f_data_pg,  tvb(off, 2)); local pg  = tvb(off, 2):uint(); off = off + 2

    local int_bytes = dissect_int(tvb, subtree, off)
    off = off + int_bytes

    local payload = tvb:len() - off
    if payload > 0 then
        subtree:add(tvb(off, payload), string.format("RDMA Payload (%d bytes)", payload))
    end

    pinfo.cols.info:set(string.format(
        "RDMA Write  pg=%d  seq=%d  payload=%dB", pg, seq, payload))
    return tvb:len()
end

-- =============================================================================
-- 2. CNP – Congestion Notification Packet (ip.proto = 0xFF)
-- =============================================================================
local rdma_cnp = Proto("rdma_ns3_cnp", "ns3 RDMA CNP (QCN)")

local f_cnp_qidx   = ProtoField.uint8 ("rdma_ns3_cnp.qIndex",  "Queue Index",  base.DEC)
local f_cnp_fid    = ProtoField.uint16("rdma_ns3_cnp.fid",     "Flow ID",      base.DEC)
local f_cnp_ecn    = ProtoField.uint8 ("rdma_ns3_cnp.ecnBits", "ECN Bits",     base.HEX, ECN_NAMES)
local f_cnp_qfb    = ProtoField.uint16("rdma_ns3_cnp.qfb",     "Queue FB",     base.DEC)
local f_cnp_total  = ProtoField.uint16("rdma_ns3_cnp.total",   "Total",        base.DEC)

rdma_cnp.fields = { f_cnp_qidx, f_cnp_fid, f_cnp_ecn, f_cnp_qfb, f_cnp_total }

function rdma_cnp.dissector(tvb, pinfo, tree)
    if tvb:len() < 8 then return 0 end

    pinfo.cols.protocol:set("RDMA-CNP")

    local subtree = tree:add(rdma_cnp, tvb(0, 8), "ns3 RDMA CNP")
    local off = 0

    subtree:add(f_cnp_qidx,  tvb(off, 1)); local qidx = tvb(off,1):uint();    off = off + 1
    subtree:add_le(f_cnp_fid,   tvb(off, 2)); local fid  = tvb(off,2):le_uint(); off = off + 2
    subtree:add(f_cnp_ecn,   tvb(off, 1)); local ecn  = tvb(off,1):uint();    off = off + 1
    subtree:add_le(f_cnp_qfb,   tvb(off, 2)); local qfb  = tvb(off,2):le_uint(); off = off + 2
    subtree:add_le(f_cnp_total, tvb(off, 2)); local tot  = tvb(off,2):le_uint()

    local ecn_str = ECN_NAMES[ecn] or string.format("0x%02x", ecn)
    pinfo.cols.info:set(string.format(
        "CNP  qIdx=%d  fid=%d  ecn=[%s]  qfb=%d", qidx, fid, ecn_str, qfb))

    if ecn == 3 then
        local ei = tree:add_proto_expert_info and
            subtree:add_expert_info(PI_SEQUENCE, PI_WARN, "Congestion Encountered (CE) marked")
    end
    return 8
end

-- =============================================================================
-- 3. ACK (ip.proto = 0xFC)
-- =============================================================================
local rdma_ack = Proto("rdma_ns3_ack", "ns3 RDMA ACK")

local f_ack_sport  = ProtoField.uint16("rdma_ns3_ack.sport",     "Source Port",    base.DEC)
local f_ack_dport  = ProtoField.uint16("rdma_ns3_ack.dport",     "Dest Port",      base.DEC)
local f_ack_flags  = ProtoField.uint16("rdma_ns3_ack.flags",     "Flags",          base.HEX)
local f_ack_cnp    = ProtoField.bool  ("rdma_ns3_ack.flags.cnp", "CNP Flag",
                                       16, {"Set","Not set"}, F_ACK_CNP_MASK)
local f_ack_pg     = ProtoField.uint16("rdma_ns3_ack.pg",        "Priority Group", base.DEC)
local f_ack_seq    = ProtoField.uint32("rdma_ns3_ack.seq",       "Sequence Number",base.DEC)

rdma_ack.fields = { f_ack_sport, f_ack_dport, f_ack_flags, f_ack_cnp, f_ack_pg, f_ack_seq,
                    f_int_nhop, f_int_ts, f_int_pint,
                    f_int_hop_lr, f_int_hop_time, f_int_hop_byt, f_int_hop_qlen }

local function dissect_ack_common(tvb, pinfo, tree, label)
    if tvb:len() < 12 then return 0 end

    local subtree = tree:add(rdma_ack, tvb(), "ns3 RDMA " .. label)
    local off = 0

    -- All ACK/NACK fields use WriteU16 / WriteU32 → little-endian
    subtree:add_le(f_ack_sport, tvb(off, 2)); local sport = tvb(off,2):le_uint(); off = off + 2
    subtree:add_le(f_ack_dport, tvb(off, 2)); local dport = tvb(off,2):le_uint(); off = off + 2

    local flags_tree = subtree:add_le(f_ack_flags, tvb(off, 2))
    flags_tree:add_le(f_ack_cnp, tvb(off, 2))
    local flags = tvb(off, 2):le_uint(); off = off + 2

    subtree:add_le(f_ack_pg,  tvb(off, 2)); local pg  = tvb(off,2):le_uint(); off = off + 2
    subtree:add_le(f_ack_seq, tvb(off, 4)); local seq = tvb(off,4):le_uint(); off = off + 4

    dissect_int(tvb, subtree, off)

    local cnp_str = (bit.band(flags, F_ACK_CNP_MASK) ~= 0) and " [CNP]" or ""
    pinfo.cols.info:set(string.format(
        "%s  sport=%d  dport=%d  pg=%d  seq=%d%s",
        label, sport, dport, pg, seq, cnp_str))
    return tvb:len()
end

function rdma_ack.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol:set("RDMA-ACK")
    return dissect_ack_common(tvb, pinfo, tree, "ACK")
end

-- =============================================================================
-- 4. NACK (ip.proto = 0xFD) – same layout as ACK
-- =============================================================================
local rdma_nack = Proto("rdma_ns3_nack", "ns3 RDMA NACK")
rdma_nack.fields = rdma_ack.fields   -- same field set

function rdma_nack.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol:set("RDMA-NACK")
    return dissect_ack_common(tvb, pinfo, tree, "NACK")
end

-- =============================================================================
-- 5. PFC – Priority Flow Control (ip.proto = 0xFE)
-- =============================================================================
local rdma_pfc = Proto("rdma_ns3_pfc", "ns3 RDMA PFC")

local f_pfc_time   = ProtoField.uint32("rdma_ns3_pfc.time",   "Pause Time (sim steps)", base.DEC)
local f_pfc_qlen   = ProtoField.uint32("rdma_ns3_pfc.qlen",   "Queue Length (bytes)",   base.DEC)
local f_pfc_qidx   = ProtoField.uint8 ("rdma_ns3_pfc.qIndex", "Queue Index",            base.DEC)

rdma_pfc.fields = { f_pfc_time, f_pfc_qlen, f_pfc_qidx }

function rdma_pfc.dissector(tvb, pinfo, tree)
    if tvb:len() < 9 then return 0 end

    pinfo.cols.protocol:set("RDMA-PFC")

    local subtree = tree:add(rdma_pfc, tvb(0, 9), "ns3 RDMA PFC")
    local off = 0

    -- PFC fields use WriteU32 / WriteU8 → little-endian
    subtree:add_le(f_pfc_time, tvb(off, 4)); local t    = tvb(off,4):le_uint(); off = off + 4
    subtree:add_le(f_pfc_qlen, tvb(off, 4)); local qlen = tvb(off,4):le_uint(); off = off + 4
    subtree:add   (f_pfc_qidx, tvb(off, 1)); local qi   = tvb(off,1):uint()

    pinfo.cols.info:set(string.format(
        "PFC  qIdx=%d  pause=%d steps  qlen=%dB", qi, t, qlen))
    return 9
end

-- =============================================================================
-- Registration
-- =============================================================================
local ip_proto_table = DissectorTable.get("ip.proto")
ip_proto_table:add(0xFF, rdma_cnp)
ip_proto_table:add(0xFC, rdma_ack)
ip_proto_table:add(0xFD, rdma_nack)
ip_proto_table:add(0xFE, rdma_pfc)

-- Register the RDMA data dissector on the configured UDP port.
-- If the port preference changes, Wireshark automatically re-registers
-- after reloading Lua (Analyze → Reload Lua Plugins).
local udp_table = DissectorTable.get("udp.port")
udp_table:add(rdma_ns3_prefs.prefs.rdma_udp_port, rdma_data)
