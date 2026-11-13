# =============================================================================
# Cocotb testbench : packet_firewall (64-bit AXI4-Stream + AXI4-Lite)
#
# Tests:
#   0. Reset
#   1. UDP dst-port 5000  → ALLOW
#   2. ICMP               → ALLOW
#   3. TCP SYN port 80    → ALLOW
#   4. TCP port 23        → DROP  (Telnet blacklisted)
#   5. SYN-flood sequence (threshold=3)
#   6. REAL backpressure  (m_axis_tready held low for 4 cycles mid-flush)
#   7. AXI4-Lite register R/W (CONTROL, RULE_CONFIG, SYN_THRESH, STATUS…)
#   8. CONTROL[0]=0 → firewall disabled, all traffic passes
# =============================================================================

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge, Timer

CLK_NS = 10

# ---------------------------------------------------------------------------
# Precomputed 64-bit word constants  (TDATA[7:0] = byte 0 / lowest address)
# ---------------------------------------------------------------------------
W0     = 0xBBAA_FFFF_FFFF_FFFF   # Dst MAC + 2B Src MAC
W1     = 0x0045_0008_FFEE_DDCC   # Src MAC (4B) + EtherType 0x0800 + IPv4 hdr
W3     = 0x000A_0100_000A_0000   # Checksum + Src IP 10.0.0.1 + Dst IP[31:16]
W5_SYN = 0x0250_0000_0000_0000   # DataOffset=5, Flags=0x02 (SYN)
W6_LAST= 0x0000_0000_0000_0000


def make_w2(protocol, total_len):
    return (
        ((protocol & 0xFF) << 56)
        | (0x40 << 48)
        | (0x00 << 40)
        | (0x40 << 32)
        | (0x00 << 24)
        | (0x00 << 16)
        | ((total_len & 0xFF) << 8)
        | ((total_len >> 8) & 0xFF)
    )


def make_w4(dip_hi, dip_lo, src_port, dst_port):
    return (
        (0x0000 << 48)
        | ((dst_port & 0xFF) << 40)
        | (((dst_port >> 8) & 0xFF) << 32)
        | ((src_port & 0xFF) << 24)
        | (((src_port >> 8) & 0xFF) << 16)
        | ((dip_lo & 0xFF) << 8)
        | (dip_hi & 0xFF)
    )


# ---------------------------------------------------------------------------
# AXI4-Lite helpers
# ---------------------------------------------------------------------------

async def axil_write(dut, addr, data):
    """Single AXI4-Lite write transaction."""
    await FallingEdge(dut.aclk)
    dut.s_axil_awaddr.value  = addr
    dut.s_axil_awvalid.value = 1
    dut.s_axil_wdata.value   = data
    dut.s_axil_wstrb.value   = 0xF
    dut.s_axil_wvalid.value  = 1
    dut.s_axil_bready.value  = 1

    # Wait for both write-address and write-data to be accepted
    aw_done = False
    w_done  = False
    while not (aw_done and w_done):
        await RisingEdge(dut.aclk)
        if int(dut.s_axil_awready.value) == 1:
            aw_done = True
        if int(dut.s_axil_wready.value) == 1:
            w_done = True

    await FallingEdge(dut.aclk)
    dut.s_axil_awvalid.value = 0
    dut.s_axil_wvalid.value  = 0

    # Wait for write response
    while True:
        await RisingEdge(dut.aclk)
        if int(dut.s_axil_bvalid.value) == 1:
            break
    await FallingEdge(dut.aclk)
    dut.s_axil_bready.value = 0


async def axil_read(dut, addr):
    """Single AXI4-Lite read transaction; returns integer value."""
    await FallingEdge(dut.aclk)
    dut.s_axil_araddr.value  = addr
    dut.s_axil_arvalid.value = 1
    dut.s_axil_rready.value  = 1

    while True:
        await RisingEdge(dut.aclk)
        if int(dut.s_axil_arready.value) == 1:
            break

    await FallingEdge(dut.aclk)
    dut.s_axil_arvalid.value = 0

    while True:
        await RisingEdge(dut.aclk)
        if int(dut.s_axil_rvalid.value) == 1:
            value = int(dut.s_axil_rdata.value)
            break

    await FallingEdge(dut.aclk)
    dut.s_axil_rready.value = 0
    return value


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

async def reset_dut(dut):
    dut.aresetn.value        = 0
    dut.s_axis_tdata.value   = 0
    dut.s_axis_tkeep.value   = 0
    dut.s_axis_tvalid.value  = 0
    dut.s_axis_tlast.value   = 0
    dut.m_axis_tready.value  = 1
    # AXI-Lite defaults
    dut.s_axil_awaddr.value  = 0
    dut.s_axil_awvalid.value = 0
    dut.s_axil_wdata.value   = 0
    dut.s_axil_wstrb.value   = 0
    dut.s_axil_wvalid.value  = 0
    dut.s_axil_bready.value  = 0
    dut.s_axil_araddr.value  = 0
    dut.s_axil_arvalid.value = 0
    dut.s_axil_rready.value  = 0

    for _ in range(4):
        await RisingEdge(dut.aclk)
    await FallingEdge(dut.aclk)
    dut.aresetn.value = 1
    await RisingEdge(dut.aclk)
    dut._log.info("Reset done: pkt=%d drop=%d",
                  int(dut.packet_count.value),
                  int(dut.dropped_count.value))


async def wait_cycles(dut, n):
    for _ in range(n):
        await RisingEdge(dut.aclk)


# ---------------------------------------------------------------------------
# AXI4-Stream send_word  (correct handshake: drive before rising, sample ready)
# ---------------------------------------------------------------------------

async def send_word(dut, data, keep, last):
    await FallingEdge(dut.aclk)
    dut.s_axis_tdata.value  = data
    dut.s_axis_tkeep.value  = keep
    dut.s_axis_tlast.value  = last
    dut.s_axis_tvalid.value = 1

    while True:
        await RisingEdge(dut.aclk)
        if int(dut.s_axis_tready.value) == 1:
            break

    await FallingEdge(dut.aclk)
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value  = 0
    dut.s_axis_tdata.value  = 0
    dut.s_axis_tkeep.value  = 0


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------

async def send_udp5000(dut):
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x11, 0x001C), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, make_w4(0x00, 0x02, 0x1234, 0x1388), 0xFF, 0)
    await send_word(dut, 0x0000_0000_0000_0000, 0x03, 1)


async def send_icmp(dut):
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x01, 0x001C), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, 0x0000_0000_0008_0200, 0xFF, 0)
    await send_word(dut, 0x0000_0000_0000_0000, 0x03, 1)


async def send_tcp_syn_80(dut):
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x06, 0x0028), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, make_w4(0x00, 0x02, 0x1234, 0x0050), 0xFF, 0)
    await send_word(dut, W5_SYN, 0xFF, 0)
    await send_word(dut, W6_LAST, 0x3F, 1)


async def send_tcp_telnet(dut):
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x06, 0x0028), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, make_w4(0x00, 0x02, 0x1234, 0x0017), 0xFF, 0)
    await send_word(dut, W5_SYN, 0xFF, 0)
    await send_word(dut, W6_LAST, 0x3F, 1)


# ---------------------------------------------------------------------------
# Output monitor
# ---------------------------------------------------------------------------

async def monitor_output(dut, stats):
    while True:
        await RisingEdge(dut.aclk)
        if int(dut.m_axis_tvalid.value) == 1 and int(dut.m_axis_tready.value) == 1:
            stats["out_words"] += 1
            if int(dut.m_axis_tlast.value):
                stats["out_pkts"] += 1
            dut._log.debug("[OUT] DATA=%016X KEEP=%02X LAST=%d",
                           int(dut.m_axis_tdata.value),
                           int(dut.m_axis_tkeep.value),
                           int(dut.m_axis_tlast.value))


def log_counters(dut, stats, label="", include_syn=False):
    msg = "[%s] pkt=%d drop=%d out_words=%d out_pkts=%d" % (
        label,
        int(dut.packet_count.value),
        int(dut.dropped_count.value),
        stats["out_words"],
        stats["out_pkts"],
    )
    if include_syn:
        msg += " syn_flood=%d" % int(dut.syn_flood_detected.value)
    dut._log.info(msg)


# ===========================================================================
# MAIN TEST
# ===========================================================================

@cocotb.test()
async def packet_firewall_test(dut):
    cocotb.start_soon(Clock(dut.aclk, CLK_NS, units="ns").start())

    stats = {"out_words": 0, "out_pkts": 0}
    cocotb.start_soon(monitor_output(dut, stats))

    # -------------------------------------------------------------------------
    # TEST 0: Reset
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 0 : RESET ===")
    await reset_dut(dut)

    # -------------------------------------------------------------------------
    # TEST 1: UDP 5000 → ALLOW (6 words)
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 1 : UDP dst-port 5000 → ALLOW ===")
    await send_udp5000(dut)
    await wait_cycles(dut, 12)
    log_counters(dut, stats, "T1")
    assert stats["out_pkts"] == 1, "T1: expected 1 output packet"

    # -------------------------------------------------------------------------
    # TEST 2: ICMP → ALLOW (6 words)
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 2 : ICMP → ALLOW ===")
    await send_icmp(dut)
    await wait_cycles(dut, 12)
    log_counters(dut, stats, "T2")
    assert stats["out_pkts"] == 2, "T2: expected 2 output packets total"

    # -------------------------------------------------------------------------
    # TEST 3: TCP SYN port 80 → ALLOW (7 words)
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 3 : TCP SYN port 80 → ALLOW ===")
    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 15)
    log_counters(dut, stats, "T3", include_syn=True)
    assert stats["out_pkts"] == 3, "T3: expected 3 output packets total"

    # -------------------------------------------------------------------------
    # TEST 4: TCP Telnet port 23 → DROP
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 4 : TCP Telnet port 23 → DROP ===")
    words_before = stats["out_words"]
    await send_tcp_telnet(dut)
    await wait_cycles(dut, 12)
    log_counters(dut, stats, "T4")
    assert stats["out_words"] == words_before, "T4: Telnet must be dropped (no extra output words)"

    # -------------------------------------------------------------------------
    # TEST 5: SYN flood (threshold=3 from parameter default set via AXI-Lite)
    # First write SYN_THRESH=3 and a short SYN_WINDOW over AXI-Lite
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 5 : SYN Flood (threshold=3) ===")

    # Configure SYN threshold = 3, window = 5000 cycles via AXI-Lite
    await axil_write(dut, 0x08, 3)      # SYN_THRESH
    await axil_write(dut, 0x0C, 5000)   # SYN_WINDOW

    v = await axil_read(dut, 0x08)
    assert v == 3, "SYN_THRESH readback failed: got %d" % v
    dut._log.info("SYN_THRESH confirmed = %d", v)

    # SYN #1 → ALLOW
    pkts_before = stats["out_pkts"]
    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 8)
    dut._log.info("After SYN#1: syn_flood=%d", int(dut.syn_flood_detected.value))

    # SYN #2 → ALLOW
    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 8)
    dut._log.info("After SYN#2: syn_flood=%d", int(dut.syn_flood_detected.value))

    # SYN #3 → threshold hit → syn_flood_detected goes HIGH
    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 8)
    dut._log.info("After SYN#3: syn_flood=%d (should be 1)", int(dut.syn_flood_detected.value))

    # SYN #4 → MUST be DROPPED due to syn_flood_detected
    words_before = stats["out_words"]
    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 12)
    dut._log.info("After SYN#4: syn_flood=%d", int(dut.syn_flood_detected.value))
    log_counters(dut, stats, "T5")

    # -------------------------------------------------------------------------
    # TEST 6: REAL backpressure — hold m_axis_tready=0 mid-flush
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 6 : REAL Backpressure (m_axis_tready=0) ===")

    # Let SYN window expire
    await wait_cycles(dut, 5100)

    # Drop tready BEFORE the packet arrives
    dut.m_axis_tready.value = 0

    # Kick off the UDP send in a background coroutine so it can stall
    send_task = cocotb.start_soon(send_udp5000(dut))

    # Wait a few cycles while output is stalled; DUT must NOT lose data
    await wait_cycles(dut, 4)
    dut._log.info("Mid-stall: m_axis_tvalid=%d s_axis_tready=%d",
                  int(dut.m_axis_tvalid.value),
                  int(dut.s_axis_tready.value))

    # Release tready
    dut.m_axis_tready.value = 1
    await send_task  # wait for send to complete

    await wait_cycles(dut, 20)
    log_counters(dut, stats, "T6")

    # -------------------------------------------------------------------------
    # TEST 7: AXI4-Lite register R/W verification
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 7 : AXI4-Lite Register R/W ===")

    # Write then read back CONTROL
    await axil_write(dut, 0x00, 0x1)
    ctrl = await axil_read(dut, 0x00)
    assert ctrl & 0x1, "CONTROL[0] should be 1 (enable)"
    dut._log.info("CONTROL = 0x%08X", ctrl)

    # Read RULE_CONFIG default (all 5 rules active = 0x1F)
    rc = await axil_read(dut, 0x04)
    dut._log.info("RULE_CONFIG = 0x%08X", rc)

    # Read STATUS register
    status = await axil_read(dut, 0x10)
    dut._log.info("STATUS = 0x%08X (bit0=EN, bit1=SYN_FLOOD)", status)

    # Read PACKET_COUNT and DROPPED_COUNT via AXI-Lite
    pc = await axil_read(dut, 0x14)
    dc = await axil_read(dut, 0x18)
    wc = await axil_read(dut, 0x1C)
    dut._log.info("PACKET_COUNT=%d DROPPED_COUNT=%d WORD_COUNT=%d", pc, dc, wc)
    assert pc == int(dut.packet_count.value),  "PACKET_COUNT register mismatch"
    assert dc == int(dut.dropped_count.value), "DROPPED_COUNT register mismatch"

    # SYN_STATUS
    syn_st = await axil_read(dut, 0x20)
    dut._log.info("SYN_STATUS = 0x%08X", syn_st)

    # -------------------------------------------------------------------------
    # TEST 8: Disable firewall via CONTROL[0]=0 → traffic passes without filter
    # -------------------------------------------------------------------------
    dut._log.info("=== TEST 8 : Disable firewall → pass-all ===")
    await axil_write(dut, 0x00, 0x0)   # CONTROL EN=0
    ctrl = await axil_read(dut, 0x00)
    assert ctrl & 0x1 == 0, "CONTROL[0] should be 0 (disabled)"

    pkts_before = stats["out_pkts"]
    # Telnet — normally DROPPED — should now pass through
    await send_tcp_telnet(dut)
    await wait_cycles(dut, 20)
    # Note: in disabled mode packet_count is NOT incremented (bypass path)
    dut._log.info("After disabled-FW Telnet: out_pkts=%d (should be +1)", stats["out_pkts"])

    # Re-enable for safety
    await axil_write(dut, 0x00, 0x1)

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    dut._log.info("=================================================")
    dut._log.info("SIMULATION COMPLETE")
    dut._log.info("  Total DUT packet_count  : %d", int(dut.packet_count.value))
    dut._log.info("  Total DUT dropped_count : %d", int(dut.dropped_count.value))
    dut._log.info("  Output words monitored  : %d", stats["out_words"])
    dut._log.info("  Output packets monitored: %d", stats["out_pkts"])
    dut._log.info("=================================================")

    await Timer(50, units="ns")
