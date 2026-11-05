# Purpose: Cocotb testbench for a 64-bit AXI4-Stream packet firewall
# Converted from the supplied Verilog testbench.
#
# Test cases:
# 1. UDP destination port 5000 -> ALLOW
# 2. ICMP echo request       -> ALLOW
# 3. TCP SYN destination 80  -> ALLOW
# 4. TCP destination 23      -> DROP
# 5. SYN-flood sequence
# 6. Output-ready observation (see note in Test 6)
#
# DUT interface:
#   aclk, aresetn
#   s_axis_tdata[63:0], s_axis_tkeep[7:0], s_axis_tvalid,
#   s_axis_tready, s_axis_tlast
#   m_axis_tdata[63:0], m_axis_tkeep[7:0], m_axis_tvalid,
#   m_axis_tready, m_axis_tlast
#   packet_count[31:0], dropped_count[31:0], word_count[31:0],
#   syn_flood_detected

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge, Timer


CLK_NS = 10

# ---------------------------------------------------------------------------
# Precomputed 64-bit word constants
# TDATA[7:0] = byte 0, TDATA[63:56] = byte 7
# ---------------------------------------------------------------------------

# Word 0: Destination MAC + first two bytes of source MAC
W0 = 0xBBAA_FFFF_FFFF_FFFF

# Word 1: Remaining source MAC + EtherType + IPv4 version/DSCP
W1 = 0x0045_0008_FFEE_DDCC

# Word 3: Checksum + source IP + first part of destination IP
W3 = 0x000A_0100_000A_0000

# Word 5 for TCP: sequence/acknowledgement continuation,
# data offset and SYN flag
W5_SYN = 0x0250_0000_0000_0000

# Word 6: TCP remainder / payload
W6_LAST = 0x0000_0000_0000_0000


# ---------------------------------------------------------------------------
# Helper functions corresponding to the Verilog functions
# make_w2() and make_w4()
# ---------------------------------------------------------------------------

def make_w2(protocol, total_len):
    """Create IPv4 header word 2."""
    return (
        ((protocol & 0xFF) << 56)
        | (0x40 << 48)                 # TTL = 64
        | (0x00 << 40)                 # Fragment field
        | (0x40 << 32)                 # Don't Fragment
        | (0x00 << 24)                 # Identification low byte
        | (0x00 << 16)                 # Identification high byte
        | ((total_len & 0xFF) << 8)    # Total length low byte
        | ((total_len >> 8) & 0xFF)    # Total length high byte
    )


def make_w4(dip_hi, dip_lo, src_port, dst_port):
    """Create the word containing the end of destination IP and L4 ports."""
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
# Reset and timing helpers
# ---------------------------------------------------------------------------

async def reset_dut(dut):
    """Apply active-low reset."""
    dut.aresetn.value = 0
    dut.s_axis_tdata.value = 0
    dut.s_axis_tkeep.value = 0
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0
    dut.m_axis_tready.value = 1

    for _ in range(4):
        await RisingEdge(dut.aclk)

    await FallingEdge(dut.aclk)
    dut.aresetn.value = 1
    await RisingEdge(dut.aclk)

    dut._log.info(
        "After reset: pkt=%d drop=%d syn=%d",
        int(dut.packet_count.value),
        int(dut.dropped_count.value),
        int(dut.syn_flood_detected.value),
    )


async def wait_cycles(dut, cycles):
    """Wait for the requested number of rising clock edges."""
    for _ in range(cycles):
        await RisingEdge(dut.aclk)


async def send_word(dut, data, keep, last):
    """
    Present one 64-bit AXI-Stream beat and wait until the DUT accepts it.

    Inputs are driven on a falling edge to avoid changing them on the
    DUT's active rising edge. A transfer occurs when TVALID and TREADY
    are both high on a rising edge.
    """
    await FallingEdge(dut.aclk)

    dut.s_axis_tdata.value = data
    dut.s_axis_tkeep.value = keep
    dut.s_axis_tlast.value = last
    dut.s_axis_tvalid.value = 1

    while True:
        await RisingEdge(dut.aclk)
        if int(dut.s_axis_tready.value) == 1:
            break

    await FallingEdge(dut.aclk)
    dut.s_axis_tvalid.value = 0
    dut.s_axis_tlast.value = 0
    dut.s_axis_tdata.value = 0
    dut.s_axis_tkeep.value = 0


# ---------------------------------------------------------------------------
# Packet generators corresponding to the Verilog packet tasks
# ---------------------------------------------------------------------------

async def send_udp5000(dut):
    """Send UDP packet to destination port 5000: 6 words."""
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x11, 0x001C), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, make_w4(0x00, 0x02, 0x1234, 0x1388), 0xFF, 0)
    await send_word(dut, 0x0000_0000_0000_0000, 0x03, 1)


async def send_icmp(dut):
    """Send ICMP echo request: 6 words."""
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x01, 0x001C), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    # Destination IP = 10.0.0.2; ICMP type = 8, code = 0
    await send_word(dut, 0x0000_0000_0008_0200, 0xFF, 0)
    await send_word(dut, 0x0000_0000_0000_0000, 0x03, 1)


async def send_tcp_syn_80(dut):
    """Send TCP SYN packet to destination port 80: 7 words."""
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x06, 0x0028), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, make_w4(0x00, 0x02, 0x1234, 0x0050), 0xFF, 0)
    await send_word(dut, W5_SYN, 0xFF, 0)
    await send_word(dut, W6_LAST, 0x3F, 1)


async def send_tcp_telnet(dut):
    """Send TCP packet to destination port 23: expected to be dropped."""
    await send_word(dut, W0, 0xFF, 0)
    await send_word(dut, W1, 0xFF, 0)
    await send_word(dut, make_w2(0x06, 0x0028), 0xFF, 0)
    await send_word(dut, W3, 0xFF, 0)
    await send_word(dut, make_w4(0x00, 0x02, 0x1234, 0x0017), 0xFF, 0)
    await send_word(dut, W5_SYN, 0xFF, 0)
    await send_word(dut, W6_LAST, 0x3F, 1)


# ---------------------------------------------------------------------------
# Output monitor: equivalent to the Verilog always @(posedge aclk) block
# ---------------------------------------------------------------------------

async def monitor_output(dut, stats):
    while True:
        await RisingEdge(dut.aclk)

        if (int(dut.m_axis_tvalid.value) == 1
                and int(dut.m_axis_tready.value) == 1):
            data = int(dut.m_axis_tdata.value)
            keep = int(dut.m_axis_tkeep.value)
            last = int(dut.m_axis_tlast.value)

            dut._log.info(
                "[OUT] DATA=%016X KEEP=%02X LAST=%d",
                data, keep, last
            )

            stats["out_words"] += 1
            if last:
                stats["out_pkts"] += 1


def log_counters(dut, stats, include_syn=False):
    """Print DUT counters and output-monitor counters."""
    message = (
        "pkt=%d drop=%d out_words=%d out_pkts=%d"
        % (
            int(dut.packet_count.value),
            int(dut.dropped_count.value),
            stats["out_words"],
            stats["out_pkts"],
        )
    )

    if include_syn:
        message += " syn=%d" % int(dut.syn_flood_detected.value)

    dut._log.info(message)


# ---------------------------------------------------------------------------
# Main Cocotb test
# ---------------------------------------------------------------------------

@cocotb.test()
async def packet_firewall_test(dut):
    """Run the packet firewall test sequence."""

    # Start 100 MHz clock (10 ns period)
    cocotb.start_soon(Clock(dut.aclk, CLK_NS, units="ns").start())

    stats = {
        "out_words": 0,
        "out_pkts": 0,
    }

    # Start output monitor
    cocotb.start_soon(monitor_output(dut, stats))

    # --------------------------- RESET -------------------------------------
    dut._log.info("=================================================")
    dut._log.info("TEST 0 : RESET")
    dut._log.info("=================================================")

    await reset_dut(dut)

    # --------------------------- TEST 1 ------------------------------------
    dut._log.info("=================================================")
    dut._log.info("TEST 1 : UDP dst-port 5000 -> expect ALLOW (6 words out)")
    dut._log.info("=================================================")

    await send_udp5000(dut)
    await wait_cycles(dut, 12)
    log_counters(dut, stats)

    # --------------------------- TEST 2 ------------------------------------
    dut._log.info("=================================================")
    dut._log.info("TEST 2 : ICMP -> expect ALLOW (6 words out)")
    dut._log.info("=================================================")

    await send_icmp(dut)
    await wait_cycles(dut, 12)
    log_counters(dut, stats)

    # --------------------------- TEST 3 ------------------------------------
    dut._log.info("=================================================")
    dut._log.info("TEST 3 : TCP SYN port 80 -> expect ALLOW (7 words out)")
    dut._log.info("=================================================")

    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 15)
    log_counters(dut, stats, include_syn=True)

    # --------------------------- TEST 4 ------------------------------------
    dut._log.info("=================================================")
    dut._log.info("TEST 4 : TCP port 23 Telnet -> expect DROP (no output)")
    dut._log.info("=================================================")

    words_before_telnet = stats["out_words"]

    await send_tcp_telnet(dut)
    await wait_cycles(dut, 12)
    log_counters(dut, stats)

    assert stats["out_words"] == words_before_telnet, (
        "Telnet packet was expected to be dropped, but output words increased"
    )

    # --------------------------- TEST 5 ------------------------------------
    dut._log.info("=================================================")
    dut._log.info("TEST 5 : SYN Flood threshold=3; send 4 SYN/port-80 packets")
    dut._log.info("=================================================")

    # This preserves the original Verilog sequence. Note that TEST 3 has
    # already sent one SYN, so the DUT's SYN counter may include that packet.
    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 8)
    dut._log.info(
        "After SYN sequence step 1: syn_flood=%d",
        int(dut.syn_flood_detected.value)
    )

    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 8)
    dut._log.info(
        "After SYN sequence step 2: syn_flood=%d",
        int(dut.syn_flood_detected.value)
    )

    await send_tcp_syn_80(dut)
    await wait_cycles(dut, 8)
    dut._log.info(
        "After SYN sequence step 3: syn_flood=%d",
        int(dut.syn_flood_detected.value)
    )

    log_counters(dut, stats)

    # --------------------------- TEST 6 ------------------------------------
    dut._log.info("=================================================")
    dut._log.info(
        "TEST 6 : Output-ready observation during UDP 5000 transmission"
    )
    dut._log.info("=================================================")

    # Wait for the SYN window to clear, as in the original testbench.
    await wait_cycles(dut, 2100)

    # IMPORTANT:
    # The supplied Verilog testbench never actually drives m_axis_tready
    # low. It leaves it at 1, so this sequence does NOT create backpressure.
    # This conversion preserves that original behavior.
    dut.m_axis_tready.value = 1

    await send_udp5000(dut)
    await wait_cycles(dut, 6)

    dut._log.info(
        "m_axis_tvalid=%d s_axis_tready=%d",
        int(dut.m_axis_tvalid.value),
        int(dut.s_axis_tready.value)
    )

    await wait_cycles(dut, 20)
    log_counters(dut, stats)

    # --------------------------- SUMMARY -----------------------------------
    dut._log.info("")
    dut._log.info("=================================================")
    dut._log.info("SIMULATION COMPLETE")
    dut._log.info("Total packets received : %d", int(dut.packet_count.value))
    dut._log.info("Total dropped          : %d", int(dut.dropped_count.value))
    dut._log.info("Output words           : %d", stats["out_words"])
    dut._log.info("Output packets         : %d", stats["out_pkts"])
    dut._log.info("=================================================")

    await Timer(50, units="ns")
