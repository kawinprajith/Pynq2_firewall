`timescale 1ns / 1ps
// =============================================================================
// Module : packet_firewall  (64-bit AXI4-Stream)
// Board  : PYNQ-Z2  Zynq-7020
//
// Pipeline stages:
//   PARSE   – buffer up to 6 header words, extract Ethernet/IPv4/TCP/UDP fields
//   DECIDE  – 1-cycle combinational rule evaluation
//   FLUSH   – forward the buffered header words to the output
//   FORWARD – pass-through remaining payload
//   DROP    – silently consume and discard the packet
//
// Byte → TDATA mapping (Xilinx DMA little-endian: TDATA[7:0] = lowest byte)
//
//  Word 0  bytes  0- 7 : Dst MAC[47:0]  |  Src MAC[47:32]
//  Word 1  bytes  8-15 : Src MAC[31:0]  |  EtherType  |  IPv4 byte0-1
//  Word 2  bytes 16-23 : IPv4 TotalLen  |  ID  |  Flags/Frag  |  TTL  |  Protocol
//  Word 3  bytes 24-31 : IPv4 Checksum  |  Src IP  |  Dst IP[31:16]
//  Word 4  bytes 32-39 : Dst IP[15:0]   |  Src Port  |  Dst Port  |  L4 bytes 4-5
//  Word 5  bytes 40-47 : TCP Seq cont   |  TCP Ack   |  DataOffset |  TCP Flags
//
// Firewall rules (first match wins):
//   DENY  : TCP dst-port 23  (Telnet)
//   DENY  : TCP SYN while syn_flood_detected
//   ALLOW : ICMP (protocol 1)
//   ALLOW : TCP dst-port 80  (HTTP)
//   ALLOW : TCP dst-port 443 (HTTPS)
//   ALLOW : UDP dst-port 5000
//   DROP  : everything else
// =============================================================================
module packet_firewall #(
    parameter [15:0] SYN_FLOOD_THRESHOLD = 16'd100,
    parameter [31:0] SYN_WINDOW_CYCLES   = 32'd10_000_000  // 100 ms @ 100 MHz
)(
    input  wire        aclk,
    input  wire        aresetn,

    // AXI4-Stream Slave (64-bit input)
    input  wire [63:0] s_axis_tdata,
    input  wire [7:0]  s_axis_tkeep,
    input  wire        s_axis_tvalid,
    output reg         s_axis_tready,
    input  wire        s_axis_tlast,

    // AXI4-Stream Master (64-bit output)
    output reg  [63:0] m_axis_tdata,
    output reg  [7:0]  m_axis_tkeep,
    output reg         m_axis_tvalid,
    input  wire        m_axis_tready,
    output reg         m_axis_tlast,

    // Statistics
    output reg  [31:0] packet_count,
    output reg  [31:0] dropped_count,
    output reg  [31:0] word_count,

    // Security
    output reg         syn_flood_detected
);

    // =========================================================================
    // State encoding
    // =========================================================================
    localparam [2:0]
        ST_PARSE   = 3'd0,
        ST_DECIDE  = 3'd1,
        ST_FLUSH   = 3'd2,
        ST_FORWARD = 3'd3,
        ST_DROP    = 3'd4;

    reg [2:0] state;

    // =========================================================================
    // Header buffer  (6 words × 64 bit)
    // =========================================================================
    reg [63:0] hdr_data [0:5];
    reg [7:0]  hdr_keep [0:5];
    reg        hdr_last [0:5];
    reg [2:0]  hdr_cnt;          // how many words captured (1-6)
    reg [2:0]  flush_ptr;        // which buffered word we're currently outputting
    reg        hdr_early_last;   // TLAST arrived at or before word 5

    // =========================================================================
    // Extracted header fields (network / big-endian byte order)
    // =========================================================================
    reg [15:0] r_ethertype;
    reg [7:0]  r_protocol;
    reg [31:0] r_src_ip;
    reg [31:0] r_dst_ip;
    reg [15:0] r_src_port;
    reg [15:0] r_dst_port;
    reg [7:0]  r_tcp_flags;   // bit1=SYN bit0=FIN bit2=RST bit4=ACK

    // =========================================================================
    // Combinational rule evaluation  (inputs are stable regs by ST_DECIDE)
    // =========================================================================
    wire is_ipv4   = (r_ethertype == 16'h0800);
    wire is_tcp    = is_ipv4 && (r_protocol == 8'd6);
    wire is_udp    = is_ipv4 && (r_protocol == 8'd17);
    wire is_icmp   = is_ipv4 && (r_protocol == 8'd1);
    wire tcp_syn   = is_tcp  && r_tcp_flags[1];

    wire deny_telnet   = is_tcp && (r_dst_port == 16'd23);
    wire allow_icmp    = is_icmp;
    wire allow_http    = is_tcp && (r_dst_port == 16'd80);
    wire allow_https   = is_tcp && (r_dst_port == 16'd443);
    wire allow_udp5000 = is_udp && (r_dst_port == 16'd5000);
    wire syn_blocked   = tcp_syn && syn_flood_detected;

    wire fw_allow = !deny_telnet && !syn_blocked &&
                    (allow_icmp || allow_http || allow_https || allow_udp5000);

    // =========================================================================
    // Registers
    // =========================================================================
    reg [2:0]  word_idx;
    reg [31:0] syn_timer;
    reg [15:0] syn_count;

    integer i;

    // =========================================================================
    // Single clocked process
    // =========================================================================
    always @(posedge aclk) begin
        if (!aresetn) begin
            state              <= ST_PARSE;
            s_axis_tready      <= 1'b1;
            m_axis_tdata       <= 64'd0;
            m_axis_tkeep       <= 8'd0;
            m_axis_tvalid      <= 1'b0;
            m_axis_tlast       <= 1'b0;
            packet_count       <= 32'd0;
            dropped_count      <= 32'd0;
            word_count         <= 32'd0;
            word_idx           <= 3'd0;
            hdr_cnt            <= 3'd0;
            flush_ptr          <= 3'd0;
            hdr_early_last     <= 1'b0;
            r_ethertype        <= 16'd0;
            r_protocol         <= 8'd0;
            r_src_ip           <= 32'd0;
            r_dst_ip           <= 32'd0;
            r_src_port         <= 16'd0;
            r_dst_port         <= 16'd0;
            r_tcp_flags        <= 8'd0;
            syn_timer          <= 32'd0;
            syn_count          <= 16'd0;
            syn_flood_detected <= 1'b0;
            for (i = 0; i < 6; i = i + 1) begin
                hdr_data[i] <= 64'd0;
                hdr_keep[i] <= 8'd0;
                hdr_last[i] <= 1'b0;
            end
        end else begin

            // -----------------------------------------------------------------
            // SYN-flood sliding window timer
            // This section has exclusive write access to syn_timer, syn_count,
            // syn_flood_detected to avoid multi-driver issues.
            // -----------------------------------------------------------------
            if (syn_timer >= SYN_WINDOW_CYCLES - 1) begin
                syn_timer          <= 32'd0;
                syn_count          <= 16'd0;
                syn_flood_detected <= 1'b0;
            end else begin
                syn_timer <= syn_timer + 1'b1;
                // Count SYN packets while in DECIDE state
                if (state == ST_DECIDE && tcp_syn && !syn_flood_detected) begin
                    if (syn_count >= SYN_FLOOD_THRESHOLD - 1)
                        syn_flood_detected <= 1'b1;
                    else
                        syn_count <= syn_count + 1'b1;
                end
            end

            // -----------------------------------------------------------------
            // Main state machine
            // -----------------------------------------------------------------
            case (state)

                // =============================================================
                // PARSE: buffer header words and extract fields
                // =============================================================
                ST_PARSE: begin
                    s_axis_tready <= 1'b1;

                    if (s_axis_tvalid) begin  // tready is 1 here
                        hdr_data[word_idx] <= s_axis_tdata;
                        hdr_keep[word_idx] <= s_axis_tkeep;
                        hdr_last[word_idx] <= s_axis_tlast;
                        word_count         <= word_count + 1'b1;

                        case (word_idx)
                            // bytes 12-13  EtherType (big-endian)
                            3'd1: r_ethertype <= {s_axis_tdata[39:32], s_axis_tdata[47:40]};

                            // byte 23  IPv4 Protocol
                            3'd2: r_protocol  <= s_axis_tdata[63:56];

                            // bytes 26-29  Src IP;  bytes 30-31  Dst IP[31:16] saved in hdr_data[3]
                            3'd3: r_src_ip    <= {s_axis_tdata[23:16], s_axis_tdata[31:24],
                                                   s_axis_tdata[39:32], s_axis_tdata[47:40]};

                            // bytes 30-33  full Dst IP;  bytes 34-37  Src/Dst Port
                            3'd4: begin
                                r_dst_ip   <= {hdr_data[3][55:48], hdr_data[3][63:56],
                                               s_axis_tdata[7:0],  s_axis_tdata[15:8]};
                                r_src_port <= {s_axis_tdata[23:16], s_axis_tdata[31:24]};
                                r_dst_port <= {s_axis_tdata[39:32], s_axis_tdata[47:40]};
                            end

                            // byte 47  TCP Flags
                            3'd5: r_tcp_flags <= s_axis_tdata[63:56];

                            default: ; // word 0: MAC addresses (not needed by rules)
                        endcase

                        if (s_axis_tlast || word_idx == 3'd5) begin
                            hdr_cnt        <= word_idx + 1'b1;
                            hdr_early_last <= s_axis_tlast;
                            s_axis_tready  <= 1'b0;
                            state          <= ST_DECIDE;
                            word_idx       <= 3'd0;
                        end else begin
                            word_idx <= word_idx + 1'b1;
                        end
                    end
                end

                // =============================================================
                // DECIDE: evaluate rules (1 cycle); pre-load first output word
                // =============================================================
                ST_DECIDE: begin
                    s_axis_tready <= 1'b0;
                    packet_count  <= packet_count + 1'b1;

                    if (!fw_allow)
                        dropped_count <= dropped_count + 1'b1;

                    flush_ptr <= 3'd0;

                    if (fw_allow) begin
                        // Pre-load word 0 so FLUSH can assert tvalid immediately
                        m_axis_tdata <= hdr_data[0];
                        m_axis_tkeep <= hdr_keep[0];
                        m_axis_tlast <= hdr_last[0];
                        state        <= ST_FLUSH;
                    end else begin
                        // Short packet already complete → back to PARSE; else DROP
                        state <= hdr_early_last ? ST_PARSE : ST_DROP;
                    end
                end

                // =============================================================
                // FLUSH: output buffered header words, one per cycle
                // =============================================================
                ST_FLUSH: begin
                    s_axis_tready <= 1'b0;
                    m_axis_tvalid <= 1'b1;  // data already in output regs from pre-load

                    if (m_axis_tready) begin
                        if (flush_ptr == hdr_cnt - 1) begin
                            // All header words sent
                            m_axis_tvalid <= 1'b0;
                            flush_ptr     <= 3'd0;
                            state         <= hdr_early_last ? ST_PARSE : ST_FORWARD;
                        end else begin
                            // Advance to next buffered word
                            flush_ptr    <= flush_ptr + 1'b1;
                            m_axis_tdata <= hdr_data[flush_ptr + 3'd1];
                            m_axis_tkeep <= hdr_keep[flush_ptr + 3'd1];
                            m_axis_tlast <= hdr_last[flush_ptr + 3'd1];
                        end
                    end
                end

                // =============================================================
                // FORWARD: pass-through remaining payload words
                // =============================================================
                ST_FORWARD: begin
                    s_axis_tready <= ~m_axis_tvalid | m_axis_tready;

                    if (s_axis_tvalid && s_axis_tready) begin
                        m_axis_tdata  <= s_axis_tdata;
                        m_axis_tkeep  <= s_axis_tkeep;
                        m_axis_tlast  <= s_axis_tlast;
                        m_axis_tvalid <= 1'b1;
                        word_count    <= word_count + 1'b1;
                        if (s_axis_tlast) begin
                            state    <= ST_PARSE;
                            word_idx <= 3'd0;
                            hdr_cnt  <= 3'd0;
                        end
                    end else if (m_axis_tvalid && m_axis_tready) begin
                        m_axis_tvalid <= 1'b0;
                    end
                end

                // =============================================================
                // DROP: silently consume and discard remainder of packet
                // =============================================================
                ST_DROP: begin
                    s_axis_tready <= 1'b1;
                    m_axis_tvalid <= 1'b0;
                    if (s_axis_tvalid) begin
                        word_count <= word_count + 1'b1;
                        if (s_axis_tlast) begin
                            state    <= ST_PARSE;
                            word_idx <= 3'd0;
                            hdr_cnt  <= 3'd0;
                        end
                    end
                end

                default: state <= ST_PARSE;
            endcase
        end
    end

endmodule
