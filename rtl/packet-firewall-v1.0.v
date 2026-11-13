`timescale 1ns / 1ps
// =============================================================================
// Module : packet_firewall  (64-bit AXI4-Stream + AXI4-Lite)
// Board  : PYNQ-Z2  Zynq-7020
//
// AXI4-Stream pipeline states:
//   PARSE   – buffer up to 6 header words, extract Ethernet/IPv4/TCP/UDP fields
//   DECIDE  – 1-cycle combinational rule evaluation
//   FLUSH   – forward the buffered header words to the output
//   FORWARD – pass-through remaining payload
//   DROP    – silently consume and discard the packet
//
// AXI4-Lite register map (32-bit, word-aligned):
//   0x00  CONTROL      [0]=EN (1=firewall active, 0=pass-all)
//   0x04  RULE_CONFIG  [0]=ALLOW_ICMP [1]=ALLOW_HTTP [2]=ALLOW_HTTPS
//                      [3]=ALLOW_UDP5000 [4]=DENY_TELNET
//   0x08  SYN_THRESH   [15:0] SYN packet count threshold
//   0x0C  SYN_WINDOW   [31:0] window size in clock cycles
//   0x10  STATUS       [0]=EN_STAT [1]=SYN_FLOOD (read-only)
//   0x14  PACKET_COUNT [31:0] (read-only)
//   0x18  DROPPED_CNT  [31:0] (read-only)
//   0x1C  WORD_COUNT   [31:0] (read-only)
//   0x20  SYN_STATUS   [0]=syn_flood_detected [15:0]=syn_count (read-only)
//
// Byte → TDATA mapping (Xilinx DMA little-endian: TDATA[7:0] = lowest byte):
//  Word 0  bytes  0- 7 : Dst MAC[47:0]  |  Src MAC[47:32]
//  Word 1  bytes  8-15 : Src MAC[31:0]  |  EtherType  |  IPv4 byte0-1
//  Word 2  bytes 16-23 : IPv4 TotalLen  |  ID  |  Flags/Frag  |  TTL  |  Protocol
//  Word 3  bytes 24-31 : IPv4 Checksum  |  Src IP  |  Dst IP[31:16]
//  Word 4  bytes 32-39 : Dst IP[15:0]  |  Src Port  |  Dst Port  |  L4 bytes 4-5
//  Word 5  bytes 40-47 : TCP Seq cont  |  TCP Ack   |  DataOffset |  TCP Flags
// =============================================================================
module packet_firewall #(
    parameter [15:0] SYN_FLOOD_THRESHOLD = 16'd100,
    parameter [31:0] SYN_WINDOW_CYCLES   = 32'd10_000_000  // 100 ms @ 100 MHz
)(
    input  wire        aclk,
    input  wire        aresetn,

    // =========================================================================
    // AXI4-Lite Slave (configuration & status)
    // =========================================================================
    input  wire [5:0]  s_axil_awaddr,
    input  wire        s_axil_awvalid,
    output reg         s_axil_awready,

    input  wire [31:0] s_axil_wdata,
    input  wire [3:0]  s_axil_wstrb,
    input  wire        s_axil_wvalid,
    output reg         s_axil_wready,

    output reg  [1:0]  s_axil_bresp,
    output reg         s_axil_bvalid,
    input  wire        s_axil_bready,

    input  wire [5:0]  s_axil_araddr,
    input  wire        s_axil_arvalid,
    output reg         s_axil_arready,

    output reg  [31:0] s_axil_rdata,
    output reg  [1:0]  s_axil_rresp,
    output reg         s_axil_rvalid,
    input  wire        s_axil_rready,

    // =========================================================================
    // AXI4-Stream Slave (64-bit packet input)
    // =========================================================================
    input  wire [63:0] s_axis_tdata,
    input  wire [7:0]  s_axis_tkeep,
    input  wire        s_axis_tvalid,
    output reg         s_axis_tready,
    input  wire        s_axis_tlast,

    // =========================================================================
    // AXI4-Stream Master (64-bit packet output)
    // =========================================================================
    output reg  [63:0] m_axis_tdata,
    output reg  [7:0]  m_axis_tkeep,
    output reg         m_axis_tvalid,
    input  wire        m_axis_tready,
    output reg         m_axis_tlast,

    // =========================================================================
    // Status outputs (mirror of AXI-Lite status registers)
    // =========================================================================
    output reg  [31:0] packet_count,
    output reg  [31:0] dropped_count,
    output reg  [31:0] word_count,
    output reg         syn_flood_detected
);

    // =========================================================================
    // AXI4-Lite register bank
    // =========================================================================
    reg [31:0] reg_control;      // 0x00
    reg [31:0] reg_rule_config;  // 0x04
    reg [31:0] reg_syn_thresh;   // 0x08
    reg [31:0] reg_syn_window;   // 0x0C
    // 0x10 STATUS      – read-only, assembled from internal state
    // 0x14 PACKET_COUNT – read-only alias
    // 0x18 DROPPED_CNT  – read-only alias
    // 0x1C WORD_COUNT   – read-only alias
    // 0x20 SYN_STATUS   – read-only alias

    // Convenience wires from configuration registers
    wire        fw_enable       = reg_control[0];
    wire        cfg_allow_icmp  = reg_rule_config[0];
    wire        cfg_allow_http  = reg_rule_config[1];
    wire        cfg_allow_https = reg_rule_config[2];
    wire        cfg_allow_udp5k = reg_rule_config[3];
    wire        cfg_deny_telnet = reg_rule_config[4];

    // Active threshold and window (register values override parameters at runtime)
    wire [15:0] active_syn_thresh = reg_syn_thresh[15:0];
    wire [31:0] active_syn_window = reg_syn_window;

    // =========================================================================
    // AXI4-Lite write logic
    // =========================================================================
    reg [5:0] axil_waddr_lat;

    always @(posedge aclk) begin
        if (!aresetn) begin
            s_axil_awready <= 1'b0;
            s_axil_wready  <= 1'b0;
            s_axil_bvalid  <= 1'b0;
            s_axil_bresp   <= 2'b00;
            axil_waddr_lat <= 6'd0;
            reg_control     <= 32'd1;                   // firewall enabled by default
            reg_rule_config <= 32'b0001_1111;           // all rules active by default
            reg_syn_thresh  <= {16'd0, SYN_FLOOD_THRESHOLD};
            reg_syn_window  <= SYN_WINDOW_CYCLES;
        end else begin
            // Accept write address
            if (s_axil_awvalid && !s_axil_awready) begin
                s_axil_awready <= 1'b1;
                axil_waddr_lat <= s_axil_awaddr;
            end else begin
                s_axil_awready <= 1'b0;
            end

            // Accept write data
            if (s_axil_wvalid && !s_axil_wready) begin
                s_axil_wready <= 1'b1;
                // Apply strobe-qualified write to writable registers
                case (axil_waddr_lat[5:2])
                    4'h0: begin // 0x00 CONTROL
                        if (s_axil_wstrb[0]) reg_control[7:0]   <= s_axil_wdata[7:0];
                        if (s_axil_wstrb[1]) reg_control[15:8]  <= s_axil_wdata[15:8];
                        if (s_axil_wstrb[2]) reg_control[23:16] <= s_axil_wdata[23:16];
                        if (s_axil_wstrb[3]) reg_control[31:24] <= s_axil_wdata[31:24];
                    end
                    4'h1: begin // 0x04 RULE_CONFIG
                        if (s_axil_wstrb[0]) reg_rule_config[7:0]   <= s_axil_wdata[7:0];
                        if (s_axil_wstrb[1]) reg_rule_config[15:8]  <= s_axil_wdata[15:8];
                        if (s_axil_wstrb[2]) reg_rule_config[23:16] <= s_axil_wdata[23:16];
                        if (s_axil_wstrb[3]) reg_rule_config[31:24] <= s_axil_wdata[31:24];
                    end
                    4'h2: begin // 0x08 SYN_THRESH
                        if (s_axil_wstrb[0]) reg_syn_thresh[7:0]   <= s_axil_wdata[7:0];
                        if (s_axil_wstrb[1]) reg_syn_thresh[15:8]  <= s_axil_wdata[15:8];
                        if (s_axil_wstrb[2]) reg_syn_thresh[23:16] <= s_axil_wdata[23:16];
                        if (s_axil_wstrb[3]) reg_syn_thresh[31:24] <= s_axil_wdata[31:24];
                    end
                    4'h3: begin // 0x0C SYN_WINDOW
                        if (s_axil_wstrb[0]) reg_syn_window[7:0]   <= s_axil_wdata[7:0];
                        if (s_axil_wstrb[1]) reg_syn_window[15:8]  <= s_axil_wdata[15:8];
                        if (s_axil_wstrb[2]) reg_syn_window[23:16] <= s_axil_wdata[23:16];
                        if (s_axil_wstrb[3]) reg_syn_window[31:24] <= s_axil_wdata[31:24];
                    end
                    default: ; // 0x10-0x20 are read-only, ignore writes
                endcase
            end else begin
                s_axil_wready <= 1'b0;
            end

            // Send write response
            if (s_axil_wready && s_axil_wvalid) begin
                s_axil_bvalid <= 1'b1;
                s_axil_bresp  <= 2'b00; // OKAY
            end else if (s_axil_bvalid && s_axil_bready) begin
                s_axil_bvalid <= 1'b0;
            end
        end
    end

    // =========================================================================
    // AXI4-Lite read logic
    // =========================================================================
    always @(posedge aclk) begin
        if (!aresetn) begin
            s_axil_arready <= 1'b0;
            s_axil_rvalid  <= 1'b0;
            s_axil_rdata   <= 32'd0;
            s_axil_rresp   <= 2'b00;
        end else begin
            if (s_axil_arvalid && !s_axil_arready) begin
                s_axil_arready <= 1'b1;
                s_axil_rvalid  <= 1'b1;
                s_axil_rresp   <= 2'b00;
                case (s_axil_araddr[5:2])
                    4'h0: s_axil_rdata <= reg_control;
                    4'h1: s_axil_rdata <= reg_rule_config;
                    4'h2: s_axil_rdata <= reg_syn_thresh;
                    4'h3: s_axil_rdata <= reg_syn_window;
                    4'h4: s_axil_rdata <= {30'd0, syn_flood_detected, fw_enable}; // STATUS
                    4'h5: s_axil_rdata <= packet_count;
                    4'h6: s_axil_rdata <= dropped_count;
                    4'h7: s_axil_rdata <= word_count;
                    4'h8: s_axil_rdata <= {syn_count, 15'd0, syn_flood_detected}; // SYN_STATUS
                    default: s_axil_rdata <= 32'hDEAD_BEEF;
                endcase
            end else begin
                s_axil_arready <= 1'b0;
                if (s_axil_rvalid && s_axil_rready)
                    s_axil_rvalid <= 1'b0;
            end
        end
    end

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
    reg [2:0]  hdr_cnt;
    reg [2:0]  flush_ptr;
    reg        hdr_early_last;

    // =========================================================================
    // Extracted header fields (network / big-endian byte order)
    // =========================================================================
    reg [15:0] r_ethertype;
    reg [7:0]  r_protocol;
    reg [31:0] r_src_ip;
    reg [31:0] r_dst_ip;
    reg [15:0] r_src_port;
    reg [15:0] r_dst_port;
    reg [7:0]  r_tcp_flags;

    // =========================================================================
    // Combinational rule evaluation
    // =========================================================================
    wire is_ipv4   = (r_ethertype == 16'h0800);
    wire is_tcp    = is_ipv4 && (r_protocol == 8'd6);
    wire is_udp    = is_ipv4 && (r_protocol == 8'd17);
    wire is_icmp   = is_ipv4 && (r_protocol == 8'd1);
    wire tcp_syn   = is_tcp  && r_tcp_flags[1];

    wire deny_telnet   = cfg_deny_telnet  && is_tcp && (r_dst_port == 16'd23);
    wire allow_icmp    = cfg_allow_icmp   && is_icmp;
    wire allow_http    = cfg_allow_http   && is_tcp && (r_dst_port == 16'd80);
    wire allow_https   = cfg_allow_https  && is_tcp && (r_dst_port == 16'd443);
    wire allow_udp5000 = cfg_allow_udp5k  && is_udp && (r_dst_port == 16'd5000);
    wire syn_blocked   = tcp_syn && syn_flood_detected;

    wire fw_allow = !deny_telnet && !syn_blocked &&
                    (allow_icmp || allow_http || allow_https || allow_udp5000);

    // =========================================================================
    // Miscellaneous registers
    // =========================================================================
    reg [2:0]  word_idx;
    reg [31:0] syn_timer;
    reg [15:0] syn_count;

    integer i;

    // =========================================================================
    // Single clocked process (stream datapath + SYN flood detector)
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
            // Exclusive write owner of: syn_timer, syn_count, syn_flood_detected
            // -----------------------------------------------------------------
            if (syn_timer >= active_syn_window - 1) begin
                syn_timer          <= 32'd0;
                syn_count          <= 16'd0;
                syn_flood_detected <= 1'b0;
            end else begin
                syn_timer <= syn_timer + 1'b1;
                if (state == ST_DECIDE && tcp_syn && !syn_flood_detected) begin
                    if (syn_count >= active_syn_thresh - 1)
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
                // FIX: qualify on (s_axis_tvalid && s_axis_tready) so a beat
                //      is only consumed when both sides have agreed.
                // =============================================================
                ST_PARSE: begin
                    s_axis_tready <= fw_enable ? 1'b1 : 1'b0;

                    if (s_axis_tvalid && s_axis_tready) begin
                        hdr_data[word_idx] <= s_axis_tdata;
                        hdr_keep[word_idx] <= s_axis_tkeep;
                        hdr_last[word_idx] <= s_axis_tlast;
                        word_count         <= word_count + 1'b1;

                        case (word_idx)
                            3'd1: r_ethertype <= {s_axis_tdata[39:32], s_axis_tdata[47:40]};
                            3'd2: r_protocol  <= s_axis_tdata[63:56];
                            3'd3: r_src_ip    <= {s_axis_tdata[23:16], s_axis_tdata[31:24],
                                                   s_axis_tdata[39:32], s_axis_tdata[47:40]};
                            3'd4: begin
                                r_dst_ip   <= {hdr_data[3][55:48], hdr_data[3][63:56],
                                               s_axis_tdata[7:0],  s_axis_tdata[15:8]};
                                r_src_port <= {s_axis_tdata[23:16], s_axis_tdata[31:24]};
                                r_dst_port <= {s_axis_tdata[39:32], s_axis_tdata[47:40]};
                            end
                            3'd5: r_tcp_flags <= s_axis_tdata[63:56];
                            default: ;
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

                    // If firewall is disabled: pass traffic straight through
                    if (!fw_enable) begin
                        if (s_axis_tvalid) begin
                            m_axis_tdata  <= s_axis_tdata;
                            m_axis_tkeep  <= s_axis_tkeep;
                            m_axis_tlast  <= s_axis_tlast;
                            m_axis_tvalid <= 1'b1;
                            word_count    <= word_count + 1'b1;
                        end else if (m_axis_tvalid && m_axis_tready) begin
                            m_axis_tvalid <= 1'b0;
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
                        m_axis_tdata <= hdr_data[0];
                        m_axis_tkeep <= hdr_keep[0];
                        m_axis_tlast <= hdr_last[0];
                        state        <= ST_FLUSH;
                    end else begin
                        state <= hdr_early_last ? ST_PARSE : ST_DROP;
                    end
                end

                // =============================================================
                // FLUSH: stream buffered header words with backpressure support
                // =============================================================
                ST_FLUSH: begin
                    s_axis_tready <= 1'b0;
                    m_axis_tvalid <= 1'b1;

                    if (m_axis_tready) begin
                        if (flush_ptr == hdr_cnt - 1) begin
                            m_axis_tvalid <= 1'b0;
                            flush_ptr     <= 3'd0;
                            state         <= hdr_early_last ? ST_PARSE : ST_FORWARD;
                        end else begin
                            flush_ptr    <= flush_ptr + 1'b1;
                            m_axis_tdata <= hdr_data[flush_ptr + 3'd1];
                            m_axis_tkeep <= hdr_keep[flush_ptr + 3'd1];
                            m_axis_tlast <= hdr_last[flush_ptr + 3'd1];
                        end
                    end
                end

                // =============================================================
                // FORWARD: pass-through remaining payload at wire speed
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
                // DROP: consume and discard packet remainder
                // FIX: qualify on (s_axis_tvalid && s_axis_tready) — this is
                //      the correct AXI handshake even during the drop path.
                //      s_axis_tready is held high, so the DUT never stalls.
                // =============================================================
                ST_DROP: begin
                    s_axis_tready <= 1'b1;
                    m_axis_tvalid <= 1'b0;

                    if (s_axis_tvalid && s_axis_tready) begin
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
