module packet_firewall (
    input  wire        aclk,
    input  wire        aresetn,

    // AXI-Stream input
    input  wire [31:0] s_axis_tdata,
    input  wire [3:0]  s_axis_tkeep,
    input  wire        s_axis_tvalid,
    output wire        s_axis_tready,
    input  wire        s_axis_tlast,

    // AXI-Stream output
    output reg  [31:0] m_axis_tdata,
    output reg  [3:0]  m_axis_tkeep,
    output reg         m_axis_tvalid,
    input  wire        m_axis_tready,
    output reg         m_axis_tlast,

    // Statistics
    output reg  [31:0] packet_count,
    output reg  [31:0] word_count
);

    // We can accept data whenever the output side is ready
    // or when there is currently no output word waiting.
    assign s_axis_tready = ~m_axis_tvalid | m_axis_tready;

    always @(posedge aclk) begin

        if (!aresetn) begin

            m_axis_tdata  <= 32'd0;
            m_axis_tkeep  <= 4'd0;
            m_axis_tvalid <= 1'b0;
            m_axis_tlast  <= 1'b0;

            packet_count  <= 32'd0;
            word_count    <= 32'd0;

        end
        else begin

            // Input transfer
            if (s_axis_tvalid && s_axis_tready) begin

                // Pass packet data through
                m_axis_tdata  <= s_axis_tdata;
                m_axis_tkeep  <= s_axis_tkeep;
                m_axis_tlast  <= s_axis_tlast;
                m_axis_tvalid <= 1'b1;

                // Count transferred words
                word_count <= word_count + 1'b1;

                // Count packets when TLAST arrives
                if (s_axis_tlast) begin
                    packet_count <= packet_count + 1'b1;
                end
            end

            // Output transfer completed
            else if (m_axis_tvalid && m_axis_tready) begin
                m_axis_tvalid <= 1'b0;
            end

        end
    end

endmodule
