`timescale 1ns / 1ps

module tb_packet_firewall;

    // ---------------------------------------------------------
    // Clock and reset
    // ---------------------------------------------------------
    reg aclk;
    reg aresetn;

    // ---------------------------------------------------------
    // AXI-Stream input
    // ---------------------------------------------------------
    reg  [31:0] s_axis_tdata;
    reg  [3:0]  s_axis_tkeep;
    reg         s_axis_tvalid;
    wire        s_axis_tready;
    reg         s_axis_tlast;

    // ---------------------------------------------------------
    // AXI-Stream output
    // ---------------------------------------------------------
    wire [31:0] m_axis_tdata;
    wire [3:0]  m_axis_tkeep;
    wire        m_axis_tvalid;
    reg         m_axis_tready;
    wire        m_axis_tlast;

    // ---------------------------------------------------------
    // Statistics
    // ---------------------------------------------------------
    wire [31:0] packet_count;
    wire [31:0] word_count;


    // ---------------------------------------------------------
    // Instantiate DUT
    // DUT = Device Under Test
    // ---------------------------------------------------------
    packet_firewall dut (
        .aclk            (aclk),
        .aresetn         (aresetn),

        .s_axis_tdata    (s_axis_tdata),
        .s_axis_tkeep    (s_axis_tkeep),
        .s_axis_tvalid   (s_axis_tvalid),
        .s_axis_tready   (s_axis_tready),
        .s_axis_tlast    (s_axis_tlast),

        .m_axis_tdata    (m_axis_tdata),
        .m_axis_tkeep    (m_axis_tkeep),
        .m_axis_tvalid   (m_axis_tvalid),
        .m_axis_tready   (m_axis_tready),
        .m_axis_tlast    (m_axis_tlast),

        .packet_count    (packet_count),
        .word_count      (word_count)
    );


    // ---------------------------------------------------------
    // Clock generation
    // 10 ns period = 100 MHz
    // ---------------------------------------------------------
    initial begin
        aclk = 1'b0;

        forever #5 aclk = ~aclk;
    end


    // ---------------------------------------------------------
    // Task: Send one AXI-Stream word
    // ---------------------------------------------------------
    task send_word;
        input [31:0] data;
        input [3:0]  keep;
        input        last;

        begin

            // Put data on input
            s_axis_tdata  = data;
            s_axis_tkeep  = keep;
            s_axis_tlast  = last;
            s_axis_tvalid = 1'b1;

            // Wait until DUT accepts the word
            @(posedge aclk);

            while (!s_axis_tready)
                @(posedge aclk);

            // Keep valid/data stable until transfer
            @(posedge aclk);

            s_axis_tvalid = 1'b0;
            s_axis_tlast  = 1'b0;
            s_axis_tdata  = 32'd0;
            s_axis_tkeep  = 4'd0;

        end
    endtask


    // ---------------------------------------------------------
    // Main test
    // ---------------------------------------------------------
    initial begin

        // Initial values
        aresetn        = 1'b0;

        s_axis_tdata  = 32'd0;
        s_axis_tkeep  = 4'd0;
        s_axis_tvalid = 1'b0;
        s_axis_tlast  = 1'b0;

        // Downstream is ready
        m_axis_tready = 1'b1;


        // -----------------------------------------------------
        // TEST 1: Reset
        // -----------------------------------------------------
        $display("========================================");
        $display("TEST 1: RESET");
        $display("========================================");

        #20;

        aresetn = 1'b1;

        @(posedge aclk);

        $display("packet_count = %0d", packet_count);
        $display("word_count   = %0d", word_count);


        // -----------------------------------------------------
        // TEST 2: One packet, 3 words
        // -----------------------------------------------------
        $display("");
        $display("========================================");
        $display("TEST 2: ONE PACKET / 3 WORDS");
        $display("========================================");

        send_word(32'hDEADBEEF, 4'b1111, 1'b0);
        send_word(32'h11223344, 4'b1111, 1'b0);
        send_word(32'h55667788, 4'b1111, 1'b1);

        // Allow output/counters to settle
        repeat (3) @(posedge aclk);

        $display("packet_count = %0d", packet_count);
        $display("word_count   = %0d", word_count);


        // -----------------------------------------------------
        // TEST 3: Two more packets
        // -----------------------------------------------------
        $display("");
        $display("========================================");
        $display("TEST 3: MULTIPLE PACKETS");
        $display("========================================");

        // Packet 2 = 2 words
        send_word(32'hAAAAAAAA, 4'b1111, 1'b0);
        send_word(32'hBBBBBBBB, 4'b1111, 1'b1);

        // Packet 3 = 4 words
        send_word(32'h12345678, 4'b1111, 1'b0);
        send_word(32'h87654321, 4'b1111, 1'b0);
        send_word(32'hCAFEBABE, 4'b1111, 1'b0);
        send_word(32'hFACEFACE, 4'b1111, 1'b1);

        repeat (3) @(posedge aclk);

        $display("packet_count = %0d", packet_count);
        $display("word_count   = %0d", word_count);


        // -----------------------------------------------------
        // TEST 4: Backpressure
        // -----------------------------------------------------
        $display("");
        $display("========================================");
        $display("TEST 4: BACKPRESSURE");
        $display("========================================");

        // Stop downstream from accepting data
        m_axis_tready = 1'b0;

        // Present a word
        s_axis_tdata  = 32'hCAFED00D;
        s_axis_tkeep  = 4'b1111;
        s_axis_tlast  = 1'b1;
        s_axis_tvalid = 1'b1;

        repeat (3) @(posedge aclk);

        $display("During backpressure:");
        $display("s_axis_tready = %b", s_axis_tready);
        $display("m_axis_tvalid = %b", m_axis_tvalid);
        $display("packet_count  = %0d", packet_count);
        $display("word_count    = %0d", word_count);

        // Release downstream
        m_axis_tready = 1'b1;

        repeat (3) @(posedge aclk);

        // Stop input
        s_axis_tvalid = 1'b0;
        s_axis_tlast  = 1'b0;

        $display("After releasing backpressure:");
        $display("packet_count = %0d", packet_count);
        $display("word_count   = %0d", word_count);


        // -----------------------------------------------------
        // Finish
        // -----------------------------------------------------
        $display("");
        $display("========================================");
        $display("SIMULATION FINISHED");
        $display("========================================");

        #20;

        $finish;

    end


    // ---------------------------------------------------------
    // Monitor output transfers
    // ---------------------------------------------------------
    always @(posedge aclk) begin

        if (m_axis_tvalid && m_axis_tready) begin

            $display(
                "OUTPUT: DATA=%h KEEP=%b LAST=%b",
                m_axis_tdata,
                m_axis_tkeep,
                m_axis_tlast
            );

        end

    end

endmodule
