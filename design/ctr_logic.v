module ctr_logic (
    input  wire [127:0] V_in,
    output wire [127:0] V_out
);
    // Big-endian 128-bit increment.
    // V[127:120] = byte 0 = MSB. Adding 1 as a 128-bit integer
    // is correct because Verilog + treats [127:0] as a natural
    // binary number with [127] as MSB - matching big-endian.
    assign V_out = V_in + 128'd1;

endmodule