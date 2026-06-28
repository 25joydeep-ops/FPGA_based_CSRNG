// =============================================================
//  sha256_schedule.v  (Verilog-2001 compatible)
//
//  FIX: output port W changed from array [31:0] W [0:63]
//       to flat packed bus [2047:0] W_flat.
//       W[i] = W_flat[2047 - i*32 -: 32]
//
//  Verilog-2001 does not permit unpacked arrays as module ports.
//  All array indexing is done internally using local wires;
//  only the flat bus crosses the module boundary.
// =============================================================

module sha256_schedule (
    input  wire [511:0]  padded_block,
    output wire [2047:0] W_flat      // 64 x 32-bit words, W[i] at [2047-i*32 -: 32]
);

    // ── Internal wire array (legal inside the module) ─────────
    wire [31:0] W [0:63];

    // ── σ0 and σ1 functions (message schedule) ────────────────
    function [31:0] sigma0;
        input [31:0] x;
        sigma0 = {x[6:0],  x[31:7]}  ^
                 {x[17:0], x[31:18]} ^
                 (x >> 3);
    endfunction

    function [31:0] sigma1;
        input [31:0] x;
        sigma1 = {x[16:0], x[31:17]} ^
                 {x[18:0], x[31:19]} ^
                 (x >> 10);
    endfunction

    genvar t;

    // ── W[0..15]: from padded message block ───────────────────
    generate
        for (t = 0; t < 16; t = t + 1) begin : w_init
            assign W[t] = padded_block[511 - t*32 -: 32];
        end
    endgenerate

    // ── W[16..63]: schedule expansion ────────────────────────
    generate
        for (t = 16; t < 64; t = t + 1) begin : w_expand
            assign W[t] = sigma1(W[t-2])  + W[t-7] +
                          sigma0(W[t-15]) + W[t-16];
        end
    endgenerate

    // ── Flatten internal array → output bus ──────────────────
    generate
        for (t = 0; t < 64; t = t + 1) begin : w_pack
            assign W_flat[2047 - t*32 -: 32] = W[t];
        end
    endgenerate

endmodule