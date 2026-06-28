// =============================================================
//  sha256_top.v  (Verilog-2001 compatible)
//
//  FIXES applied:
//  1. Removed wire [31:0] H_init [0:7] array -
//     replaced with wire [255:0] H_init_flat packed directly
//     from H0 localparams.
//  2. Removed wire [31:0] digest_words [0:7] array -
//     sha256_core now outputs reg [255:0] digest directly,
//     so digest is wired straight through.
//  3. sha256_core port .H_in → .H_in_flat
//     sha256_core port .digest now [255:0] wire, not array.
// =============================================================
module sha256_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [274:0] chunk_data,
    output wire [255:0] digest,
    output wire         digest_valid
);

    // ── SHA-256 Initial Hash Values (FIPS 180-4) ──────────────
    localparam [31:0] H0_0 = 32'h6a09e667;
    localparam [31:0] H0_1 = 32'hbb67ae85;
    localparam [31:0] H0_2 = 32'h3c6ef372;
    localparam [31:0] H0_3 = 32'ha54ff53a;
    localparam [31:0] H0_4 = 32'h510e527f;
    localparam [31:0] H0_5 = 32'h9b05688c;
    localparam [31:0] H0_6 = 32'h1f83d9ab;
    localparam [31:0] H0_7 = 32'h5be0cd19;

    // ── H_init as flat 256-bit bus (no array needed) ──────────
    // sha256_core expects H_in_flat[255-i*32 -: 32] = H[i]
    wire [255:0] H_init_flat;
    assign H_init_flat = {H0_0, H0_1, H0_2, H0_3,
                          H0_4, H0_5, H0_6, H0_7};

    // ── Zero-pad 275 bits → 440-bit bus for padding module ────
    wire [439:0] byte_aligned;
    assign byte_aligned = {chunk_data, 5'b00000, 160'b0};

    // ── Padding module ────────────────────────────────────────
    wire [511:0] padded_block;
    sha256_padding u_pad (
        .data_in      (byte_aligned),
        .num_bytes    (6'd35),
        .padded_block (padded_block)
    );

    // ── SHA-256 core ──────────────────────────────────────────
    // digest is now [255:0] wire directly from core output reg.
    // No intermediate array needed.
    sha256_core u_core (
        .clk          (clk),
        .rst_n        (rst_n),
        .start        (start),
        .padded_block (padded_block),
        .H_in_flat    (H_init_flat),
        .digest       (digest),
        .digest_valid (digest_valid)
    );

endmodule