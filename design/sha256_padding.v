// =============================================================
//  sha256_padding.v
//  Pads an incoming byte block to a 512-bit (64-byte) message
//  block as required by SHA-256 (FIPS 180-4).
//
//  Your MATLAB feeds 35-byte chunks (275 bits zero-padded to
//  280 bits = 35 bytes).  This module accepts up to 55 bytes
//  (the SHA-256 single-block limit) and produces one padded
//  512-bit block.
//
//  Padding rule:
//    1. Append 0x80 after last data byte
//    2. Append 0x00 until total = 56 bytes
//    3. Append original bit-length as 64-bit big-endian
//
//  Interface:
//    - data_in      : raw input bytes, left-justified in 440-bit
//                     bus (55 bytes max). Only num_bytes are valid.
//    - num_bytes    : number of valid bytes in data_in (6-bit)
//    - padded_block : 512-bit padded output, ready to feed core
// =============================================================

module sha256_padding (
    input  wire [439:0] data_in,      // up to 55 bytes, MSB-first
    input  wire [5:0]   num_bytes,    // how many bytes are valid (1-55)
    output reg  [511:0] padded_block  // 512-bit padded message block
);

    integer i;
    reg [7:0] byte_buf [0:63];   // working buffer, 64 bytes
    reg [63:0] bit_length;

    always @(*) begin
        // ── Step 1: copy input bytes into buffer ──────────────
        for (i = 0; i < 64; i = i + 1)
            byte_buf[i] = 8'h00;

        for (i = 0; i < 55; i = i + 1) begin
            if (i < num_bytes)
                // data_in is MSB-first: byte 0 is bits [439:432]
                byte_buf[i] = data_in[439 - i*8 -: 8];
        end

        // ── Step 2: append 0x80 after last data byte ──────────
        byte_buf[num_bytes] = 8'h80;

        // ── Step 3: bytes num_bytes+1 .. 55 stay 0x00 ─────────
        // (already zeroed in init loop above)

        // ── Step 4: append 64-bit big-endian bit-length ───────
        // bit_length = num_bytes * 8
        bit_length = {58'b0, num_bytes} << 3;  // num_bytes * 8

        byte_buf[56] = bit_length[63:56];
        byte_buf[57] = bit_length[55:48];
        byte_buf[58] = bit_length[47:40];
        byte_buf[59] = bit_length[39:32];
        byte_buf[60] = bit_length[31:24];
        byte_buf[61] = bit_length[23:16];
        byte_buf[62] = bit_length[15:8];
        byte_buf[63] = bit_length[7:0];

        // ── Step 5: pack buffer into 512-bit output ────────────
        for (i = 0; i < 64; i = i + 1)
            padded_block[511 - i*8 -: 8] = byte_buf[i];
    end

endmodule