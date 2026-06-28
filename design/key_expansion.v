// =============================================================
//  key_expansion.v
//  AES-256 Key Schedule - expands 256-bit key into 15 round keys.
//
//  Matches MATLAB aes_key_expansion() exactly:
//    - Input  : 256-bit key (32 bytes)
//    - Output : 15 x 128-bit round keys (w[0..3] through w[56..59])
//      packed as a flat 1920-bit bus [1919:0], round key r at
//      bits [1919 - r*128 -: 128], r = 0..14
//
//  AES-256 schedule:
//    - w[0..7]  : loaded directly from key bytes
//    - w[i], i >= 8:
//        temp = w[i-1]
//        if (i mod 8 == 0): SubWord(RotWord(temp)) XOR Rcon[i/8]
//        if (i mod 8 == 4): SubWord(temp)
//        else              : temp unchanged
//        w[i] = w[i-8] XOR temp
//    - 60 words total → 15 round keys of 4 words each
//
//  This is purely combinational.
//
//  Ports:
//    key [255:0]       : 256-bit AES key, MSB = byte 0
//    round_keys [1919:0]: 15 packed 128-bit round keys
// =============================================================

module key_expansion (
    input  wire [255:0] key,
    output wire [1919:0] round_keys
);

    // ── RCON values - match MATLAB RCON array (1-indexed, we use 0-indexed) ──
    // MATLAB: RCON[1..7] used at i/8 = 1..7 (i = 8,16,24,32,40,48,56)
    // Note: only 7 Rcon values are needed for AES-256 (60 words, 8 original)
    wire [7:0] RCON [0:6];
    assign RCON[0] = 8'h01;  // used at i=8  (i/8=1)
    assign RCON[1] = 8'h02;  // used at i=16 (i/8=2)
    assign RCON[2] = 8'h04;  // used at i=24 (i/8=3)
    assign RCON[3] = 8'h08;  // used at i=32 (i/8=4)
    assign RCON[4] = 8'h10;  // used at i=40 (i/8=5)
    assign RCON[5] = 8'h20;  // used at i=48 (i/8=6)
    assign RCON[6] = 8'h40;  // used at i=56 (i/8=7)

    // ── Key words w[0..59], each 32 bits ─────────────────────────────────────
    wire [31:0] w [0:59];

    // ── w[0..7]: directly from key bytes (MSB-first) ─────────────────────────
    // MATLAB: w(:,i) = key_bytes((i-1)*4+1 : i*4)' for i=1..8
    assign w[0] = key[255:224];
    assign w[1] = key[223:192];
    assign w[2] = key[191:160];
    assign w[3] = key[159:128];
    assign w[4] = key[127:96];
    assign w[5] = key[95:64];
    assign w[6] = key[63:32];
    assign w[7] = key[31:0];

    // ── S-Box instances for key schedule ─────────────────────────────────────
    // We need SubWord on a 4-byte word = 4 parallel S-box lookups.
    // Instantiate one set of 4 S-boxes per word that needs SubWord.
    // Words needing SubWord: i mod 8 == 0 (after RotWord) and i mod 8 == 4
    // That is words: 8,12,16,20,24,28,32,36,40,44,48,52,56 (13 SubWord ops)
    // We'll use a generate block with a helper function pattern instead -
    // Verilog-2001 doesn't support functions returning arrays, so we
    // instantiate the sbox inline using a wire array approach.

    // SubWord results for each relevant word index
    // For i mod 8 == 0: apply RotWord then SubWord to w[i-1]
    // RotWord(w) = {w[23:0], w[31:24]}  (rotate left by one byte)

    // ── Helper wires: rotated and substituted words ───────────────────────────
    // We need SubWord(RotWord(w[i-1])) for i = 8,16,24,32,40,48,56
    // and SubWord(w[i-1])             for i = 12,20,28,36,44,52

    // Declare S-box output wires for all needed bytes
    // Format: sb_rXX_bY = S-box output for round word XX, byte Y
    // (XX = word index, Y = byte 0..3)

    // --- i=8: SubWord(RotWord(w[7])) XOR {RCON[0],0,0,0} ---
    wire [31:0] rot_w7  = {w[7][23:0],  w[7][31:24]};
    wire [7:0] sb_8_b0, sb_8_b1, sb_8_b2, sb_8_b3;
    aes_sbox u_sb_8_b0 (.in(rot_w7[31:24]), .out(sb_8_b0));
    aes_sbox u_sb_8_b1 (.in(rot_w7[23:16]), .out(sb_8_b1));
    aes_sbox u_sb_8_b2 (.in(rot_w7[15:8]),  .out(sb_8_b2));
    aes_sbox u_sb_8_b3 (.in(rot_w7[7:0]),   .out(sb_8_b3));
    wire [31:0] sw_8 = {sb_8_b0 ^ RCON[0], sb_8_b1, sb_8_b2, sb_8_b3};
    assign w[8] = w[0] ^ sw_8;

    assign w[9]  = w[1] ^ w[8];
    assign w[10] = w[2] ^ w[9];
    assign w[11] = w[3] ^ w[10];

    // --- i=12: SubWord(w[11]) ---
    wire [7:0] sb_12_b0, sb_12_b1, sb_12_b2, sb_12_b3;
    aes_sbox u_sb_12_b0 (.in(w[11][31:24]), .out(sb_12_b0));
    aes_sbox u_sb_12_b1 (.in(w[11][23:16]), .out(sb_12_b1));
    aes_sbox u_sb_12_b2 (.in(w[11][15:8]),  .out(sb_12_b2));
    aes_sbox u_sb_12_b3 (.in(w[11][7:0]),   .out(sb_12_b3));
    wire [31:0] sw_12 = {sb_12_b0, sb_12_b1, sb_12_b2, sb_12_b3};
    assign w[12] = w[4] ^ sw_12;

    assign w[13] = w[5]  ^ w[12];
    assign w[14] = w[6]  ^ w[13];
    assign w[15] = w[7]  ^ w[14];

    // --- i=16: SubWord(RotWord(w[15])) XOR {RCON[1],0,0,0} ---
    wire [31:0] rot_w15 = {w[15][23:0], w[15][31:24]};
    wire [7:0] sb_16_b0, sb_16_b1, sb_16_b2, sb_16_b3;
    aes_sbox u_sb_16_b0 (.in(rot_w15[31:24]), .out(sb_16_b0));
    aes_sbox u_sb_16_b1 (.in(rot_w15[23:16]), .out(sb_16_b1));
    aes_sbox u_sb_16_b2 (.in(rot_w15[15:8]),  .out(sb_16_b2));
    aes_sbox u_sb_16_b3 (.in(rot_w15[7:0]),   .out(sb_16_b3));
    wire [31:0] sw_16 = {sb_16_b0 ^ RCON[1], sb_16_b1, sb_16_b2, sb_16_b3};
    assign w[16] = w[8]  ^ sw_16;

    assign w[17] = w[9]  ^ w[16];
    assign w[18] = w[10] ^ w[17];
    assign w[19] = w[11] ^ w[18];

    // --- i=20: SubWord(w[19]) ---
    wire [7:0] sb_20_b0, sb_20_b1, sb_20_b2, sb_20_b3;
    aes_sbox u_sb_20_b0 (.in(w[19][31:24]), .out(sb_20_b0));
    aes_sbox u_sb_20_b1 (.in(w[19][23:16]), .out(sb_20_b1));
    aes_sbox u_sb_20_b2 (.in(w[19][15:8]),  .out(sb_20_b2));
    aes_sbox u_sb_20_b3 (.in(w[19][7:0]),   .out(sb_20_b3));
    wire [31:0] sw_20 = {sb_20_b0, sb_20_b1, sb_20_b2, sb_20_b3};
    assign w[20] = w[12] ^ sw_20;

    assign w[21] = w[13] ^ w[20];
    assign w[22] = w[14] ^ w[21];
    assign w[23] = w[15] ^ w[22];

    // --- i=24: SubWord(RotWord(w[23])) XOR {RCON[2],0,0,0} ---
    wire [31:0] rot_w23 = {w[23][23:0], w[23][31:24]};
    wire [7:0] sb_24_b0, sb_24_b1, sb_24_b2, sb_24_b3;
    aes_sbox u_sb_24_b0 (.in(rot_w23[31:24]), .out(sb_24_b0));
    aes_sbox u_sb_24_b1 (.in(rot_w23[23:16]), .out(sb_24_b1));
    aes_sbox u_sb_24_b2 (.in(rot_w23[15:8]),  .out(sb_24_b2));
    aes_sbox u_sb_24_b3 (.in(rot_w23[7:0]),   .out(sb_24_b3));
    wire [31:0] sw_24 = {sb_24_b0 ^ RCON[2], sb_24_b1, sb_24_b2, sb_24_b3};
    assign w[24] = w[16] ^ sw_24;

    assign w[25] = w[17] ^ w[24];
    assign w[26] = w[18] ^ w[25];
    assign w[27] = w[19] ^ w[26];

    // --- i=28: SubWord(w[27]) ---
    wire [7:0] sb_28_b0, sb_28_b1, sb_28_b2, sb_28_b3;
    aes_sbox u_sb_28_b0 (.in(w[27][31:24]), .out(sb_28_b0));
    aes_sbox u_sb_28_b1 (.in(w[27][23:16]), .out(sb_28_b1));
    aes_sbox u_sb_28_b2 (.in(w[27][15:8]),  .out(sb_28_b2));
    aes_sbox u_sb_28_b3 (.in(w[27][7:0]),   .out(sb_28_b3));
    wire [31:0] sw_28 = {sb_28_b0, sb_28_b1, sb_28_b2, sb_28_b3};
    assign w[28] = w[20] ^ sw_28;

    assign w[29] = w[21] ^ w[28];
    assign w[30] = w[22] ^ w[29];
    assign w[31] = w[23] ^ w[30];

    // --- i=32: SubWord(RotWord(w[31])) XOR {RCON[3],0,0,0} ---
    wire [31:0] rot_w31 = {w[31][23:0], w[31][31:24]};
    wire [7:0] sb_32_b0, sb_32_b1, sb_32_b2, sb_32_b3;
    aes_sbox u_sb_32_b0 (.in(rot_w31[31:24]), .out(sb_32_b0));
    aes_sbox u_sb_32_b1 (.in(rot_w31[23:16]), .out(sb_32_b1));
    aes_sbox u_sb_32_b2 (.in(rot_w31[15:8]),  .out(sb_32_b2));
    aes_sbox u_sb_32_b3 (.in(rot_w31[7:0]),   .out(sb_32_b3));
    wire [31:0] sw_32 = {sb_32_b0 ^ RCON[3], sb_32_b1, sb_32_b2, sb_32_b3};
    assign w[32] = w[24] ^ sw_32;

    assign w[33] = w[25] ^ w[32];
    assign w[34] = w[26] ^ w[33];
    assign w[35] = w[27] ^ w[34];

    // --- i=36: SubWord(w[35]) ---
    wire [7:0] sb_36_b0, sb_36_b1, sb_36_b2, sb_36_b3;
    aes_sbox u_sb_36_b0 (.in(w[35][31:24]), .out(sb_36_b0));
    aes_sbox u_sb_36_b1 (.in(w[35][23:16]), .out(sb_36_b1));
    aes_sbox u_sb_36_b2 (.in(w[35][15:8]),  .out(sb_36_b2));
    aes_sbox u_sb_36_b3 (.in(w[35][7:0]),   .out(sb_36_b3));
    wire [31:0] sw_36 = {sb_36_b0, sb_36_b1, sb_36_b2, sb_36_b3};
    assign w[36] = w[28] ^ sw_36;

    assign w[37] = w[29] ^ w[36];
    assign w[38] = w[30] ^ w[37];
    assign w[39] = w[31] ^ w[38];

    // --- i=40: SubWord(RotWord(w[39])) XOR {RCON[4],0,0,0} ---
    wire [31:0] rot_w39 = {w[39][23:0], w[39][31:24]};
    wire [7:0] sb_40_b0, sb_40_b1, sb_40_b2, sb_40_b3;
    aes_sbox u_sb_40_b0 (.in(rot_w39[31:24]), .out(sb_40_b0));
    aes_sbox u_sb_40_b1 (.in(rot_w39[23:16]), .out(sb_40_b1));
    aes_sbox u_sb_40_b2 (.in(rot_w39[15:8]),  .out(sb_40_b2));
    aes_sbox u_sb_40_b3 (.in(rot_w39[7:0]),   .out(sb_40_b3));
    wire [31:0] sw_40 = {sb_40_b0 ^ RCON[4], sb_40_b1, sb_40_b2, sb_40_b3};
    assign w[40] = w[32] ^ sw_40;

    assign w[41] = w[33] ^ w[40];
    assign w[42] = w[34] ^ w[41];
    assign w[43] = w[35] ^ w[42];

    // --- i=44: SubWord(w[43]) ---
    wire [7:0] sb_44_b0, sb_44_b1, sb_44_b2, sb_44_b3;
    aes_sbox u_sb_44_b0 (.in(w[43][31:24]), .out(sb_44_b0));
    aes_sbox u_sb_44_b1 (.in(w[43][23:16]), .out(sb_44_b1));
    aes_sbox u_sb_44_b2 (.in(w[43][15:8]),  .out(sb_44_b2));
    aes_sbox u_sb_44_b3 (.in(w[43][7:0]),   .out(sb_44_b3));
    wire [31:0] sw_44 = {sb_44_b0, sb_44_b1, sb_44_b2, sb_44_b3};
    assign w[44] = w[36] ^ sw_44;

    assign w[45] = w[37] ^ w[44];
    assign w[46] = w[38] ^ w[45];
    assign w[47] = w[39] ^ w[46];

    // --- i=48: SubWord(RotWord(w[47])) XOR {RCON[5],0,0,0} ---
    wire [31:0] rot_w47 = {w[47][23:0], w[47][31:24]};
    wire [7:0] sb_48_b0, sb_48_b1, sb_48_b2, sb_48_b3;
    aes_sbox u_sb_48_b0 (.in(rot_w47[31:24]), .out(sb_48_b0));
    aes_sbox u_sb_48_b1 (.in(rot_w47[23:16]), .out(sb_48_b1));
    aes_sbox u_sb_48_b2 (.in(rot_w47[15:8]),  .out(sb_48_b2));
    aes_sbox u_sb_48_b3 (.in(rot_w47[7:0]),   .out(sb_48_b3));
    wire [31:0] sw_48 = {sb_48_b0 ^ RCON[5], sb_48_b1, sb_48_b2, sb_48_b3};
    assign w[48] = w[40] ^ sw_48;

    assign w[49] = w[41] ^ w[48];
    assign w[50] = w[42] ^ w[49];
    assign w[51] = w[43] ^ w[50];

    // --- i=52: SubWord(w[51]) ---
    wire [7:0] sb_52_b0, sb_52_b1, sb_52_b2, sb_52_b3;
    aes_sbox u_sb_52_b0 (.in(w[51][31:24]), .out(sb_52_b0));
    aes_sbox u_sb_52_b1 (.in(w[51][23:16]), .out(sb_52_b1));
    aes_sbox u_sb_52_b2 (.in(w[51][15:8]),  .out(sb_52_b2));
    aes_sbox u_sb_52_b3 (.in(w[51][7:0]),   .out(sb_52_b3));
    wire [31:0] sw_52 = {sb_52_b0, sb_52_b1, sb_52_b2, sb_52_b3};
    assign w[52] = w[44] ^ sw_52;

    assign w[53] = w[45] ^ w[52];
    assign w[54] = w[46] ^ w[53];
    assign w[55] = w[47] ^ w[54];

    // --- i=56: SubWord(RotWord(w[55])) XOR {RCON[6],0,0,0} ---
    wire [31:0] rot_w55 = {w[55][23:0], w[55][31:24]};
    wire [7:0] sb_56_b0, sb_56_b1, sb_56_b2, sb_56_b3;
    aes_sbox u_sb_56_b0 (.in(rot_w55[31:24]), .out(sb_56_b0));
    aes_sbox u_sb_56_b1 (.in(rot_w55[23:16]), .out(sb_56_b1));
    aes_sbox u_sb_56_b2 (.in(rot_w55[15:8]),  .out(sb_56_b2));
    aes_sbox u_sb_56_b3 (.in(rot_w55[7:0]),   .out(sb_56_b3));
    wire [31:0] sw_56 = {sb_56_b0 ^ RCON[6], sb_56_b1, sb_56_b2, sb_56_b3};
    assign w[56] = w[48] ^ sw_56;

    assign w[57] = w[49] ^ w[56];
    assign w[58] = w[50] ^ w[57];
    assign w[59] = w[51] ^ w[58];

    // ── Pack 15 round keys into flat 1920-bit output ──────────────────────────
    // round_keys[1919 - r*128 -: 128] = {w[r*4], w[r*4+1], w[r*4+2], w[r*4+3]}
    // MATLAB: rk(:,:,r) = w(:, (r-1)*4+1 : r*4)  for r = 1..15
    genvar r;
    generate
        for (r = 0; r < 15; r = r + 1) begin : rk_pack
            assign round_keys[1919 - r*128 -: 128] = {
                w[r*4],   w[r*4+1],
                w[r*4+2], w[r*4+3]
            };
        end
    endgenerate

endmodule