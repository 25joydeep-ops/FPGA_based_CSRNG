// =============================================================
//  aes_rounds.v
//  AES-256 encryption rounds - sequential FSM.
//
//  Implements exactly the MATLAB aes256_encrypt() inner loop:
//
//    AddRoundKey(state, rk[0])           ← initial round
//    for rnd = 1..13:                    ← rounds 1-13 (mixed)
//        SubBytes → ShiftRows → MixColumns → AddRoundKey(rk[rnd])
//    SubBytes → ShiftRows → AddRoundKey(rk[14])  ← final round (no MixColumns)
//
//  Timing: assert start for 1 cycle with plaintext + round_keys valid.
//          ciphertext_valid pulses high 16 cycles later (1 init + 14 rounds).
//
//  Ports:
//    clk, rst_n          : clock, active-low reset
//    start               : 1-cycle pulse, load plaintext and begin
//    plaintext  [127:0]  : 128-bit input block
//    round_keys [1919:0] : 15 x 128-bit round keys from key_expansion
//    ciphertext [127:0]  : 128-bit AES-256 output
//    ciphertext_valid    : 1-cycle pulse when ciphertext is ready
//
//  State matrix convention (matching MATLAB bytes_to_state / state_to_bytes):
//    Column-major: byte 0 → state[row=0,col=0], byte 1 → state[row=1,col=0] ...
//    Packed in this module as: plaintext[127:120] = byte 0 = col0,row0
//    state[col][row] in a 4x4 byte array indexed [0..3][0..3]
// =============================================================

module aes_rounds (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] plaintext,
    input  wire [1919:0] round_keys,
    output reg  [127:0] ciphertext,
    output reg          ciphertext_valid
);

    // ── GF(2^8) multiply-by-2 (xtime) ────────────────────────────────────────
    // Matches MATLAB gmul2: if MSB set, shift left and XOR 0x1b; mask to 8 bits
    function [7:0] xtime;
        input [7:0] a;
        xtime = a[7] ? ((a << 1) ^ 8'h1b) : (a << 1);
    endfunction

    // ── GF(2^8) multiply-by-3 = xtime(a) XOR a ───────────────────────────────
    function [7:0] xtime3;
        input [7:0] a;
        xtime3 = xtime(a) ^ a;
    endfunction

    // ── S-Box instances: 16 parallel lookups for SubBytes ─────────────────────
    // state_in  [0..15] maps to state bytes in column-major order
    wire [7:0] sb_in  [0:15];
    wire [7:0] sb_out [0:15];

    genvar gi;
    generate
        for (gi = 0; gi < 16; gi = gi + 1) begin : sbox_array
            aes_sbox u_sbox (.in(sb_in[gi]), .out(sb_out[gi]));
        end
    endgenerate

    // ── Round key extraction helper ───────────────────────────────────────────
    // round_keys[1919 - r*128 -: 128] for r = 0..14
    // Each 128-bit key packed as 4 words [127:0] = {w0, w1, w2, w3}
    // rk byte b of round r = round_keys[1919 - r*128 - b*8 -: 8]

    // ── State register: 4x4 bytes, column-major [col][row] ───────────────────
    // Packed as: state_reg[127 - (col*4+row)*8 -: 8] = state[col][row]
    // This matches MATLAB bytes_to_state / state_to_bytes exactly.
    //
    //   byte index in 128-bit word → (col, row):
    //   byte 0  → col=0,row=0  → bits [127:120]
    //   byte 1  → col=0,row=1  → bits [119:112]
    //   byte 2  → col=0,row=2  → bits [111:104]
    //   byte 3  → col=0,row=3  → bits [103:96]
    //   byte 4  → col=1,row=0  → bits [95:88]
    //   ...
    //   byte 15 → col=3,row=3  → bits [7:0]

    reg [127:0] state_reg;
    reg [3:0]   round_cnt;   // 0 = init ARK, 1-14 = rounds 1-14
    reg         busy;

    // ── Wire current state bytes as array for clarity ─────────────────────────
    wire [7:0] s [0:3][0:3];  // s[col][row]
    genvar gc, gr;
    generate
        for (gc = 0; gc < 4; gc = gc + 1) begin : col_wire
            for (gr = 0; gr < 4; gr = gr + 1) begin : row_wire
                assign s[gc][gr] = state_reg[127 - (gc*4 + gr)*8 -: 8];
            end
        end
    endgenerate

    // ── S-box inputs: feed current state bytes (used during SubBytes step) ────
    // Flat mapping: sb_in[col*4+row] = s[col][row]
    generate
        for (gc = 0; gc < 4; gc = gc + 1) begin : sbin_col
            for (gr = 0; gr < 4; gr = gr + 1) begin : sbin_row
                assign sb_in[gc*4 + gr] = s[gc][gr];
            end
        end
    endgenerate

    // ── SubBytes result: sb_out[col*4+row] = S[s[col][row]] ──────────────────
    // ── ShiftRows: row r is left-rotated by r positions ───────────────────────
    // After SubBytes+ShiftRows:
    //   sr[col][row] = sb_out[(col + row) mod 4 * 4 + row]
    //                = S[ s[(col+row)%4][row] ]
    wire [7:0] sr [0:3][0:3];  // sr[col][row] = after SubBytes+ShiftRows
    generate
        for (gc = 0; gc < 4; gc = gc + 1) begin : sr_col
            for (gr = 0; gr < 4; gr = gr + 1) begin : sr_row
                // ShiftRows: column gc, row gr gets source from column (gc+gr)%4
                assign sr[gc][gr] = sb_out[((gc + gr) % 4)*4 + gr];
            end
        end
    endgenerate

    // ── MixColumns on ShiftRows result ───────────────────────────────────────
    // For each column c (matching MATLAB mix_columns per column):
    //   out[0] = xtime(sr[0]) ^ xtime3(sr[1]) ^ sr[2]        ^ sr[3]
    //   out[1] = sr[0]        ^ xtime(sr[1])  ^ xtime3(sr[2])^ sr[3]
    //   out[2] = sr[0]        ^ sr[1]         ^ xtime(sr[2]) ^ xtime3(sr[3])
    //   out[3] = xtime3(sr[0])^ sr[1]         ^ sr[2]        ^ xtime(sr[3])
    wire [7:0] mc [0:3][0:3];  // mc[col][row]
    generate
        for (gc = 0; gc < 4; gc = gc + 1) begin : mc_col
            assign mc[gc][0] = xtime(sr[gc][0]) ^ xtime3(sr[gc][1]) ^ sr[gc][2]         ^ sr[gc][3];
            assign mc[gc][1] = sr[gc][0]        ^ xtime(sr[gc][1])  ^ xtime3(sr[gc][2]) ^ sr[gc][3];
            assign mc[gc][2] = sr[gc][0]        ^ sr[gc][1]         ^ xtime(sr[gc][2])  ^ xtime3(sr[gc][3]);
            assign mc[gc][3] = xtime3(sr[gc][0])^ sr[gc][1]         ^ sr[gc][2]         ^ xtime(sr[gc][3]);
        end
    endgenerate

    // ── Round key byte extraction: rk[r][col][row] ───────────────────────────
    // round_keys[1919 - r*128 - (col*4+row)*8 -: 8]
    // We wire this directly in the FSM using round_cnt

    // ── Round key for current round ───────────────────────────────────────────
    wire [127:0] cur_rk = round_keys[1919 - round_cnt*128 -: 128];

    // ── FSM ───────────────────────────────────────────────────────────────────
    integer col, row;
    reg [7:0] next_state [0:3][0:3];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy             <= 1'b0;
            ciphertext_valid <= 1'b0;
            round_cnt        <= 4'd0;
            state_reg        <= 128'd0;
            ciphertext       <= 128'd0;
        end
        else begin
            ciphertext_valid <= 1'b0;  // default deassert

            if (start && !busy) begin
                // ── Round 0: AddRoundKey with round_key[0] ────────────
                // state = plaintext XOR round_keys[0]
                state_reg <= plaintext ^ round_keys[1919:1792];  // rk[0]
                round_cnt <= 4'd1;
                busy      <= 1'b1;
            end

            else if (busy) begin
                if (round_cnt < 14) begin
                    // ── Rounds 1-13: SubBytes, ShiftRows, MixColumns, ARK ──
                    // Build new state from mc[] XOR cur_rk
                    begin : mixed_round
                        reg [127:0] new_state;
                        integer c, r2;
                        new_state = 128'd0;
                        for (c = 0; c < 4; c = c + 1) begin
                            for (r2 = 0; r2 < 4; r2 = r2 + 1) begin
                                new_state[127 - (c*4+r2)*8 -: 8] =
                                    mc[c][r2] ^ cur_rk[127 - (c*4+r2)*8 -: 8];
                            end
                        end
                        state_reg <= new_state;
                    end
                    round_cnt <= round_cnt + 4'd1;
                end

                else begin
                    // ── Round 14: SubBytes, ShiftRows, ARK (no MixColumns) ─
                    // cur_rk = round_keys[14]
                    begin : final_round
                        reg [127:0] new_state;
                        integer c, r2;
                        new_state = 128'd0;
                        for (c = 0; c < 4; c = c + 1) begin
                            for (r2 = 0; r2 < 4; r2 = r2 + 1) begin
                                // sr[c][r2] = SubBytes+ShiftRows result
                                new_state[127 - (c*4+r2)*8 -: 8] =
                                    sr[c][r2] ^ cur_rk[127 - (c*4+r2)*8 -: 8];
                            end
                        end
                        ciphertext       <= new_state;
                        ciphertext_valid <= 1'b1;
                        busy             <= 1'b0;
                        round_cnt        <= 4'd0;
                    end
                end
            end
        end
    end

endmodule