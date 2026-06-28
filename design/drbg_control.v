// =============================================================
//  drbg_control.v
//  AES-CTR-DRBG control FSM (NIST SP 800-90A, Section 10.2.1)
//  AES-256, No Derivation Function.
//
//  Matches MATLAB functions exactly:
//    ctr_drbg_instantiate() → ctr_drbg_update() → state (Key, V)
//    ctr_drbg_generate()    → output bytes, then ctr_drbg_update(zeros)
//
//  ── MATLAB Flow (per seed) ────────────────────────────────────
//  Instantiate:
//    seed_material = [entropy_32bytes || 0x00 × 16]  (48 bytes)
//    Key = 0x00 × 32,  V = 0x00 × 16
//    (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
//
//  CTR_DRBG_Update(provided_48, Key, V):
//    V = inc128(V); blk0 = AES(Key, V)   → first  16 bytes of temp
//    V = inc128(V); blk1 = AES(Key, V)   → next   16 bytes of temp
//    V = inc128(V); blk2 = AES(Key, V)   → last   16 bytes of temp
//    temp = temp XOR provided_48
//    Key_new = temp[0:31];  V_new = temp[32:47]
//
//  Generate(Key, V, 256 bits):
//    V = inc128(V); blk0 = AES(Key, V)   → output bytes  0-15
//    V = inc128(V); blk1 = AES(Key, V)   → output bytes 16-31
//    (Key, V) = CTR_DRBG_Update(0x00×48, Key, V)   ← reseed step
//      → 3 more AES calls with updated V producing new Key/V
//
//  Total AES calls per seed: 3 (instantiate) + 2 (generate) + 3 (reseed) = 8
//
//  ── FSM States ────────────────────────────────────────────────
//  IDLE          : waiting for seed_valid
//  INST_AES0..2  : 3 AES calls for CTR_DRBG_Update(instantiate)
//  INST_UPDATE   : XOR temp with seed, extract Key/V
//  GEN_AES0..1   : 2 AES calls for generate output
//  RESEED_AES0..2: 3 AES calls for CTR_DRBG_Update(zeros)
//  RESEED_UPDATE : XOR temp with zeros, extract new Key/V
//  DONE          : pulse drbg_valid, return to IDLE
//
//  ── Interface ─────────────────────────────────────────────────
//  Each SHA-256 digest arrives as a 256-bit seed.  This module
//  processes it and emits a 256-bit DRBG output.  Any number of
//  seeds may be streamed in back-to-back.
//
//  Ports:
//    clk, rst_n          : clock, active-low reset
//    seed_valid          : 1-cycle pulse; seed_data must be stable
//    seed_data [255:0]   : 256-bit SHA-256 digest (entropy)
//    drbg_valid          : 1-cycle pulse when drbg_out is ready
//    drbg_out  [255:0]   : 256-bit pseudorandom output
// =============================================================


module drbg_control (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         seed_valid,
    input  wire [255:0] seed_data,
    output reg          drbg_valid,
    output reg  [255:0] drbg_out
);

    // ── FSM state encoding ────────────────────────────────────────────────────
    localparam [3:0]
        S_IDLE          = 4'd0,
        S_INST_AES0     = 4'd1,   // AES call 0 of CTR_DRBG_Update (instantiate)
        S_INST_WAIT0    = 4'd2,
        S_INST_AES1     = 4'd3,   // AES call 1
        S_INST_WAIT1    = 4'd4,
        S_INST_AES2     = 4'd5,   // AES call 2
        S_INST_WAIT2    = 4'd6,
        S_INST_UPDATE   = 4'd7,   // XOR + split → Key, V
        S_GEN_AES0      = 4'd8,   // AES call 0 of generate
        S_GEN_WAIT0     = 4'd9,
        S_GEN_AES1      = 4'd10,  // AES call 1 of generate
        S_GEN_WAIT1     = 4'd11,
        S_RESEED        = 4'd12,  // kick off CTR_DRBG_Update(zeros) inline
        S_DONE          = 4'd13;

    // The reseed CTR_DRBG_Update(zeros) reuses the same AES-call pattern.
    // We fold it into an additional "phase" flag rather than duplicate states.
    // phase=0 → instantiate update, phase=1 → reseed update
    // We reuse states S_INST_AES0..S_INST_UPDATE for the reseed update as well,
    // controlled by the `reseed_phase` register set before entering S_INST_AES0.

    localparam [3:0]
        S_RUPD_AES0     = 4'd8,   // reuse gen slot - but we need distinct
        S_RUPD_WAIT0    = 4'd9,
        S_RUPD_AES1     = 4'd10,
        S_RUPD_WAIT1    = 4'd11,
        S_RUPD_AES2     = 4'd12,
        S_RUPD_WAIT2    = 4'd13;
    // Actually, let's use a cleaner approach: a sub-phase counter 0-2 and
    // a mode bit (INSTANTIATE_UPDATE vs RESEED_UPDATE vs GENERATE).
    // Simplified linear FSM below is clearer for synthesis.

    // ── DRBG internal state ───────────────────────────────────────────────────
    reg [255:0] Key;        // current AES-256 key
    reg [127:0] V;          // current 128-bit counter
    reg [383:0] temp;       // accumulates 3 × 128-bit AES outputs (48 bytes)
    reg [383:0] seed_mat;   // 48-byte seed material for CTR_DRBG_Update
    reg [255:0] gen_out;    // accumulates 2 × 128-bit generate outputs

    // ── AES-core wiring ───────────────────────────────────────────────────────
    reg          aes_start;
    reg  [255:0] aes_key_in;
    reg  [127:0] aes_pt_in;
    wire [127:0] aes_ct_out;
    wire         aes_valid;

    aes_core u_aes (
        .clk              (clk),
        .rst_n            (rst_n),
        .start            (aes_start),
        .key              (aes_key_in),
        .plaintext        (aes_pt_in),
        .ciphertext       (aes_ct_out),
        .ciphertext_valid (aes_valid)
    );

    // ── CTR logic wiring ─────────────────────────────────────────────────────
    wire [127:0] V_inc;
    ctr_logic u_ctr (.V_in(V), .V_out(V_inc));

    // ── FSM ───────────────────────────────────────────────────────────────────
    // Linear 15-state chain: each AES call is a 2-state pair (KICK + WAIT)
    // State encoding (4 bits, 0-13 defined above, we need up to 15 states)

    // Expanded state encoding
    localparam [4:0]
        ST_IDLE       = 5'd0,
        // Instantiate: CTR_DRBG_Update(seed_mat, 0^256, 0^128)
        ST_IU_AES0    = 5'd1,   // inc V, kick AES
        ST_IU_WAIT0   = 5'd2,   // wait aes_valid, store blk0
        ST_IU_AES1    = 5'd3,
        ST_IU_WAIT1   = 5'd4,
        ST_IU_AES2    = 5'd5,
        ST_IU_WAIT2   = 5'd6,
        ST_IU_XOR     = 5'd7,   // XOR temp48 with seed_mat → Key, V
        // Generate: 2 AES calls → 32 output bytes
        ST_GEN_AES0   = 5'd8,
        ST_GEN_WAIT0  = 5'd9,
        ST_GEN_AES1   = 5'd10,
        ST_GEN_WAIT1  = 5'd11,
        // Reseed: CTR_DRBG_Update(0^384, Key, V)
        ST_RU_AES0    = 5'd12,
        ST_RU_WAIT0   = 5'd13,
        ST_RU_AES1    = 5'd14,
        ST_RU_WAIT1   = 5'd15,
        ST_RU_AES2    = 5'd16,
        ST_RU_WAIT2   = 5'd17,
        ST_RU_XOR     = 5'd18,  // XOR temp48 with zeros → Key, V
        ST_DONE       = 5'd19;

    reg [4:0] state;

    // ── XOR + split helper (combinational) ───────────────────────────────────
    // temp XOR seed_mat → Key_new = [383:128], V_new = [127:0]
    // (temp is 384 bits = 48 bytes; MATLAB: Key=temp[0:31], V=temp[32:47])
    // In our packing: temp[383:128] = bytes 0-31 = Key_new
    //                 temp[127:0]   = bytes 32-47 = V_new
    wire [383:0] temp_xored;
    assign temp_xored = temp ^ seed_mat;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= ST_IDLE;
            Key        <= 256'd0;
            V          <= 128'd0;
            temp       <= 384'd0;
            seed_mat   <= 384'd0;
            gen_out    <= 256'd0;
            aes_start  <= 1'b0;
            aes_key_in <= 256'd0;
            aes_pt_in  <= 128'd0;
            drbg_valid <= 1'b0;
            drbg_out   <= 256'd0;
        end
        else begin
            aes_start  <= 1'b0;   // default: deassert
            drbg_valid <= 1'b0;   // default: deassert

            case (state)

                // ── IDLE: wait for seed ───────────────────────────────────
                ST_IDLE: begin
                    if (seed_valid) begin
                        // MATLAB ctr_drbg_instantiate:
                        //   seed_material = [entropy_32bytes || 0x00 × 16]
                        //   Key = 0^256,  V = 0^128
                        seed_mat <= {seed_data, 128'd0};  // 32 bytes entropy + 16 zero bytes
                        Key      <= 256'd0;
                        V        <= 128'd0;
                        state    <= ST_IU_AES0;
                    end
                end

                // ════════════════════════════════════════════════════════
                // INSTANTIATE: CTR_DRBG_Update(seed_mat, Key=0, V=0)
                // ════════════════════════════════════════════════════════

                // ── IU AES call 0: V = inc(V); blk0 = AES(Key, V) ────────
                ST_IU_AES0: begin
                    V         <= V_inc;       // inc128(V)
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;      // encrypt incremented V
                    aes_start  <= 1'b1;
                    state      <= ST_IU_WAIT0;
                end

                ST_IU_WAIT0: begin
                    if (aes_valid) begin
                        temp[383:256] <= aes_ct_out;  // blk0 = bytes 0-15
                        state         <= ST_IU_AES1;
                    end
                end

                // ── IU AES call 1: V = inc(V); blk1 = AES(Key, V) ────────
                ST_IU_AES1: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_IU_WAIT1;
                end

                ST_IU_WAIT1: begin
                    if (aes_valid) begin
                        temp[255:128] <= aes_ct_out;  // blk1 = bytes 16-31
                        state         <= ST_IU_AES2;
                    end
                end

                // ── IU AES call 2: V = inc(V); blk2 = AES(Key, V) ────────
                ST_IU_AES2: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_IU_WAIT2;
                end

                ST_IU_WAIT2: begin
                    if (aes_valid) begin
                        temp[127:0] <= aes_ct_out;   // blk2 = bytes 32-47
                        state       <= ST_IU_XOR;
                    end
                end

                // ── IU XOR: temp = temp XOR seed_mat; Key=temp[0:31], V=temp[32:47]
                ST_IU_XOR: begin
                    // temp_xored = temp ^ seed_mat (combinational, stable now)
                    Key   <= temp_xored[383:128];  // bytes 0-31
                    V     <= temp_xored[127:0];    // bytes 32-47
                    temp  <= 384'd0;               // clear for next use
                    state <= ST_GEN_AES0;
                end

                // ════════════════════════════════════════════════════════
                // GENERATE: 2 AES calls → 32 output bytes
                // ════════════════════════════════════════════════════════

                // ── GEN AES call 0: V = inc(V); blk0 = AES(Key, V) ───────
                ST_GEN_AES0: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_GEN_WAIT0;
                end

                ST_GEN_WAIT0: begin
                    if (aes_valid) begin
                        gen_out[255:128] <= aes_ct_out;  // output bytes 0-15
                        state            <= ST_GEN_AES1;
                    end
                end

                // ── GEN AES call 1: V = inc(V); blk1 = AES(Key, V) ───────
                ST_GEN_AES1: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_GEN_WAIT1;
                end

                ST_GEN_WAIT1: begin
                    if (aes_valid) begin
                        gen_out[127:0] <= aes_ct_out;   // output bytes 16-31
                        // ── Kick reseed: CTR_DRBG_Update(0^384, Key, V) ───
                        // seed_mat = all zeros (MATLAB: zeros(1,48,'uint8'))
                        seed_mat <= 384'd0;
                        state    <= ST_RU_AES0;
                    end
                end

                // ════════════════════════════════════════════════════════
                // RESEED: CTR_DRBG_Update(0^384, Key, V)
                // Same 3-AES-call pattern as instantiate update
                // ════════════════════════════════════════════════════════

                // ── RU AES call 0 ─────────────────────────────────────────
                ST_RU_AES0: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_RU_WAIT0;
                end

                ST_RU_WAIT0: begin
                    if (aes_valid) begin
                        temp[383:256] <= aes_ct_out;
                        state         <= ST_RU_AES1;
                    end
                end

                // ── RU AES call 1 ─────────────────────────────────────────
                ST_RU_AES1: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_RU_WAIT1;
                end

                ST_RU_WAIT1: begin
                    if (aes_valid) begin
                        temp[255:128] <= aes_ct_out;
                        state         <= ST_RU_AES2;
                    end
                end

                // ── RU AES call 2 ─────────────────────────────────────────
                ST_RU_AES2: begin
                    V          <= V_inc;
                    aes_key_in <= Key;
                    aes_pt_in  <= V_inc;
                    aes_start  <= 1'b1;
                    state      <= ST_RU_WAIT2;
                end

                ST_RU_WAIT2: begin
                    if (aes_valid) begin
                        temp[127:0] <= aes_ct_out;
                        state       <= ST_RU_XOR;
                    end
                end

                // ── RU XOR: temp = temp XOR 0^384; Key=temp[0:31], V=temp[32:47]
                // XOR with zeros is identity, but we keep the structure
                // identical to instantiate for clarity and correctness.
                ST_RU_XOR: begin
                    Key   <= temp_xored[383:128];  // seed_mat=0, so just temp
                    V     <= temp_xored[127:0];
                    temp  <= 384'd0;
                    state <= ST_DONE;
                end

                // ── DONE: output gen_out, return to IDLE ──────────────────
                ST_DONE: begin
                    drbg_out   <= gen_out;
                    drbg_valid <= 1'b1;
                    state      <= ST_IDLE;
                end

                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule