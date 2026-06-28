// =============================================================
//  aes_core.v
//  AES-256 encrypt-only core.
//
//  Wires key_expansion (combinational) and aes_rounds (sequential)
//  together.  Matches MATLAB aes256_encrypt() exactly.
//
//  Key expansion is purely combinational - round keys are stable
//  1 cycle after key is applied, so they are valid by the time
//  aes_rounds begins its first round on the cycle after start.
//
//  Timing: assert start for 1 cycle with key + plaintext valid.
//          ciphertext_valid pulses high 16 cycles later.
//          (1 cycle initial ARK + 13 mixed rounds + 1 final round
//           = 15 state transitions, valid on cycle 16)
//
//  Ports:
//    clk, rst_n           : clock, active-low reset
//    start                : 1-cycle pulse to begin
//    key        [255:0]   : AES-256 key
//    plaintext  [127:0]   : 128-bit plaintext block
//    ciphertext [127:0]   : 128-bit ciphertext output
//    ciphertext_valid     : 1-cycle pulse when output is ready
// =============================================================


module aes_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] key,
    input  wire [127:0] plaintext,
    output wire [127:0] ciphertext,
    output wire         ciphertext_valid
);

    // ── Round keys from key schedule (combinational) ──────────────────────────
    wire [1919:0] round_keys;

    key_expansion u_kexp (
        .key        (key),
        .round_keys (round_keys)
    );

    // ── AES rounds FSM ────────────────────────────────────────────────────────
    aes_rounds u_rounds (
        .clk              (clk),
        .rst_n            (rst_n),
        .start            (start),
        .plaintext        (plaintext),
        .round_keys       (round_keys),
        .ciphertext       (ciphertext),
        .ciphertext_valid (ciphertext_valid)
    );

endmodule