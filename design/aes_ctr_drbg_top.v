// =============================================================
//  aes_ctr_drbg_top.v
//  AES-CTR-DRBG top-level module.
//
//  Instantiates drbg_control (which contains aes_core + ctr_logic).
//  Provides the clean external interface that seed_interface.v drives.
//
//  Ports:
//    clk, rst_n          : clock, active-low reset
//    seed_valid          : 1-cycle pulse; seed_data stable
//    seed_data [255:0]   : 256-bit entropy (SHA-256 digest)
//    drbg_valid          : 1-cycle pulse; drbg_out stable
//    drbg_out  [255:0]   : 256-bit pseudorandom output
// =============================================================


module aes_ctr_drbg_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         seed_valid,
    input  wire [255:0] seed_data,
    output wire         drbg_valid,
    output wire [255:0] drbg_out
);

    drbg_control u_drbg (
        .clk        (clk),
        .rst_n      (rst_n),
        .seed_valid (seed_valid),
        .seed_data  (seed_data),
        .drbg_valid (drbg_valid),
        .drbg_out   (drbg_out)
    );

endmodule