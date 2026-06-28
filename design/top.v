// =============================================================
//  top.v
//  Full system top-level for Chua CSRNG on XC7S50 Spartan-7.
//
//  ── Data flow ─────────────────────────────────────────────
//  PC (TeraTerm Send File)
//    → UART RX (1 ASCII byte per entropy bit)
//    → entropy_buffer (accumulates 275 ASCII chars → 275 bits)
//    → sha256_top (275-bit chunk → 256-bit digest)
//    → seed_interface (handshake / latch)
//    → aes_ctr_drbg_top (256-bit seed → 256-bit DRBG output)
//    → output_formatter (256-bit → 64 hex chars + newline)
//    → UART TX
//    → PC (TeraTerm log → .txt file)
//
//  ── ASCII entropy input protocol ──────────────────────────
//  TeraTerm sends the .txt bitstream file directly.
//  Each character '0' (0x30) or '1' (0x31) is one entropy bit.
//  entropy_buffer extracts bit = rx_data[0] for each received byte.
//  (0x30[0]=0, 0x31[0]=1 - LSB correctly gives the bit value)
//
//  ── Output protocol ───────────────────────────────────────
//  For each 256-bit DRBG key, output_formatter sends 64 hex
//  ASCII chars + '\n'.  TeraTerm log captures one key per line.
//
//  ── Parameters ────────────────────────────────────────────
//  TOTAL_CHUNKS : number of 275-bit entropy chunks to process.
//                 Set to floor(bitstream_length / 275).
//                 Your MATLAB numChunks value goes here.
//  BAUD_RATE    : 115200 default
//  CLOCK_FREQ   : 100_000_000 (100 MHz Spartan-7 onboard clock)
//                 Verify against your XDC constraint file.
//
//  ── Reset ─────────────────────────────────────────────────
//  rst is active-HIGH from board button (most Spartan-7 boards).
//  Internally converted to active-LOW rst_n for all submodules.
//
//  ── Ports ─────────────────────────────────────────────────
//  clk      : 100 MHz system clock (from board oscillator)
//  rst      : active-HIGH reset (push button)
//  rx       : UART RX pin (from PC)
//  tx       : UART TX pin (to PC)
//  led_busy : optional status LED - high while system is active
//  led_done : optional status LED - pulses when all chunks done
// =============================================================



module top #(
    parameter TOTAL_CHUNKS = 10,           // ← SET THIS to your numChunks value
    parameter BAUD_RATE    = 115200,
    parameter CLOCK_FREQ   = 100_000_000  // 100 MHz
)(
    input  wire clk,
    input  wire rst,       // active-HIGH board reset button
    input  wire rx,        // UART RX from PC
    output wire tx,        // UART TX to PC
    output wire led_busy,  // HIGH while processing
    output wire led_done   // HIGH after all chunks complete
);

    // ── Active-low reset for all submodules ───────────────────
    wire rst_n = ~rst;

    // ══════════════════════════════════════════════════════════
    // UART layer
    // ══════════════════════════════════════════════════════════

    wire        rx_data_valid;
    wire [7:0]  rx_data;
    wire        tx_busy;
    wire        tx_start;
    wire [7:0]  tx_data;

    uart_top #(
        .BAUD_RATE  (BAUD_RATE),
        .CLOCK_FREQ (CLOCK_FREQ)
    ) u_uart (
        .clk          (clk),
        .rst          (rst),        // uart modules use active-HIGH rst
        .tx_start     (tx_start),
        .tx_data      (tx_data),
        .rx           (rx),
        .tx           (tx),
        .rx_data_valid(rx_data_valid),
        .rx_data      (rx_data),
        .tx_busy      (tx_busy)
    );

    // ══════════════════════════════════════════════════════════
    // Entropy buffer
    // ASCII input: each received byte is one '0' or '1' char.
    // entropy_buffer extracts bit = rx_data[0] per byte.
    // sha_busy fed back to stall accumulation if SHA is running.
    // ══════════════════════════════════════════════════════════

    wire [274:0] chunk_data;
    wire         chunk_valid;
    wire         sha_busy;
    wire         all_chunks_done;

    entropy_buffer #(
        .TOTAL_CHUNKS (TOTAL_CHUNKS)
    ) u_ebuf (
        .clk            (clk),
        .rst_n          (rst_n),
        .rx_data_valid  (rx_data_valid),
        .rx_data        (rx_data),
        .chunk_data     (chunk_data),
        .chunk_valid    (chunk_valid),
        .sha_busy       (sha_busy),
        .all_chunks_done(all_chunks_done)
    );

    // ══════════════════════════════════════════════════════════
    // SHA-256
    // chunk_valid → sha256_top.start (1-cycle pulse)
    // sha256_top.digest_valid → 1-cycle pulse with 256-bit digest
    // sha_busy: reflect sha256 core busy state back to entropy_buffer
    // ══════════════════════════════════════════════════════════

    wire [255:0] sha_digest;
    wire         sha_digest_valid;
    wire         sha_start;

    // sha_start = chunk_valid (already a 1-cycle pulse from entropy_buffer)
    assign sha_start = chunk_valid;

    // sha_busy: the SHA core is busy from the cycle after start until
    // digest_valid pulses.  We infer this with a simple SR flag.
    reg sha_busy_r;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            sha_busy_r <= 1'b0;
        else if (sha_start)
            sha_busy_r <= 1'b1;
        else if (sha_digest_valid)
            sha_busy_r <= 1'b0;
    end
    assign sha_busy = sha_busy_r;

    sha256_top u_sha (
        .clk          (clk),
        .rst_n        (rst_n),
        .start        (sha_start),
        .chunk_data   (chunk_data),
        .digest       (sha_digest),
        .digest_valid (sha_digest_valid)
    );

    // ══════════════════════════════════════════════════════════
    // Seed interface
    // Bridges SHA-256 digest pulses to DRBG seed input,
    // latching if DRBG is still busy with a prior seed.
    // ══════════════════════════════════════════════════════════

    wire [255:0] drbg_seed_data;
    wire         drbg_seed_valid;
    wire         drbg_output_valid;  // also feeds back to seed_interface

    seed_interface u_seed (
        .clk          (clk),
        .rst_n        (rst_n),
        .digest_valid (sha_digest_valid),
        .digest_data  (sha_digest),
        .seed_valid   (drbg_seed_valid),
        .seed_data    (drbg_seed_data),
        .drbg_valid   (drbg_output_valid)
    );

    // ══════════════════════════════════════════════════════════
    // AES-CTR-DRBG
    // ══════════════════════════════════════════════════════════

    wire [255:0] drbg_out;

    aes_ctr_drbg_top u_drbg (
        .clk        (clk),
        .rst_n      (rst_n),
        .seed_valid (drbg_seed_valid),
        .seed_data  (drbg_seed_data),
        .drbg_valid (drbg_output_valid),
        .drbg_out   (drbg_out)
    );

    // ══════════════════════════════════════════════════════════
    // Output formatter
    // drbg_output_valid + drbg_out → 64 hex chars + '\n' → UART TX
    // ══════════════════════════════════════════════════════════

    wire formatter_busy;
    wire formatter_done;

    output_formatter u_fmt (
        .clk           (clk),
        .rst_n         (rst_n),
        .drbg_valid    (drbg_output_valid),
        .drbg_out      (drbg_out),
        .tx_start      (tx_start),
        .tx_data       (tx_data),
        .tx_busy       (tx_busy),
        .formatter_busy(formatter_busy),
        .done_pulse    (formatter_done)
    );

    // ══════════════════════════════════════════════════════════
    // Status LEDs
    // led_busy : any subsystem is active
    // led_done : all chunks processed and all output sent
    // ══════════════════════════════════════════════════════════

    // all_done latches after final formatter_done
    reg all_done_r;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            all_done_r <= 1'b0;
        else if (all_chunks_done && formatter_done)
            all_done_r <= 1'b1;
    end

    assign led_busy = sha_busy_r | formatter_busy | ~all_chunks_done;
    assign led_done = all_done_r;

endmodule