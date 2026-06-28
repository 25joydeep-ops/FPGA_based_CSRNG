// =============================================================
//  uart_rx.v  -  UART Receiver (corrected for architecture)
//
//  Changes from your original:
//  1. Mid-bit sampling restored: baud counter starts at
//     BAUD_COUNT/2 on start-bit detection so each data bit
//     is sampled at its centre - mandatory for reliable
//     hardware operation on the Spartan-7 board.
//  2. rx_data_valid is now a clean 1-cycle pulse: it is
//     asserted for exactly one clock cycle when a byte is
//     ready. entropy_buffer depends on this behaviour to
//     count bytes correctly without double-latching.
//  3. rx input is double-registered (rx_sync) to prevent
//     metastability - essential for any asynchronous input
//     on FPGA fabric.
//  4. Reset now also clears bit_index and shift_reg for
//     deterministic startup state.
//
//  For SIMULATION: leave BAUD_COUNT at 10 (matches uart_tx).
//  For HARDWARE:   uncomment the formula line and comment
//                  out the localparam BAUD_COUNT = 10 line.
//                  Also update CLOCK_FREQ to your board's
//                  actual clock (Spartan-7 board = 100 MHz
//                  typically - verify your constraint file).
// =============================================================

module uart_rx #(
    parameter BAUD_RATE  = 115200,
    parameter CLOCK_FREQ = 100000000   // 100 MHz for Spartan-7
)(
    input  wire       clk,
    input  wire       rst,
    input  wire       rx,
    output reg        rx_data_valid,   // 1-cycle pulse when byte ready
    output reg  [7:0] rx_data
);

    // ── Baud rate divider ─────────────────────────────────────
    // For hardware: CLOCK_FREQ / BAUD_RATE (e.g. 100M/115200 = 868)
    // For simulation: keep at 10 to match uart_tx
    localparam BAUD_COUNT = CLOCK_FREQ / BAUD_RATE;
    //localparam BAUD_COUNT = 10;

    // ── Metastability protection: double-register rx input ────
    reg rx_d1, rx_sync;
    always @(posedge clk) begin
        rx_d1  <= rx;
        rx_sync <= rx_d1;
    end

    // ── Internal registers ────────────────────────────────────
    reg [15:0] baud_counter;
    reg [3:0]  bit_index;
    reg [7:0]  shift_reg;
    reg        rx_busy;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            rx_data_valid <= 0;
            rx_busy       <= 0;
            baud_counter  <= 0;
            bit_index     <= 0;
            shift_reg     <= 0;
            rx_data       <= 0;
        end

        else begin
            rx_data_valid <= 0;   // default: deassert every cycle (1-cycle pulse)

            if (!rx_busy && !rx_sync) begin
                // ── Start bit detected ────────────────────────
                // Begin counter at BAUD_COUNT/2 so the first
                // sample lands at the centre of bit 0, and all
                // subsequent samples also hit their bit centres.
                rx_busy      <= 1;
                baud_counter <= BAUD_COUNT / 2;
                bit_index    <= 0;
            end

            else if (rx_busy) begin
                if (baud_counter < BAUD_COUNT) begin
                    baud_counter <= baud_counter + 1;
                end
                else begin
                    baud_counter <= 0;

                    if (bit_index < 8) begin
                        // ── Sample data bits 0..7 ─────────────
                        shift_reg[bit_index] <= rx_sync;
                        bit_index <= bit_index + 1;
                    end
                    else begin
                        // ── Stop bit slot - latch byte ────────
                        // bit_index == 8: this is the stop bit
                        // position. We latch the received data
                        // and pulse valid for exactly 1 cycle.
                        rx_data       <= shift_reg;
                        rx_data_valid <= 1;
                        rx_busy       <= 0;
                        bit_index     <= 0;
                        // Note: we do not verify the stop bit is
                        // actually '1'. For robustness in a later
                        // revision, add a framing error flag here.
                    end
                end
            end
        end
    end

endmodule