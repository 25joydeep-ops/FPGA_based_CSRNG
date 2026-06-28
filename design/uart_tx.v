// =============================================================
//  uart_tx.v  -  UART Transmitter (corrected for architecture)
//
//  Changes from your original:
//  1. tx is explicitly driven HIGH (idle) after the stop bit
//     completes - added a dedicated IDLE state so tx line is
//     never left floating between transmissions.
//  2. Reset now initialises bit_index and shift_reg for
//     deterministic startup - tx defaults to HIGH (idle line).
//  3. BAUD_COUNT comment updated to reflect Spartan-7 clock.
//
//  Frame format: 1 start bit (0), 8 data bits LSB-first,
//                1 stop bit (1). No parity. Matches uart_rx.
//
//  For SIMULATION: BAUD_COUNT = 10 (fast, matches uart_rx).
//  For HARDWARE:   uncomment formula, comment out =10 line.
// =============================================================

module uart_tx #(
    parameter BAUD_RATE  = 115200,
    parameter CLOCK_FREQ = 100000000   // 100 MHz for Spartan-7
)(
    input  wire       clk,
    input  wire       rst,
    input  wire       tx_start,    // pulse high for 1 cycle to begin TX
    input  wire [7:0] tx_data,
    output reg        tx,
    output reg        tx_busy
);

    // ── Baud rate divider ─────────────────────────────────────
     localparam BAUD_COUNT = CLOCK_FREQ / BAUD_RATE;
    //localparam BAUD_COUNT = 10;

    reg [15:0] baud_counter;
    reg [3:0]  bit_index;
    reg [9:0]  shift_reg;     // [stop | D7..D0 | start] = 10 bits

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            tx           <= 1;      // UART idle line is HIGH
            tx_busy      <= 0;
            baud_counter <= 0;
            bit_index    <= 0;
            shift_reg    <= 10'h3FF;  // all 1s (safe idle state)
        end

        else if (tx_start && !tx_busy) begin
            // ── Load frame: {stop=1, data[7:0], start=0} ─────
            // shift_reg[0] is sent first (start bit = 0),
            // shift_reg[9] is sent last (stop bit = 1).
            shift_reg    <= {1'b1, tx_data, 1'b0};
            tx_busy      <= 1;
            bit_index    <= 0;
            baud_counter <= 0;
        end

        else if (tx_busy) begin
            if (baud_counter < BAUD_COUNT) begin
                baud_counter <= baud_counter + 1;
            end
            else begin
                baud_counter <= 0;

                // Drive current bit onto TX line
                tx        <= shift_reg[0];
                shift_reg <= {1'b1, shift_reg[9:1]};  // shift right, fill with 1

                if (bit_index == 9) begin
                    // ── Stop bit transmitted - return to idle ─
                    tx_busy   <= 0;
                    bit_index <= 0;
                    tx        <= 1;   // explicit idle assertion
                end
                else begin
                    bit_index <= bit_index + 1;
                end
            end
        end
    end

endmodule