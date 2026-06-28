// =============================================================
//  uart_top.v  -  UART Top (updated port comments only)
//
//  Your original instantiation was correct. Updated here to
//  reflect the corrected submodule behaviour:
//    - rx_data_valid is now a guaranteed 1-cycle pulse
//    - tx line idles HIGH after each transmission
//
//  This module is instantiated by top.v. It does not need to
//  know about entropy_buffer or SHA-256 - those connections
//  are made at the top level.
// =============================================================

module uart_top #(
    parameter BAUD_RATE  = 115200,
    parameter CLOCK_FREQ = 100000000
)(
    input  wire       clk,
    input  wire       rst,
    input  wire       tx_start,
    input  wire [7:0] tx_data,
    input  wire       rx,
    output wire       tx,
    output wire       rx_data_valid,   // 1-cycle pulse
    output wire [7:0] rx_data,
    output wire       tx_busy
);

    uart_tx #(
        .BAUD_RATE  (BAUD_RATE),
        .CLOCK_FREQ (CLOCK_FREQ)
    ) uart_transmitter (
        .clk      (clk),
        .rst      (rst),
        .tx_start (tx_start),
        .tx_data  (tx_data),
        .tx       (tx),
        .tx_busy  (tx_busy)
    );

    uart_rx #(
        .BAUD_RATE  (BAUD_RATE),
        .CLOCK_FREQ (CLOCK_FREQ)
    ) uart_receiver (
        .clk          (clk),
        .rst          (rst),
        .rx           (rx),
        .rx_data_valid(rx_data_valid),
        .rx_data      (rx_data)
    );

endmodule