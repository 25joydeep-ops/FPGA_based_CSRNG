// =============================================================
//  entropy_buffer.v  (ASCII input version)
//  Accumulates ASCII entropy bytes from uart_rx into 275-bit
//  chunks and presents each chunk to sha256_top.
//
//  ── ASCII input protocol ──────────────────────────────────
//  TeraTerm "Send File" transmits your bitstream .txt file as
//  a stream of ASCII characters:
//    '0' = 0x30  →  entropy bit 0
//    '1' = 0x31  →  entropy bit 1
//  This module extracts: bit = rx_data[0]  (LSB of 0x30 = 0,
//                                           LSB of 0x31 = 1)
//  One UART byte = one entropy bit.
//
//  ── Chunk geometry ────────────────────────────────────────
//  275 ASCII bytes received → 275 bits extracted → chunk_data
//  Matches your MATLAB chunkBits = 275 exactly.
//  Bit ordering: first received bit → chunk_data[274] (MSB)
//                last  received bit → chunk_data[0]   (LSB)
//
//  ── Interface ─────────────────────────────────────────────
//  From uart_rx : rx_data_valid (1-cycle pulse), rx_data [7:0]
//  To sha256_top: chunk_data [274:0], chunk_valid (1-cycle)
//  From sha256  : sha_busy - stalls accumulation while SHA runs
//  Status       : all_chunks_done (latches after last chunk)
//
//  ── Parameters ────────────────────────────────────────────
//  TOTAL_CHUNKS : set equal to floor(bitstream_length / 275)
//                 same value as MATLAB numChunks
// =============================================================

module entropy_buffer #(
    parameter TOTAL_CHUNKS = 1
)(
    input  wire         clk,
    input  wire         rst_n,

    // From uart_rx
    input  wire         rx_data_valid,
    input  wire [7:0]   rx_data,

    // To sha256_top
    output reg  [274:0] chunk_data,
    output reg          chunk_valid,
    input  wire         sha_busy,

    // Status
    output reg          all_chunks_done
);

    // ── Bit accumulation buffer ───────────────────────────────
    // 275-bit shift register filled MSB-first.
    // bit_count tracks how many bits have been accumulated.
    reg [274:0] bit_buffer;
    reg [8:0]   bit_count;    // 0 to 275

    // ── Chunk counter ─────────────────────────────────────────
    reg [$clog2(TOTAL_CHUNKS+1)-1:0] chunks_done;

    // ── FSM ───────────────────────────────────────────────────
    localparam IDLE        = 2'd0;
    localparam ACCUMULATE  = 2'd1;
    localparam CHUNK_READY = 2'd2;
    localparam DONE        = 2'd3;

    reg [1:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            bit_buffer      <= 275'd0;
            bit_count       <= 9'd0;
            chunk_data      <= 275'd0;
            chunk_valid     <= 1'b0;
            chunks_done     <= 0;
            all_chunks_done <= 1'b0;
            state           <= IDLE;
        end

        else begin
            chunk_valid <= 1'b0;  // default: 1-cycle pulse only

            case (state)

                // ── IDLE: reset buffer, wait for first byte ───
                IDLE: begin
                    bit_buffer <= 275'd0;
                    bit_count  <= 9'd0;
                    if (rx_data_valid && !sha_busy)begin
                        bit_buffer <= {274'd0, rx_data[0]};
                        bit_count  <= 9'd1;
                        state      <= ACCUMULATE;
                    end
                end

                // ── ACCUMULATE: one ASCII byte = one bit ──────
                ACCUMULATE: begin
                    if (rx_data_valid && !sha_busy) begin
                        // Extract entropy bit from LSB of ASCII char.
                        // '0'=0x30: [0]=0  '1'=0x31: [0]=1
                        // Shift buffer left, insert new bit at LSB.
                        // This builds the chunk MSB-first:
                        //   first received bit ends up at chunk_data[274]
                        bit_buffer <= {bit_buffer[273:0], rx_data[0]};
                        bit_count  <=  bit_count+9'd1;

                        if(bit_count==9'd274)
                            state <= CHUNK_READY;
                        
                    end
                end

                // ── CHUNK_READY: wait for SHA free, then pulse ─
                CHUNK_READY: begin
                    if (!sha_busy) begin
                        // Latch final buffer into chunk_data output.
                        // bit_buffer now contains 275 bits MSB-first
                        // from the last shift - but bit_count was
                        // incremented to 275 on the previous cycle,
                        // so bit_buffer[274:0] holds bits 0-274 with
                        // bit 274 = first received, bit 0 = last received.
                        // This matches sha256_top's expected ordering.
                        chunk_data  <= bit_buffer;
                        chunk_valid <= 1'b1;
                        chunks_done <= chunks_done + 1;

                        // Reset for next chunk
                        bit_buffer <= 275'd0;
                        bit_count  <= 9'd0;

                        if (chunks_done + 1 >= TOTAL_CHUNKS) begin
                            all_chunks_done <= 1'b1;
                            state           <= DONE;
                        end
                        else begin
                            state <= IDLE;
                        end
                    end
                    // If sha_busy, hold here and retry next cycle
                end

                // ── DONE: all chunks processed ────────────────
                DONE: begin
                    chunk_valid     <= 1'b0;
                    all_chunks_done <= 1'b1;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule