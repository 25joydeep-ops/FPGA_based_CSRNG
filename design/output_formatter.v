// =============================================================
//  output_formatter.v
//  Serialises a 256-bit DRBG output as 64 uppercase hex ASCII
//  characters followed by newline (0x0A) over uart_tx.
//
//  ── Output format ─────────────────────────────────────────
//  Per 256-bit key: 64 hex chars + '\n' = 65 UART bytes.
//  Example: "A3F1C7D2...16B9\n"
//  Each line in TeraTerm log = one 256-bit key.
//  Directly comparable to MATLAB allHex{ch} (uppercase).
//
//  ── Nibble ordering ───────────────────────────────────────
//  drbg_out[255:252] → char 0 (MS nibble of byte 0)
//  drbg_out[251:248] → char 1 (LS nibble of byte 0)
//  ...
//  drbg_out[7:4]     → char 62
//  drbg_out[3:0]     → char 63
//  0x0A              → char 64 (newline)
//
//  ── Timing ────────────────────────────────────────────────
//  - Assert tx_start for 1 cycle per byte (when !tx_busy)
//  - done_pulse fires 1 cycle after newline tx completes
//    (i.e. after tx_busy deasserts for the final newline byte)
//  - formatter_busy held high from drbg_valid until done_pulse
//
//  ── Interface ─────────────────────────────────────────────
//  Inputs : clk, rst_n, drbg_valid, drbg_out[255:0], tx_busy
//  Outputs: tx_start, tx_data[7:0], formatter_busy, done_pulse
// =============================================================

module output_formatter (
    input  wire         clk,
    input  wire         rst_n,

    input  wire         drbg_valid,
    input  wire [255:0] drbg_out,

    output reg          tx_start,
    output reg  [7:0]   tx_data,
    input  wire         tx_busy,

    output reg          formatter_busy,
    output reg          done_pulse
);

    // ── Nibble to uppercase hex ASCII ─────────────────────────
    // 0x0-0x9 → '0'-'9' (0x30-0x39)
    // 0xA-0xF → 'A'-'F' (0x41-0x46)
    // Verification: n=0xA → 0x37+0xA=0x41='A' ✓
    //               n=0xF → 0x37+0xF=0x46='F' ✓
    //               n=0x0 → 0x30+0x0=0x30='0' ✓
    //               n=0x9 → 0x30+0x9=0x39='9' ✓
    function [7:0] to_hex;
        input [3:0] n;
        to_hex = (n < 4'd10) ? (8'h30 + {4'b0000, n})
                              : (8'h37 + {4'b0000, n});
    endfunction

    // ── Registers ─────────────────────────────────────────────
    reg [255:0] buf_reg;    // latched copy of drbg_out
    reg [6:0]   char_idx;   // 0..64 (65 total: 64 hex + 1 newline)
    reg         sending;    // high while sending hex chars + newline
    reg         wait_last;  // high while waiting for newline to finish TX

    // ── Detect falling edge of tx_busy (byte transmission done) ─
    reg tx_busy_d;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) tx_busy_d <= 1'b0;
        else        tx_busy_d <= tx_busy;
    end
    wire tx_done = tx_busy_d & ~tx_busy;  // 1-cycle pulse when byte completes

    // ── Main FSM ──────────────────────────────────────────────
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            buf_reg        <= 256'd0;
            char_idx       <= 7'd0;
            sending        <= 1'b0;
            wait_last      <= 1'b0;
            formatter_busy <= 1'b0;
            done_pulse     <= 1'b0;
            tx_start       <= 1'b0;
            tx_data        <= 8'h00;
        end

        else begin
            tx_start   <= 1'b0;  // default: deassert each cycle
            done_pulse <= 1'b0;  // default: deassert each cycle

            // ── State: WAIT_LAST ──────────────────────────────
            // Waiting for the newline byte to finish transmitting.
            // done_pulse fires on the cycle tx_busy falls for it.
            if (wait_last) begin
                if (tx_done) begin
                    wait_last      <= 1'b0;
                    formatter_busy <= 1'b0;
                    done_pulse     <= 1'b1;
                end
            end

            // ── State: IDLE - latch new DRBG output ──────────
            else if (drbg_valid && !sending) begin
                buf_reg        <= drbg_out;
                char_idx       <= 7'd0;
                sending        <= 1'b1;
                formatter_busy <= 1'b1;
            end

            // ── State: SENDING - drive one char per TX slot ──
            // Only proceed when uart_tx is free and we haven't
            // just loaded a byte this cycle (tx_start was 0).
            else if (sending && !tx_busy && !tx_start) begin

                if (char_idx < 7'd64) begin
                    // ── Hex nibble characters (0..63) ─────────
                    // char_idx even  → MS nibble of current top byte
                    //                  buf_reg[255:252]
                    // char_idx odd   → LS nibble of current top byte
                    //                  buf_reg[251:248]
                    //                  then shift buf_reg left 8 bits
                    if (char_idx[0] == 1'b0) begin
                        tx_data  <= to_hex(buf_reg[255:252]);
                        tx_start <= 1'b1;
                    end
                    else begin
                        tx_data  <= to_hex(buf_reg[251:248]);
                        tx_start <= 1'b1;
                        buf_reg  <= {buf_reg[247:0], 8'h00};  // advance to next byte
                    end
                    char_idx <= char_idx + 7'd1;
                end

                else begin
                    // ── Newline (char_idx == 64) ───────────────
                    tx_data   <= 8'h0A;
                    tx_start  <= 1'b1;
                    sending   <= 1'b0;
                    char_idx  <= 7'd0;
                    wait_last <= 1'b1;
                    // formatter_busy stays HIGH until wait_last clears
                end
            end
        end
    end

endmodule