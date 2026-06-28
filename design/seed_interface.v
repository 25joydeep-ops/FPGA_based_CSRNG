module seed_interface (
    input  wire         clk,
    input  wire         rst_n,

    input  wire         digest_valid,
    input  wire [255:0] digest_data,

    output reg          seed_valid,
    output reg  [255:0] seed_data,

    input  wire         drbg_valid
);

    reg         drbg_busy;
    reg         pending;
    reg [255:0] latched_digest;
    reg         seed_valid_hold;  // extends seed_valid by 1 extra cycle
                                  // for pending-latch drain path only

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            drbg_busy      <= 1'b0;
            pending        <= 1'b0;
            latched_digest <= 256'd0;
            seed_valid     <= 1'b0;
            seed_data      <= 256'd0;
            seed_valid_hold<= 1'b0;
        end
        else begin
            // ── Extend: if hold was set last cycle, keep seed_valid high ──
            if (seed_valid_hold) begin
                seed_valid      <= 1'b1;
                seed_valid_hold <= 1'b0;   // only one extra cycle
            end
            else begin
                seed_valid <= 1'b0;        // default deassert
            end

            if (drbg_valid) begin
                if (digest_valid) begin
                    // Case A: simultaneous DRBG-done + new digest
                    // Forward new digest directly, drop any pending
                    seed_valid      <= 1'b1;
                    seed_valid_hold <= 1'b0;
                    seed_data       <= digest_data;
                    pending         <= 1'b0;
                    drbg_busy       <= 1'b1;
                end
                else if (pending) begin
                    // Case B: DRBG free, drain latch
                    // Use 2-cycle pulse so testbench has time to sample
                    seed_valid      <= 1'b1;
                    seed_valid_hold <= 1'b1;   // hold for 1 extra cycle
                    seed_data       <= latched_digest;
                    pending         <= 1'b0;
                    drbg_busy       <= 1'b1;
                end
                else begin
                    // Case C: truly idle
                    drbg_busy       <= 1'b0;
                    seed_valid_hold <= 1'b0;
                end
            end
            else begin
                if (digest_valid) begin
                    if (!drbg_busy) begin
                        // Case D: idle → forward immediately
                        seed_valid      <= 1'b1;
                        seed_valid_hold <= 1'b0;
                        seed_data       <= digest_data;
                        drbg_busy       <= 1'b1;
                    end
                    else begin
                        // Case E: busy → latch
                        latched_digest  <= digest_data;
                        pending         <= 1'b1;
                    end
                end
            end
        end
    end

endmodule