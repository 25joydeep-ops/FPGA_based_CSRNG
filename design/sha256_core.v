module sha256_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [511:0] padded_block,
    input  wire [255:0] H_in_flat,    // 8 x 32-bit H_in words packed MSB-first
    output reg  [255:0] digest,       // 8 x 32-bit digest words packed MSB-first
    output reg          digest_valid
);

    // ── Helper: extract H_in word i from flat bus ─────────────
    // H_in[i] = H_in_flat[255 - i*32 -: 32]

    // ── SHA-256 round constants ───────────────────────────────
    reg [31:0] K [0:63];
    initial begin
        K[ 0]=32'h428a2f98; K[ 1]=32'h71374491;
        K[ 2]=32'hb5c0fbcf; K[ 3]=32'he9b5dba5;
        K[ 4]=32'h3956c25b; K[ 5]=32'h59f111f1;
        K[ 6]=32'h923f82a4; K[ 7]=32'hab1c5ed5;
        K[ 8]=32'hd807aa98; K[ 9]=32'h12835b01;
        K[10]=32'h243185be; K[11]=32'h550c7dc3;
        K[12]=32'h72be5d74; K[13]=32'h80deb1fe;
        K[14]=32'h9bdc06a7; K[15]=32'hc19bf174;
        K[16]=32'he49b69c1; K[17]=32'hefbe4786;
        K[18]=32'h0fc19dc6; K[19]=32'h240ca1cc;
        K[20]=32'h2de92c6f; K[21]=32'h4a7484aa;
        K[22]=32'h5cb0a9dc; K[23]=32'h76f988da;
        K[24]=32'h983e5152; K[25]=32'ha831c66d;
        K[26]=32'hb00327c8; K[27]=32'hbf597fc7;
        K[28]=32'hc6e00bf3; K[29]=32'hd5a79147;
        K[30]=32'h06ca6351; K[31]=32'h14292967;
        K[32]=32'h27b70a85; K[33]=32'h2e1b2138;
        K[34]=32'h4d2c6dfc; K[35]=32'h53380d13;
        K[36]=32'h650a7354; K[37]=32'h766a0abb;
        K[38]=32'h81c2c92e; K[39]=32'h92722c85;
        K[40]=32'ha2bfe8a1; K[41]=32'ha81a664b;
        K[42]=32'hc24b8b70; K[43]=32'hc76c51a3;
        K[44]=32'hd192e819; K[45]=32'hd6990624;
        K[46]=32'hf40e3585; K[47]=32'h106aa070;
        K[48]=32'h19a4c116; K[49]=32'h1e376c08;
        K[50]=32'h2748774c; K[51]=32'h34b0bcb5;
        K[52]=32'h391c0cb3; K[53]=32'h4ed8aa4a;
        K[54]=32'h5b9cca4f; K[55]=32'h682e6ff3;
        K[56]=32'h748f82ee; K[57]=32'h78a5636f;
        K[58]=32'h84c87814; K[59]=32'h8cc70208;
        K[60]=32'h90befffa; K[61]=32'ha4506ceb;
        K[62]=32'hbef9a3f7; K[63]=32'hc67178f2;
    end

    // ── Message schedule - flat 2048-bit bus ──────────────────
    wire [2047:0] W_flat;
    sha256_schedule u_sched (
        .padded_block (padded_block),
        .W_flat       (W_flat)
    );

    // ── W[i] accessor (combinational, no storage) ─────────────
    // Use a function so W_flat[2047-i*32-:32] reads cleanly.
    // Called only with constant i inside the always block.
    // We use a wire array internally - legal inside a module.
    wire [31:0] W [0:63];
    genvar gi;
    generate
        for (gi = 0; gi < 64; gi = gi + 1) begin : w_unpack
            assign W[gi] = W_flat[2047 - gi*32 -: 32];
        end
    endgenerate

    // ── Working variables ─────────────────────────────────────
    reg [31:0] a, b, c, d, e, f, g, h_reg;
    reg [31:0] H [0:7];
    reg [6:0]  round;
    reg        busy;

    // ── Module-scope temporaries (avoids local reg in block) ──
    reg [31:0] temp1, temp2;

    // ── Compression functions ─────────────────────────────────
    function [31:0] Sigma0;
        input [31:0] x;
        Sigma0 = {x[1:0],x[31:2]} ^ {x[12:0],x[31:13]} ^ {x[21:0],x[31:22]};
    endfunction

    function [31:0] Sigma1;
        input [31:0] x;
        Sigma1 = {x[5:0],x[31:6]} ^ {x[10:0],x[31:11]} ^ {x[24:0],x[31:25]};
    endfunction

    function [31:0] Ch;
        input [31:0] e_in, f_in, g_in;
        Ch = (e_in & f_in) ^ (~e_in & g_in);
    endfunction

    function [31:0] Maj;
        input [31:0] a_in, b_in, c_in;
        Maj = (a_in & b_in) ^ (a_in & c_in) ^ (b_in & c_in);
    endfunction

    // ── Main FSM ──────────────────────────────────────────────
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy         <= 1'b0;
            digest_valid <= 1'b0;
            round        <= 7'd0;
            digest       <= 256'd0;
            a <= 0; b <= 0; c <= 0; d <= 0;
            e <= 0; f <= 0; g <= 0; h_reg <= 0;
            H[0]<=0; H[1]<=0; H[2]<=0; H[3]<=0;
            H[4]<=0; H[5]<=0; H[6]<=0; H[7]<=0;
        end

        else begin
            digest_valid <= 1'b0;

            if (start && !busy) begin
                // Load H_in from flat bus: H_in[i] at [255-i*32 -: 32]
                H[0] <= H_in_flat[255:224]; H[1] <= H_in_flat[223:192];
                H[2] <= H_in_flat[191:160]; H[3] <= H_in_flat[159:128];
                H[4] <= H_in_flat[127:96];  H[5] <= H_in_flat[95:64];
                H[6] <= H_in_flat[63:32];   H[7] <= H_in_flat[31:0];

                a     <= H_in_flat[255:224]; b <= H_in_flat[223:192];
                c     <= H_in_flat[191:160]; d <= H_in_flat[159:128];
                e     <= H_in_flat[127:96];  f <= H_in_flat[95:64];
                g     <= H_in_flat[63:32];   h_reg <= H_in_flat[31:0];

                round <= 7'd0;
                busy  <= 1'b1;
            end

            else if (busy) begin
                if (round < 7'd64) begin
                    // One compression round
                    temp1 = h_reg + Sigma1(e) + Ch(e,f,g) + K[round] + W[round];
                    temp2 = Sigma0(a) + Maj(a,b,c);

                    h_reg <= g;
                    g     <= f;
                    f     <= e;
                    e     <= d + temp1;
                    d     <= c;
                    c     <= b;
                    b     <= a;
                    a     <= temp1 + temp2;

                    round <= round + 7'd1;
                end

                else begin
                    // H update - pack result into flat digest bus
                    digest[255:224] <= H[0] + a;
                    digest[223:192] <= H[1] + b;
                    digest[191:160] <= H[2] + c;
                    digest[159:128] <= H[3] + d;
                    digest[127:96]  <= H[4] + e;
                    digest[95:64]   <= H[5] + f;
                    digest[63:32]   <= H[6] + g;
                    digest[31:0]    <= H[7] + h_reg;

                    digest_valid <= 1'b1;
                    busy         <= 1'b0;
                end
            end
        end
    end

endmodule