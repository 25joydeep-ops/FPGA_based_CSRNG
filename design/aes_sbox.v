// =============================================================
//  aes_sbox.v
//  AES SubBytes S-Box - combinational lookup table.
//
//  Identical byte-for-byte to the aes_sbox() array in AES.m.
//  Used by both key_expansion and aes_rounds.
//
//  Port:
//    in  [7:0]  : input byte
//    out [7:0]  : substituted byte  (S[in])
// =============================================================

module aes_sbox (
    input  wire [7:0] in,
    output wire [7:0] out
);

    reg [7:0] S [0:255];

    initial begin
        // Row 0x00
        S[8'h00]=8'h63; S[8'h01]=8'h7c; S[8'h02]=8'h77; S[8'h03]=8'h7b;
        S[8'h04]=8'hf2; S[8'h05]=8'h6b; S[8'h06]=8'h6f; S[8'h07]=8'hc5;
        S[8'h08]=8'h30; S[8'h09]=8'h01; S[8'h0a]=8'h67; S[8'h0b]=8'h2b;
        S[8'h0c]=8'hfe; S[8'h0d]=8'hd7; S[8'h0e]=8'hab; S[8'h0f]=8'h76;
        // Row 0x10
        S[8'h10]=8'hca; S[8'h11]=8'h82; S[8'h12]=8'hc9; S[8'h13]=8'h7d;
        S[8'h14]=8'hfa; S[8'h15]=8'h59; S[8'h16]=8'h47; S[8'h17]=8'hf0;
        S[8'h18]=8'had; S[8'h19]=8'hd4; S[8'h1a]=8'ha2; S[8'h1b]=8'haf;
        S[8'h1c]=8'h9c; S[8'h1d]=8'ha4; S[8'h1e]=8'h72; S[8'h1f]=8'hc0;
        // Row 0x20
        S[8'h20]=8'hb7; S[8'h21]=8'hfd; S[8'h22]=8'h93; S[8'h23]=8'h26;
        S[8'h24]=8'h36; S[8'h25]=8'h3f; S[8'h26]=8'hf7; S[8'h27]=8'hcc;
        S[8'h28]=8'h34; S[8'h29]=8'ha5; S[8'h2a]=8'he5; S[8'h2b]=8'hf1;
        S[8'h2c]=8'h71; S[8'h2d]=8'hd8; S[8'h2e]=8'h31; S[8'h2f]=8'h15;
        // Row 0x30
        S[8'h30]=8'h04; S[8'h31]=8'hc7; S[8'h32]=8'h23; S[8'h33]=8'hc3;
        S[8'h34]=8'h18; S[8'h35]=8'h96; S[8'h36]=8'h05; S[8'h37]=8'h9a;
        S[8'h38]=8'h07; S[8'h39]=8'h12; S[8'h3a]=8'h80; S[8'h3b]=8'he2;
        S[8'h3c]=8'heb; S[8'h3d]=8'h27; S[8'h3e]=8'hb2; S[8'h3f]=8'h75;
        // Row 0x40
        S[8'h40]=8'h09; S[8'h41]=8'h83; S[8'h42]=8'h2c; S[8'h43]=8'h1a;
        S[8'h44]=8'h1b; S[8'h45]=8'h6e; S[8'h46]=8'h5a; S[8'h47]=8'ha0;
        S[8'h48]=8'h52; S[8'h49]=8'h3b; S[8'h4a]=8'hd6; S[8'h4b]=8'hb3;
        S[8'h4c]=8'h29; S[8'h4d]=8'he3; S[8'h4e]=8'h2f; S[8'h4f]=8'h84;
        // Row 0x50
        S[8'h50]=8'h53; S[8'h51]=8'hd1; S[8'h52]=8'h00; S[8'h53]=8'hed;
        S[8'h54]=8'h20; S[8'h55]=8'hfc; S[8'h56]=8'hb1; S[8'h57]=8'h5b;
        S[8'h58]=8'h6a; S[8'h59]=8'hcb; S[8'h5a]=8'hbe; S[8'h5b]=8'h39;
        S[8'h5c]=8'h4a; S[8'h5d]=8'h4c; S[8'h5e]=8'h58; S[8'h5f]=8'hcf;
        // Row 0x60
        S[8'h60]=8'hd0; S[8'h61]=8'hef; S[8'h62]=8'haa; S[8'h63]=8'hfb;
        S[8'h64]=8'h43; S[8'h65]=8'h4d; S[8'h66]=8'h33; S[8'h67]=8'h85;
        S[8'h68]=8'h45; S[8'h69]=8'hf9; S[8'h6a]=8'h02; S[8'h6b]=8'h7f;
        S[8'h6c]=8'h50; S[8'h6d]=8'h3c; S[8'h6e]=8'h9f; S[8'h6f]=8'ha8;
        // Row 0x70
        S[8'h70]=8'h51; S[8'h71]=8'ha3; S[8'h72]=8'h40; S[8'h73]=8'h8f;
        S[8'h74]=8'h92; S[8'h75]=8'h9d; S[8'h76]=8'h38; S[8'h77]=8'hf5;
        S[8'h78]=8'hbc; S[8'h79]=8'hb6; S[8'h7a]=8'hda; S[8'h7b]=8'h21;
        S[8'h7c]=8'h10; S[8'h7d]=8'hff; S[8'h7e]=8'hf3; S[8'h7f]=8'hd2;
        // Row 0x80
        S[8'h80]=8'hcd; S[8'h81]=8'h0c; S[8'h82]=8'h13; S[8'h83]=8'hec;
        S[8'h84]=8'h5f; S[8'h85]=8'h97; S[8'h86]=8'h44; S[8'h87]=8'h17;
        S[8'h88]=8'hc4; S[8'h89]=8'ha7; S[8'h8a]=8'h7e; S[8'h8b]=8'h3d;
        S[8'h8c]=8'h64; S[8'h8d]=8'h5d; S[8'h8e]=8'h19; S[8'h8f]=8'h73;
        // Row 0x90
        S[8'h90]=8'h60; S[8'h91]=8'h81; S[8'h92]=8'h4f; S[8'h93]=8'hdc;
        S[8'h94]=8'h22; S[8'h95]=8'h2a; S[8'h96]=8'h90; S[8'h97]=8'h88;
        S[8'h98]=8'h46; S[8'h99]=8'hee; S[8'h9a]=8'hb8; S[8'h9b]=8'h14;
        S[8'h9c]=8'hde; S[8'h9d]=8'h5e; S[8'h9e]=8'h0b; S[8'h9f]=8'hdb;
        // Row 0xa0
        S[8'ha0]=8'he0; S[8'ha1]=8'h32; S[8'ha2]=8'h3a; S[8'ha3]=8'h0a;
        S[8'ha4]=8'h49; S[8'ha5]=8'h06; S[8'ha6]=8'h24; S[8'ha7]=8'h5c;
        S[8'ha8]=8'hc2; S[8'ha9]=8'hd3; S[8'haa]=8'hac; S[8'hab]=8'h62;
        S[8'hac]=8'h91; S[8'had]=8'h95; S[8'hae]=8'he4; S[8'haf]=8'h79;
        // Row 0xb0
        S[8'hb0]=8'he7; S[8'hb1]=8'hc8; S[8'hb2]=8'h37; S[8'hb3]=8'h6d;
        S[8'hb4]=8'h8d; S[8'hb5]=8'hd5; S[8'hb6]=8'h4e; S[8'hb7]=8'ha9;
        S[8'hb8]=8'h6c; S[8'hb9]=8'h56; S[8'hba]=8'hf4; S[8'hbb]=8'hea;
        S[8'hbc]=8'h65; S[8'hbd]=8'h7a; S[8'hbe]=8'hae; S[8'hbf]=8'h08;
        // Row 0xc0
        S[8'hc0]=8'hba; S[8'hc1]=8'h78; S[8'hc2]=8'h25; S[8'hc3]=8'h2e;
        S[8'hc4]=8'h1c; S[8'hc5]=8'ha6; S[8'hc6]=8'hb4; S[8'hc7]=8'hc6;
        S[8'hc8]=8'he8; S[8'hc9]=8'hdd; S[8'hca]=8'h74; S[8'hcb]=8'h1f;
        S[8'hcc]=8'h4b; S[8'hcd]=8'hbd; S[8'hce]=8'h8b; S[8'hcf]=8'h8a;
        // Row 0xd0
        S[8'hd0]=8'h70; S[8'hd1]=8'h3e; S[8'hd2]=8'hb5; S[8'hd3]=8'h66;
        S[8'hd4]=8'h48; S[8'hd5]=8'h03; S[8'hd6]=8'hf6; S[8'hd7]=8'h0e;
        S[8'hd8]=8'h61; S[8'hd9]=8'h35; S[8'hda]=8'h57; S[8'hdb]=8'hb9;
        S[8'hdc]=8'h86; S[8'hdd]=8'hc1; S[8'hde]=8'h1d; S[8'hdf]=8'h9e;
        // Row 0xe0
        S[8'he0]=8'he1; S[8'he1]=8'hf8; S[8'he2]=8'h98; S[8'he3]=8'h11;
        S[8'he4]=8'h69; S[8'he5]=8'hd9; S[8'he6]=8'h8e; S[8'he7]=8'h94;
        S[8'he8]=8'h9b; S[8'he9]=8'h1e; S[8'hea]=8'h87; S[8'heb]=8'he9;
        S[8'hec]=8'hce; S[8'hed]=8'h55; S[8'hee]=8'h28; S[8'hef]=8'hdf;
        // Row 0xf0
        S[8'hf0]=8'h8c; S[8'hf1]=8'ha1; S[8'hf2]=8'h89; S[8'hf3]=8'h0d;
        S[8'hf4]=8'hbf; S[8'hf5]=8'he6; S[8'hf6]=8'h42; S[8'hf7]=8'h68;
        S[8'hf8]=8'h41; S[8'hf9]=8'h99; S[8'hfa]=8'h2d; S[8'hfb]=8'h0f;
        S[8'hfc]=8'hb0; S[8'hfd]=8'h54; S[8'hfe]=8'hbb; S[8'hff]=8'h16;
    end

    assign out = S[in];

endmodule