/////////////////////////////////////////////
// aes
//   Top level module with SPI interface and SPI core
/////////////////////////////////////////////

module aes (
    input  logic clk,
    input  logic sck,
    input  logic sdi,
    output logic sdo,
    input  logic load,
    output logic done
);

  logic [127:0] key, plaintext, cyphertext;

  aes_spi spi (
      sck,
      sdi,
      sdo,
      done,
      key,
      plaintext,
      cyphertext
  );
  aes_core core (
      clk,
      load,
      key,
      plaintext,
      done,
      cyphertext
  );
endmodule

/////////////////////////////////////////////
// aes_spi
//   SPI interface.  Shifts in key and plaintext
//   Captures ciphertext when done, then shifts it out
//   Tricky cases to properly change sdo on negedge clk
/////////////////////////////////////////////

module aes_spi (
    input logic sck,
    input logic sdi,
    output logic sdo,
    input logic done,
    output logic [127:0] key,
    plaintext,
    input logic [127:0] cyphertext
);

  logic sdodelayed, wasdone;
  logic [127:0] cyphertextcaptured;

  // assert load
  // apply 256 sclks to shift in key and plaintext, starting with plaintext[127]
  // then deassert load, wait until done
  // then apply 128 sclks to shift out cyphertext, starting with cyphertext[127]
  // SPI mode is equivalent to cpol = 0, cpha = 0 since data is sampled on first edge and the first
  // edge is a rising edge (clock going from low in the idle state to high).
  always_ff @(posedge sck)
    if (!wasdone) {cyphertextcaptured, plaintext, key} = {cyphertext, plaintext[126:0], key, sdi};
    else {cyphertextcaptured, plaintext, key} = {cyphertextcaptured[126:0], plaintext, key, sdi};

  // sdo should change on the negative edge of sck
  always_ff @(negedge sck) begin
    wasdone = done;
    sdodelayed = cyphertextcaptured[126];
  end

  // when done is first asserted, shift out msb before clock edge
  assign sdo = (done & !wasdone) ? cyphertext[127] : sdodelayed;
endmodule

/////////////////////////////////////////////
// aes_core
//   top level AES encryption module
//   when load is asserted, takes the current key and plaintext
//   generates cyphertext and asserts done when complete 11 cycles later
// 
//   See FIPS-197 with Nk = 4, Nb = 4, Nr = 10
//
//   The key and message are 128-bit values packed into an array of 16 bytes as
//   shown below
//        [127:120] [95:88] [63:56] [31:24]     S0,0    S0,1    S0,2    S0,3
//        [119:112] [87:80] [55:48] [23:16]     S1,0    S1,1    S1,2    S1,3
//        [111:104] [79:72] [47:40] [15:8]      S2,0    S2,1    S2,2    S2,3
//        [103:96]  [71:64] [39:32] [7:0]       S3,0    S3,1    S3,2    S3,3
//
//   Equivalently, the values are packed into four words as given
//        [127:96]  [95:64] [63:32] [31:0]      w[0]    w[1]    w[2]    w[3]
/////////////////////////////////////////////
// Define the AES state type - 4x4 array of bytes
typedef logic [7:0] aes_state_t[0:3][0:3];

module aes_core (
    input  logic         clk,
    input  logic         load,
    input  logic [127:0] key,
    input  logic [127:0] plaintext,
    output logic         done,
    output logic [127:0] cyphertext
);

  // State machine states
  typedef enum logic [2:0] {
    IDLE,
    INIT,
    ROUNDS,
    FINAL,
    COMPLETE
  } state_t;

  // Internal signals
  state_t state, next_state;
  logic [3:0] round_count;
  logic round_complete;
  aes_state_t sub_bytes_out;
  aes_state_t shift_rows_out;
  aes_state_t mix_columns_out;
  aes_state_t round_mux_out;

  // State arrays
  aes_state_t current_state;
  aes_state_t next_state_data;
  aes_state_t round_key;

  // Key expansion signals
  logic [127:0] expanded_keys[11];
  logic key_expansion_done;

  // Submodules instantiation
  KeyExpansion key_expansion (
      .clk(clk),
      .load(load),
      .key(key),
      .done(key_expansion_done),
      .round_keys(expanded_keys)
  );

  Input2State plaintext_to_state (
      .in   (plaintext),     // Changed from .input to .in
      .state(current_state)
  );

  State2Output final_output (
      .state(current_state),
      .out  (cyphertext)      // Changed from .output to .out
  );

  // Round operations
  SubBytes sub_bytes (
      .clk(clk),
      .state_in(current_state),
      .state_out(sub_bytes_out)
  );

  ShiftRows shift_rows (
      .state_in (sub_bytes_out),
      .state_out(shift_rows_out)
  );

  MixColumns mix_columns (
      .state_in (shift_rows_out),
      .state_out(mix_columns_out)
  );

  AddRoundKey add_round_key (
      .state_in (round_mux_out),
      .round_key(round_key),
      .state_out(next_state_data)
  );

  // State machine logic
  always_ff @(posedge clk) begin
    if (load) begin
      state <= INIT;
      round_count <= '0;
      done <= 1'b0;
    end else begin
      state <= next_state;
      if (state == ROUNDS) round_count <= round_count + 1;
      if (state == COMPLETE) done <= 1'b1;
      else done <= 1'b0;
    end

    current_state <= next_state_data;
  end

  // Next state logic
  always_comb begin
    next_state = state;
    case (state)
      IDLE: if (load && key_expansion_done) next_state = INIT;
      INIT: next_state = ROUNDS;
      ROUNDS: begin
        if (round_count == 9) next_state = FINAL;
      end
      FINAL: next_state = COMPLETE;
      COMPLETE: next_state = IDLE;
    endcase
  end

  // Round key selection
  always_comb begin
    round_key[0][0] = expanded_keys[int'(round_count)][127:120];
    round_key[1][0] = expanded_keys[int'(round_count)][119:112];
    round_key[2][0] = expanded_keys[int'(round_count)][111:104];
    round_key[3][0] = expanded_keys[int'(round_count)][103:96];
    round_key[0][1] = expanded_keys[int'(round_count)][95:88];
    round_key[1][1] = expanded_keys[int'(round_count)][87:80];
    round_key[2][1] = expanded_keys[int'(round_count)][79:72];
    round_key[3][1] = expanded_keys[int'(round_count)][71:64];
    round_key[0][2] = expanded_keys[int'(round_count)][63:56];
    round_key[1][2] = expanded_keys[int'(round_count)][55:48];
    round_key[2][2] = expanded_keys[int'(round_count)][47:40];
    round_key[3][2] = expanded_keys[int'(round_count)][39:32];
    round_key[0][3] = expanded_keys[int'(round_count)][31:24];
    round_key[1][3] = expanded_keys[int'(round_count)][23:16];
    round_key[2][3] = expanded_keys[int'(round_count)][15:8];
    round_key[3][3] = expanded_keys[int'(round_count)][7:0];
  end

  // Round operation mux
  always_comb begin
    case (state)
      INIT: round_mux_out = current_state;
      ROUNDS: round_mux_out = mix_columns_out;
      FINAL: round_mux_out = shift_rows_out;
      default: round_mux_out = current_state;
    endcase
  end

endmodule

/////////////////////////////////////////////
// ShiftRows
//   Shift rows in a 4x4 state array
/////////////////////////////////////////////

module ShiftRows (
    input  aes_state_t state,
    output aes_state_t shifted
);

  assign shifted[0][0] = state[0][0];
  assign shifted[0][1] = state[0][1];
  assign shifted[0][2] = state[0][2];
  assign shifted[0][3] = state[0][3];
  assign shifted[1][0] = state[1][1];
  assign shifted[1][1] = state[1][2];
  assign shifted[1][2] = state[1][3];
  assign shifted[1][3] = state[1][0];
  assign shifted[2][0] = state[2][2];
  assign shifted[2][1] = state[2][3];
  assign shifted[2][2] = state[2][0];
  assign shifted[2][3] = state[2][1];
  assign shifted[3][0] = state[3][3];
  assign shifted[3][1] = state[3][0];
  assign shifted[3][2] = state[3][1];
  assign shifted[3][3] = state[3][2];
endmodule

/////////////////////////////////////////////
// AddRoundKey
//   Add round key to a 4x4 state array
/////////////////////////////////////////////

module AddRoundKey (
    input aes_state_t state,
    input logic [127:0] roundkey,
    output aes_state_t result
);

  assign result[0][0] = state[0][0] ^ roundkey[127:120];
  assign result[0][1] = state[0][1] ^ roundkey[119:112];
  assign result[0][2] = state[0][2] ^ roundkey[111:104];
  assign result[0][3] = state[0][3] ^ roundkey[103:96];
  assign result[1][0] = state[1][0] ^ roundkey[95:88];
  assign result[1][1] = state[1][1] ^ roundkey[87:80];
  assign result[1][2] = state[1][2] ^ roundkey[79:72];
  assign result[1][3] = state[1][3] ^ roundkey[71:64];
  assign result[2][0] = state[2][0] ^ roundkey[63:56];
  assign result[2][1] = state[2][1] ^ roundkey[55:48];
  assign result[2][2] = state[2][2] ^ roundkey[47:40];
  assign result[2][3] = state[2][3] ^ roundkey[39:32];
  assign result[3][0] = state[3][0] ^ roundkey[31:24];
  assign result[3][1] = state[3][1] ^ roundkey[23:16];
  assign result[3][2] = state[3][2] ^ roundkey[15:8];
  assign result[3][3] = state[3][3] ^ roundkey[7:0];
endmodule

/////////////////////////////////////////////
// KeyExpansion
//   Generate key schedule from key
/////////////////////////////////////////////

module KeyExpansion (
    input  logic         clk,              // Clock input
    input  logic         load,             // Load signal to start key expansion
    input  logic [127:0] key,              // Original 128-bit key
    output logic [127:0] roundKeys[10:0],  // 176 bytes (10 rounds) of expanded keys
    output logic         done              // Signal indicating completion
);
  // AES Rcon for round constant
  const
  logic [31:0]
  rcon[0:9] = '{
      32'h01000000,
      32'h02000000,
      32'h04000000,
      32'h08000000,
      32'h10000000,
      32'h20000000,
      32'h40000000,
      32'h80000000,
      32'h1b000000,
      32'h36000000
  };

  // State variables
  logic [3:0] round_counter;
  logic [31:0] temp;
  logic [7:0] sbox_in, sbox_out;
  logic [1:0] byte_counter;

  // S-box instance
  sbox s1 (
      .a(sbox_in),
      .y(sbox_out)
  );

  // State machine states
  enum logic [2:0] {
    IDLE,
    ROTATE,
    SBOX,
    RCON,
    GEN_KEY,
    DONE
  } state;

  always_ff @(posedge clk) begin
    case (state)
      IDLE: begin
        if (load) begin
          roundKeys[0] <= key;
          round_counter <= 4'd1;
          byte_counter <= 2'd0;
          temp <= {key[23:16], key[15:8], key[7:0], key[31:24]};  // Initial rotate
          state <= SBOX;
          done <= 1'b0;
        end
      end

      SBOX: begin
        sbox_in <= temp[31:24];
        temp <= {temp[23:0], sbox_out};
        if (byte_counter == 2'd3) begin
          state <= RCON;
          byte_counter <= 2'd0;
        end else begin
          byte_counter <= byte_counter + 1;
        end
      end

      RCON: begin
        temp  <= temp ^ rcon[round_counter-1];
        state <= GEN_KEY;
      end

      GEN_KEY: begin
        roundKeys[round_counter][127:96] <= roundKeys[round_counter-1][127:96] ^ temp;
        roundKeys[round_counter][95:64] <= roundKeys[round_counter-1][95:64] ^ roundKeys[round_counter][127:96];
        roundKeys[round_counter][63:32] <= roundKeys[round_counter-1][63:32] ^ roundKeys[round_counter][95:64];
        roundKeys[round_counter][31:0] <= roundKeys[round_counter-1][31:0] ^ roundKeys[round_counter][63:32];

        if (round_counter == 4'd10) begin
          state <= DONE;
        end else begin
          round_counter <= round_counter + 1;
          temp <= {
            roundKeys[round_counter][23:16],
            roundKeys[round_counter][15:8],
            roundKeys[round_counter][7:0],
            roundKeys[round_counter][31:24]
          };
          state <= SBOX;
        end
      end

      DONE: begin
        done  <= 1'b1;
        state <= IDLE;
      end

      default: state <= IDLE;
    endcase
  end
endmodule

/////////////////////////////////////////////
// Input2State
//   Convert input to state
/////////////////////////////////////////////

module Input2State (
    input logic [127:0] in,  // Input bytes packed into 128-bit value
    output aes_state_t state  // Output state matrix
);

  // Map input bytes to state matrix following FIPS-197:
  // in[127:120] -> state[0][0]
  // in[119:112] -> state[1][0]
  // in[111:104] -> state[2][0]
  // in[103:96]  -> state[3][0]
  // in[95:88]   -> state[0][1]
  // etc.

  always_comb begin
    // Column 0
    state[0][0] = in[127:120];
    state[1][0] = in[119:112];
    state[2][0] = in[111:104];
    state[3][0] = in[103:96];

    // Column 1
    state[0][1] = in[95:88];
    state[1][1] = in[87:80];
    state[2][1] = in[79:72];
    state[3][1] = in[71:64];

    // Column 2
    state[0][2] = in[63:56];
    state[1][2] = in[55:48];
    state[2][2] = in[47:40];
    state[3][2] = in[39:32];

    // Column 3
    state[0][3] = in[31:24];
    state[1][3] = in[23:16];
    state[2][3] = in[15:8];
    state[3][3] = in[7:0];
  end

endmodule

/////////////////////////////////////////////
// State2Output
//   Convert state to output
/////////////////////////////////////////////

module State2Output (
    input aes_state_t state,  // Input state matrix
    output logic [127:0] out  // Output bytes packed into 128-bit value
);

  // Map state matrix to output bytes following FIPS-197 ordering:
  // state[0][0] -> out[127:120]
  // state[1][0] -> out[119:112]
  // state[2][0] -> out[111:104] 
  // state[3][0] -> out[103:96]
  // state[0][1] -> out[95:88]
  // etc.

  always_comb begin
    // Column 0
    out[127:120] = state[0][0];
    out[119:112] = state[1][0];
    out[111:104] = state[2][0];
    out[103:96] = state[3][0];

    // Column 1 
    out[95:88] = state[0][1];
    out[87:80] = state[1][1];
    out[79:72] = state[2][1];
    out[71:64] = state[3][1];

    // Column 2
    out[63:56] = state[0][2];
    out[55:48] = state[1][2];
    out[47:40] = state[2][2];
    out[39:32] = state[3][2];

    // Column 3
    out[31:24] = state[0][3];
    out[23:16] = state[1][3];
    out[15:8] = state[2][3];
    out[7:0] = state[3][3];
  end

endmodule

/////////////////////////////////////////////
// SubBytes
//   Perform byte substitution on a 4x4 state array
/////////////////////////////////////////////

module SubBytes (
    input  logic       clk,
    input  aes_state_t state_in,
    output aes_state_t state_out
);

  // Instantiate 16 sbox_sync modules (4x4 array)
  genvar i, j;
  generate
    for (i = 0; i < 4; i++) begin : rows
      for (j = 0; j < 4; j++) begin : cols
        sbox_sync sbox_inst (
            .clk(clk),
            .a  (state_in[i][j]),
            .y  (state_out[i][j])
        );
      end
    end
  endgenerate

endmodule

/////////////////////////////////////////////
// sbox
//   Infamous AES byte substitutions with magic numbers
//   Combinational version which is mapped to LUTs (logic cells)
//   Section 5.1.1, Figure 7
/////////////////////////////////////////////

module sbox (
    input  logic [7:0] a,
    output logic [7:0] y
);

  // sbox implemented as a ROM
  // This module is combinational and will be inferred using LUTs (logic cells)
  logic [7:0] sbox[0:255];

  initial $readmemh("sbox.txt", sbox);
  assign y = sbox[a];
endmodule

/////////////////////////////////////////////
// sbox
//   Infamous AES byte substitutions with magic numbers
//   Synchronous version which is mapped to embedded block RAMs (EBR)
//   Section 5.1.1, Figure 7
/////////////////////////////////////////////
module sbox_sync (
    input  logic [7:0] a,
    input   logic    clk,
    output  logic [7:0] y
);

  // sbox implemented as a ROM
  // This module is synchronous and will be inferred using BRAMs (Block RAMs)
  logic [7:0] sbox[0:255];

  initial $readmemh("sbox.txt", sbox);

  // Synchronous version
  always_ff @(posedge clk) begin
    y <= sbox[a];
  end
endmodule

/////////////////////////////////////////////
// mixcolumns
//   Even funkier action on columns
//   Section 5.1.3, Figure 9
//   Same operation performed on each of four columns
/////////////////////////////////////////////

module mixcolumns (
    input  logic [127:0] a,
    output logic [127:0] y
);

  mixcolumn mc0 (
      a[127:96],
      y[127:96]
  );
  mixcolumn mc1 (
      a[95:64],
      y[95:64]
  );
  mixcolumn mc2 (
      a[63:32],
      y[63:32]
  );
  mixcolumn mc3 (
      a[31:0],
      y[31:0]
  );
endmodule

/////////////////////////////////////////////
// mixcolumn
//   Perform Galois field operations on bytes in a column
//   See EQ(4) from E. Ahmed et al, Lightweight Mix Columns Implementation for AES, AIC09
//   for this hardware implementation
/////////////////////////////////////////////

module mixcolumn (
    input  logic [31:0] a,
    output logic [31:0] y
);

  logic [7:0] a0, a1, a2, a3, y0, y1, y2, y3, t0, t1, t2, t3, tmp;

  assign {a0, a1, a2, a3} = a;
  assign tmp = a0 ^ a1 ^ a2 ^ a3;

  galoismult gm0 (
      a0 ^ a1,
      t0
  );
  galoismult gm1 (
      a1 ^ a2,
      t1
  );
  galoismult gm2 (
      a2 ^ a3,
      t2
  );
  galoismult gm3 (
      a3 ^ a0,
      t3
  );

  assign y0 = a0 ^ tmp ^ t0;
  assign y1 = a1 ^ tmp ^ t1;
  assign y2 = a2 ^ tmp ^ t2;
  assign y3 = a3 ^ tmp ^ t3;
  assign y  = {y0, y1, y2, y3};
endmodule

/////////////////////////////////////////////
// galoismult
//   Multiply by x in GF(2^8) is a left shift
//   followed by an XOR if the result overflows
//   Uses irreducible polynomial x^8+x^4+x^3+x+1 = 00011011
/////////////////////////////////////////////

module galoismult (
    input  logic [7:0] a,
    output logic [7:0] y
);

  logic [7:0] ashift;

  assign ashift = {a[6:0], 1'b0};
  assign y = a[7] ? (ashift ^ 8'b00011011) : ashift;
endmodule
