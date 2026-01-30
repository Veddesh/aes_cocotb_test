// Copyright (c) 2000-2011 Bluespec, Inc.

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

`ifdef sram
  module bram_1rw(
               clka,
               ena,
               wea, //wea-1/WRITE, wea-0/READ
               addra,
               dina,
               douta
                  `ifdef sram_pwr_pins
               ,vdd,
               vss
                  `endif
               );
  
    parameter                      ADDR_WIDTH = 1;
    parameter                      DATA_WIDTH = 1;
    parameter                      MEMSIZE    = 1;
    parameter                      NAME       = "ITag_0";

    input                          clka;
    input                          ena;
    input                          wea;
   `ifdef sram_pwr_pins
    input                          vdd;
    input                          vss;
   `endif
    input [ADDR_WIDTH-1:0]         addra;
    input [DATA_WIDTH-1:0]         dina;
    output [DATA_WIDTH-1:0]        douta;

    if (DATA_WIDTH == 256) begin : Data_width_256
      TS1N28HPCPUHDSVTB64X256M1SB `ifdef sram_debug #(.NAME(NAME)) `endif 
                                   t0 (.CLK(clka),
                                      .CEB(!ena),   //Active low- CHIP ENABLE
                                      .WEB(!wea),   //WEB-1/READ. WEB-0/WRITE
                                      .CEBM(1'b1),  //Chip enable BIST mode - Active low.
                                      .WEBM(1'b1),  //Write enable BIST mode - Active low
                                      .A(addra),
                                      .D(dina),
                                      .AM(6'b0),       //Address inp for BIST
                                      .DM(256'b0),       //Data input for BIST
                                      .BIST(1'b0),     //BIST interface enable
                                      //Timing adjustment for debugging
                                      //purposes. Not used now.
                                      .RTSEL(2'b01), .WTSEL(2'b00),
                                      .Q(douta)//Output data
                                       `ifdef sram_pwr_pins
                                      ,.VDD(vdd),
                                      .VSS(vss)
                                       `endif
                                    );
    end

    if (DATA_WIDTH == 20) begin : Data_width_20
      TS1N28HPCPUHDSVTB64X20M1SB `ifdef sram_debug #(.NAME(NAME)) `endif 
                                   t1(.CLK(clka),
                                      .CEB(!ena),   //Active low- CHIP ENABLE
                                      .WEB(!wea),   //WEB-1/READ. WEB-0/WRITE
                                      .CEBM(1'b1),  //Chip enable BIST mode - Active low.
                                      .WEBM(1'b1),  //Write enable BIST mode - Active low
                                      .A(addra),
                                      .D(dina),
                                      .AM(6'b0),       //Address inp for BIST
                                      .DM(20'b0),       //Data input for BIST
                                      .BIST(1'b0),     //BIST interface enable
                                      //Timing adjustment for debugging
                                      //purposes. Not used now.
                                      .RTSEL(2'b01), .WTSEL(2'b00),
                                      .Q(douta)     //Output data
                                       `ifdef sram_pwr_pins
                                      ,.VDD(vdd),
                                      .VSS(vss)
                                       `endif
                                    );

    end


  endmodule


`else
module bram_1rw(
             clka,
             ena,
             wea,
             addra,
             dina,
             douta
             );

   parameter                      ADDR_WIDTH = 1;
   parameter                      DATA_WIDTH = 1;
   parameter                      MEMSIZE    = 1;
   parameter                      NAME       = "ITag_0";

   input                          clka;
   input                          ena;
   input                          wea;
   input [ADDR_WIDTH-1:0]         addra;
   input [DATA_WIDTH-1:0]         dina;
   output [DATA_WIDTH-1:0]        douta;

   (* RAM_STYLE = "BLOCK" *)
   reg [DATA_WIDTH-1:0]           ram[0:MEMSIZE-1];
   reg [DATA_WIDTH-1:0]           out_reg;

   // synopsys translate_off
   integer                        i;
   initial
   begin : init_block
      for (i = 0; i < MEMSIZE; i = i + 1) begin
         ram[i] = { ((DATA_WIDTH+1)/2) { 2'b10 } };
      end
      out_reg  = { ((DATA_WIDTH+1)/2) { 2'b10 } };
   end
   // synopsys translate_on

   always @(posedge clka) begin
      if (ena) begin
         if (wea) begin
            ram[addra] <= dina;
         end
         else begin
            out_reg <= ram[addra];
         end
      end
   end

   // Output driver
   assign douta=out_reg;

endmodule
`endif
