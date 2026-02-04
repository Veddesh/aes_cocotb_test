module cocotb_iverilog_dump();
initial begin
    $dumpfile("sim_build/mkAesBlockCipher.fst");
    $dumpvars(0, mkAesBlockCipher);
end
endmodule
