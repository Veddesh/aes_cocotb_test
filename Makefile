TOPLEVEL_LANG ?= verilog
SIM ?= icarus


VERILOG_SOURCES := $(PWD)/rtl/*.v
TOPLEVEL := mkAesBlockCipher
MODULE := aes_test
WAVES = 1
include $(shell cocotb-config --makefiles)/Makefile.sim
