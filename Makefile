TOPLEVEL_LANG ?= verilog
SIM ?= icarus

VERILOG_SOURCES := $(PWD)/rtl/*.v
TOPLEVEL := mkAesBlockCipher
MODULE := aes_test

COMPILE_ARGS += -g2012

include $(shell cocotb-config --makefiles)/Makefile.sim
