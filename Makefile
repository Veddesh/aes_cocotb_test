
TOPLEVEL_LANG ?= verilog


SIM ?= icarus


VERILOG_SOURCES := $(PWD)/rtl/*.v


TOPLEVEL := mkAesBlockCipher


MODULE := aes_test


include $(shell cocotb-config --makefiles)/Makefile.sim

