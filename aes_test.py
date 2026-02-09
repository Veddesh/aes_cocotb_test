import cocotb
from cocotb.triggers import RisingEdge, ReadOnly, Timer
from cocotb.clock import Clock
from Crypto.Cipher import AES
import logging
import os

def aes_ref(key, mode, text, iv=None, nonce=None, initial_counter=0, decrypt=False):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=initial_counter)
    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)

    if decrypt:
        return cipher.decrypt(text)
    else:
        return cipher.encrypt(text)

class AESTestbench:
    def __init__(self, dut):
        self.dut = dut
        cocotb.start_soon(Clock(self.dut.CLK, 10, unit="ns").start())

    async def reset(self):
        self.dut.RST_N.value = 0
        self.dut.EN_start.value = 0
        self.dut.EN_put.value = 0
        self.dut.EN_get.value = 0
        self.dut.EN_end_of_text.value = 0
        await RisingEdge(self.dut.CLK)
        await RisingEdge(self.dut.CLK)
        self.dut.RST_N.value = 1
        await RisingEdge(self.dut.CLK)

    async def run_aes_test_flow(self, mode_code, mode_name, key, p1, text_out, iv=None, nonce=None, counter=0, decrypt=False):
        key_len_bytes = len(key)
        if key_len_bytes == 16:
            key_lenn_val = 0
        elif key_len_bytes == 24:
            key_lenn_val = 1
        elif key_len_bytes == 32:
            key_lenn_val = 2

        expected = aes_ref(key, mode_name, p1, iv=iv, nonce=nonce, initial_counter=counter, decrypt=decrypt)

        while not self.dut.RDY_start.value:
            await RisingEdge(self.dut.CLK)

        self.dut.start_key.value = int.from_bytes(key, "big")
        if iv:
            self.dut.start_iv.value = int.from_bytes(iv, "big")

        self.dut.start_intext.value = int.from_bytes(p1, "big")
        self.dut.start_mode.value = mode_code
        self.dut.start_keylenn.value = key_lenn_val
        self.dut.start_decrypt.value = 1 if decrypt else 0

        self.dut.EN_start.value = 1
        await RisingEdge(self.dut.CLK)
        self.dut.EN_start.value = 0

        while not self.dut.RDY_get.value:
            await RisingEdge(self.dut.CLK)

        self.dut.EN_get.value = 1
        await ReadOnly()

        val1 = int(self.dut.get.value)
        exp1 = int.from_bytes(expected, "big")
        nist1 = int.from_bytes(text_out, "big")
        self.dut._log.info(f"{mode_name} {'DECRYPT' if decrypt else 'ENCRYPT'} ({key_len_bytes*8}-bit) B1: Exp={hex(exp1)} Act={hex(val1)} NIST={hex(nist1)}")
        assert val1 == exp1 == nist1

        await RisingEdge(self.dut.CLK)
        self.dut.EN_get.value = 0

        while not self.dut.RDY_end_of_text.value:
            await RisingEdge(self.dut.CLK)

        self.dut.EN_end_of_text.value = 1
        await RisingEdge(self.dut.CLK)
        self.dut.EN_end_of_text.value = 0

def parse_rsp_file(filepath):
    tests = []
    current_decrypt_state = False
    key = iv = pt = ct = None
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line == "[ENCRYPT]":
                current_decrypt_state = False
                key = iv = pt = ct = None
                continue
            elif line == "[DECRYPT]":
                current_decrypt_state = True
                key = iv = pt = ct = None
                continue
            if not line or line.startswith("#") or line.startswith("COUNT"):
                continue
            if "=" in line:
                parts = line.split("=")
                setting = parts[0].strip()
                value = parts[1].strip()
                if setting == "KEY": key = value
                elif setting == "IV": iv = value
                elif setting == "PLAINTEXT": pt = value
                elif setting == "CIPHERTEXT": ct = value
                if pt is not None and ct is not None:
                    tests.append({"key": key,"pt": pt,"iv": iv,"ct": ct,"decrypt": current_decrypt_state})
                    pt = ct = None
    return tests

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "ECB", "ECBGFSbox128.rsp")))
async def test_aes_ecb_kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(0, "ECB", key, text_in, text_out, decrypt=is_decrypt)


@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "ECB", "ECBGFSbox192.rsp")))
async def test_aes_ecb_192kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(0, "ECB", key, text_in, text_out, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "ECB", "ECBGFSbox256.rsp")))
async def test_aes_ecb_256kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(0, "ECB", key, text_in, text_out, decrypt=is_decrypt)


@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "OFB", "OFBGFSbox128.rsp")))
async def test_aes_ofb_kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(3, "OFB", key, text_in, text_out, iv=iv, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "OFB", "OFBKeySbox256.rsp")))
async def test_aes_ofb_256kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(3, "OFB", key, text_in, text_out, iv=iv, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "OFB", "OFBKeySbox192.rsp")))
async def test_aes_ofb_192kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(3, "OFB", key, text_in, text_out, iv=iv, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "CBC", "CBCGFSbox128.rsp")))
async def test_aes_cbc_kat(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(1, "CBC", key, text_in, text_out, iv=iv, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "CFB", "CFB128GFSbox128.rsp")))
async def test_aes_cfb_kat_gfsbox(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(2, "CFB", key, text_in, text_out, iv=iv, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "CFB", "CFB128VarTxt128.rsp")))
async def test_aes_cfb_kat_vartxt(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(2, "CFB", key, text_in, text_out, iv=iv, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(vector = parse_rsp_file(os.path.join("vectors", "CBC", "CBCVarKey128.rsp")))
async def test_aes_cbc_kat_varkey(dut, vector):
    tb = AESTestbench(dut)
    await tb.reset()
    key = bytes.fromhex(vector["key"])
    iv = bytes.fromhex(vector["iv"])
    is_decrypt = vector["decrypt"]
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    text_out = bytes.fromhex(vector["pt"] if is_decrypt else vector["ct"])
    await tb.run_aes_test_flow(1, "CBC", key, text_in, text_out, iv=iv, decrypt=is_decrypt)
