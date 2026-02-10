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

    async def reset(self):
        cocotb.start_soon(Clock(self.dut.CLK, 10, unit="ns").start())
        self.dut.RST_N.value = 0
        self.dut.EN_start.value = 0
        self.dut.EN_put.value = 0
        self.dut.EN_get.value = 0
        self.dut.EN_end_of_text.value = 0
        
        await RisingEdge(self.dut.CLK)
        await RisingEdge(self.dut.CLK)
        
        self.dut.RST_N.value = 1
        await RisingEdge(self.dut.CLK)
        self.dut._log.info("Reset complete.")

    async def run_aes_test_flow(self, mode_code, mode_name, key, text_in, text_out=None, iv=None, nonce=None, counter=0, decrypt=False):
        cocotb.start_soon(Clock(self.dut.CLK, 10, unit="ns").start())
        key_len_bytes = len(key)
        if key_len_bytes == 16:
            key_lenn_val = 0
        elif key_len_bytes == 24:
            key_lenn_val = 1
        elif key_len_bytes == 32:
            key_lenn_val = 2

        expected_full = aes_ref(key, mode_name, text_in, iv=iv, nonce=nonce, initial_counter=counter, decrypt=decrypt)

        input_blocks = [text_in[i:i+16] for i in range(0, len(text_in), 16)]
        ref_blocks = [expected_full[i:i+16] for i in range(0, len(expected_full), 16)]
        
        nist_blocks = None
        if text_out:
            nist_blocks = [text_out[i:i+16] for i in range(0, len(text_out), 16)]

        for i in range(len(input_blocks)):
            if i == 0:
                while not self.dut.RDY_start.value:
                    await RisingEdge(self.dut.CLK)

                self.dut.start_key.value = int.from_bytes(key, "big")
                if iv: self.dut.start_iv.value = int.from_bytes(iv, "big")
                self.dut.start_intext.value = int.from_bytes(input_blocks[i], "big")
                self.dut.start_mode.value = mode_code
                self.dut.start_keylenn.value = key_lenn_val
                self.dut.start_decrypt.value = 1 if decrypt else 0

                self.dut.EN_start.value = 1
                await RisingEdge(self.dut.CLK)
                self.dut.EN_start.value = 0
            else:
                while not self.dut.RDY_put.value:
                    await RisingEdge(self.dut.CLK)

                self.dut.put_nxt_blk.value = int.from_bytes(input_blocks[i], "big")
                self.dut.EN_put.value = 1
                await RisingEdge(self.dut.CLK)
                self.dut.EN_put.value = 0

            while not self.dut.RDY_get.value:
                await RisingEdge(self.dut.CLK)

            self.dut.EN_get.value = 1
            await ReadOnly()

            val_dut = int(self.dut.get.value)
            val_ref = int.from_bytes(ref_blocks[i], "big")

            if nist_blocks:
                val_nist = int.from_bytes(nist_blocks[i], "big")
                self.dut._log.info(f"TRIPLE CHECK Block {i}: DUT={hex(val_dut)} REF={hex(val_ref)} NIST={hex(val_nist)}")
                assert val_dut == val_ref == val_nist, f"Mismatch at block {i}"
            else:
                self.dut._log.info(f"DOUBLE CHECK Block {i}: DUT={hex(val_dut)} REF={hex(val_ref)}")
                assert val_dut == val_ref, f"Mismatch at block {i}"

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


@cocotb.test()
async def test_aes_cbc_2blocks(dut):
    tb = AESTestbench(dut)
    await tb.reset()

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    

    await tb.run_aes_test_flow(mode_code=1, mode_name="CBC", key=key, text_in=pt, iv=iv, decrypt=False)
