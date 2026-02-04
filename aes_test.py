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

async def run_aes_test_flow(dut, mode_code, mode_name, key, p1, iv=None, nonce=None, counter=0, decrypt=False):
    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())
    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0
    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)

    # Correctly passing decrypt flag to reference model
    expected = aes_ref(key, mode_name, p1, iv=iv, nonce=nonce, initial_counter=counter, decrypt=decrypt)

    while not dut.RDY_start.value:
        await RisingEdge(dut.CLK)

    dut.start_key.value = int.from_bytes(key, "big")
    if iv:
        dut.start_iv.value = int.from_bytes(iv, "big")

    dut.start_intext.value = int.from_bytes(p1, "big")
    dut.start_mode.value = mode_code
    dut.start_keylenn.value = 0
    dut.start_decrypt.value = 1 if decrypt else 0

    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0

    while not dut.RDY_get.value:
        await RisingEdge(dut.CLK)

    dut.EN_get.value = 1
    await ReadOnly()

    val1 = int(dut.get.value)
    exp1 = int.from_bytes(expected[0:16], "big")

    dut._log.info(f"{mode_name} {'DECRYPT' if decrypt else 'ENCRYPT'} B1: Exp={hex(exp1)} Act={hex(val1)}")
    assert val1 == exp1

    await RisingEdge(dut.CLK)
    dut.EN_get.value = 0

    while not dut.RDY_end_of_text.value:
        await RisingEdge(dut.CLK)

    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0

def parse_rsp_file(filepath):
    tests = []
    current_decrypt_state = False 
    with open(filepath, "r") as f:
        key, pt, ct = None, None, None
        for line in f:
            line = line.strip()
            if line == "[ENCRYPT]":
                current_decrypt_state = False
                continue
            elif line == "[DECRYPT]":
                current_decrypt_state = True
                continue
            if line.startswith("KEY ="):
                key = line.split("=")[1].strip()
            elif line.startswith("PLAINTEXT ="):
                pt = line.split("=")[1].strip()
            elif line.startswith("CIPHERTEXT ="):
                ct = line.split("=")[1].strip()
                tests.append({"key": key, "pt": pt, "ct": ct, "decrypt": current_decrypt_state})
    return tests

@cocotb.test()
@cocotb.parametrize(
    vector = parse_rsp_file(os.path.join("vectors", "ECB", "ECBGFSbox128.rsp"))
)
async def test_aes_ecb_kat(dut, vector):
    key = bytes.fromhex(vector["key"])
    is_decrypt = vector["decrypt"]
    # Logic: If we are testing Decrypt, we feed Ciphertext to the DUT
    text_in = bytes.fromhex(vector["ct"] if is_decrypt else vector["pt"])
    
    await run_aes_test_flow(dut, 0, "ECB", key, text_in, decrypt=is_decrypt)

@cocotb.test()
@cocotb.parametrize(arg1=["f34481ec3cc627bacd5dc3fb08f273e6"],
                     arg3=["00000000000000000000000000000000"])
async def test_aes_ecb(dut, arg1, arg3):
    k = bytes.fromhex(arg3)
    p1 = bytes.fromhex(arg1)
    await run_aes_test_flow(dut, 0, "ECB", k, p1)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51"],
                     arg3=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_cbc(dut, arg1, arg2, arg3):
    k = bytes.fromhex(arg1)
    iv = bytes.fromhex(arg2)
    p1 = bytes.fromhex(arg3)
    await run_aes_test_flow(dut, 1, "CBC", k, p1, iv=iv)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51"],
                     arg3=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_cfb(dut, arg1, arg2, arg3):
    k = bytes.fromhex(arg1)
    iv = bytes.fromhex(arg2)
    p1 = bytes.fromhex(arg3)
    await run_aes_test_flow(dut, 2, "CFB", k, p1, iv=iv)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51"],
                     arg3=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_ofb(dut, arg1, arg2, arg3):
    k = bytes.fromhex(arg3)
    iv = bytes.fromhex(arg2)
    p1 = bytes.fromhex(arg1)
    await run_aes_test_flow(dut, 3, "OFB", k, p1, iv=iv)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f"],
                     arg3=["f0f1f2f3f4f5f6f7"],
                     arg4=["000102030405060708090a0b0c0d0e0f"],
                     arg5=[2])
async def test_aes_ctr(dut, arg1, arg3, arg4, arg5):
    k = bytes.fromhex(arg4)
    p1 = bytes.fromhex(arg1)
    nonce = bytes.fromhex(arg3)
    cnt = arg5
    iv_hw = nonce + cnt.to_bytes(8, "big")
    await run_aes_test_flow(dut, 4, "CTR", k, p1, iv=iv_hw, nonce=nonce, counter=cnt)
