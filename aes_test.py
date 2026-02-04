import cocotb
from cocotb.triggers import RisingEdge, ReadOnly, Timer
from cocotb.clock import Clock
from Crypto.Cipher import AES
import logging

def aes_ref(key, mode, plaintext, iv=None, nonce=None, initial_counter=0):
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
    return cipher.encrypt(plaintext)

async def run_aes_test_flow(dut, mode_code, mode_name, key, p1, p2, iv=None, nonce=None, counter=0):
    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())
    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0
    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)

    expected = aes_ref(key, mode_name, p1 + p2, iv=iv, nonce=nonce, initial_counter=counter)

    while not dut.RDY_start.value: 
        await RisingEdge(dut.CLK)
    
    dut.start_key.value = int.from_bytes(key, "big")
    
    if iv: 
        dut.start_iv.value = int.from_bytes(iv, "big")
    
    dut.start_intext.value = int.from_bytes(p1, "big")
    dut.start_mode.value = mode_code
    dut.start_decrypt.value = 0
    dut.start_keylenn.value = 0
    
    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0

    while not dut.RDY_get.value: 
        await RisingEdge(dut.CLK)
    
    dut.EN_get.value = 1
    await ReadOnly()
    
    val1= int(dut.get.value)
    exp1=int.from_bytes(expected[0:16], "big")
    
    dut._log.info(f"{mode_name} B1: Exp={hex(exp1)} Act={hex(val1)}")
    assert val1 == exp1
    
    await RisingEdge(dut.CLK)
    dut.EN_get.value = 0

    while not (dut.RDY_put.value and dut.can_take_input.value): 
        await RisingEdge(dut.CLK)
    dut.put_nxt_blk.value = int.from_bytes(p2, "big")
    
    dut.EN_put.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_put.value = 0

    while not dut.RDY_get.value: 
        await RisingEdge(dut.CLK)
    
    dut.EN_get.value = 1
    await ReadOnly()
    val2= int(dut.get.value)
    exp2= int.from_bytes(expected[16:32], "big")
    dut._log.info(f"{mode_name} B2: Exp={hex(exp2)} Act={hex(val2)}")
    assert val2 == exp2
    await RisingEdge(dut.CLK)
    dut.EN_get.value = 0

    while not dut.RDY_end_of_text.value: 
        await RisingEdge(dut.CLK)
    
    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f","111102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51","112d8a571e03ac9c9eb76fac45af8e23"],
                     arg3=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_ecb(dut,arg1,arg2,arg3):
    k = bytes.fromhex(arg3)
    p1 = bytes.fromhex(arg1)
    p2 = bytes.fromhex(arg2)
    await run_aes_test_flow(dut, 0, "ECB", k, p1, p2)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f","111102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51","112d8a571e03ac9c9eb76fac45af8e23"],
                     arg3=["000102030405060708090a0b0c0d0e0f"],
                     arg4=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_cbc(dut,arg1,arg2,arg3,arg4):

    k = bytes.fromhex(arg1)
    iv = bytes.fromhex(arg2)
    p1 = bytes.fromhex(arg3)
    p2 = bytes.fromhex(arg4)
    await run_aes_test_flow(dut, 1, "CBC", k, p1, p2, iv=iv)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f","111102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51","112d8a571e03ac9c9eb76fac45af8e23"],
                     arg3=["000102030405060708090a0b0c0d0e0f"],
                     arg4=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_cfb(dut,arg1,arg2,arg3,arg4):
    k = bytes.fromhex(arg1)
    iv = bytes.fromhex(arg2)
    p1 = bytes.fromhex(arg3)
    p2 = bytes.fromhex(arg4)
    await run_aes_test_flow(dut, 2, "CFB", k, p1, p2, iv=iv)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f","111102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51","112d8a571e03ac9c9eb76fac45af8e23"],
                     arg3=["000102030405060708090a0b0c0d0e0f"],
                     arg4=["000102030405060708090a0b0c0d0e0f"])
async def test_aes_ofb(dut,arg1,arg2,arg3,arg4):
    k = bytes.fromhex(arg3)
    iv = bytes.fromhex(arg4)
    p1 = bytes.fromhex(arg1)
    p2 = bytes.fromhex(arg2)
    await run_aes_test_flow(dut, 3, "OFB", k, p1, p2, iv=iv)

@cocotb.test()
@cocotb.parametrize(arg1=["000102030405060708090a0b0c0d0e0f","111102030405060708090a0b0c0d0e0f"],
                     arg2=["ae2d8a571e03ac9c9eb76fac45af8e51","112d8a571e03ac9c9eb76fac45af8e23"],
                    arg3=["f0f1f2f3f4f5f6f7","abc1f2f3f4f5f6f7"],
                     arg4=["000102030405060708090a0b0c0d0e0f"],
                    arg5=[2])
async def test_aes_ctr(dut,arg1,arg2,arg3,arg4,arg5):
    k = bytes.fromhex(arg4)
    p1 = bytes.fromhex(arg1)
    p2 = bytes.fromhex(arg2)
    nonce = bytes.fromhex(arg3)
    cnt = arg5
    iv_hw = nonce + cnt.to_bytes(8, "big")
    await run_aes_test_flow(dut, 4, "CTR", k, p1, p2, iv=iv_hw, nonce=nonce, counter=cnt)
