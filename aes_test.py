import cocotb
from cocotb.triggers import RisingEdge, ReadOnly, Timer
from cocotb.clock import Clock
from Crypto.Util.Padding import pad, unpad 
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes





def aes_ref(key,mode,plaintext,iv= None,nonce=None,aad= b"",initial_counter= 0):

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.encrypt(plaintext)


    elif mode == "CTR":

        cipher=AES.new(key,AES.MODE_CTR,nonce=nonce,initial_value=initial_counter)
        return cipher.encrypt(plaintext)

    elif mode == "CFB":
        cipher = AES.new(key ,AES.MODE_CFB,iv=iv)
        return cipher.encrypt(plaintext)

    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB,iv=iv)
        return cipher.encrypt(plaintext)

    else:
        logging.warning(f"Unsupported AES mode: {mode}")



def aes_ref_dec(key,mode,ciphertext,iv= None,nonce=None,aad= b"",initial_counter= 0):

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(ciphertext)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(ciphertext)


    elif mode == "CTR":

        cipher=AES.new(key,AES.MODE_CTR,nonce=nonce,initial_value=initial_counter)
        return cipher.decrypt(ciphertext)

    elif mode == "CFB":
        cipher = AES.new(key ,AES.MODE_CFB,iv=iv)
        return cipher.decrypt(ciphertext)

    elif mode == "OFB":
        cipher = AES.new(key, AES.MODE_OFB,iv=iv)
        return cipher.decrypt(ciphertext)

    else:
        logging.warning(f"Unsupported AES mode: {mode}")



@cocotb.test()
async def test_aes_ecb(dut):

    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())

    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0


    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)


    key_bytes = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block_hex = "6bc1bee22e409f96e93d7e117393172a"
    block_bytes = bytes.fromhex(block_hex)
    plaintext_refinput=block_bytes+block_bytes

    expected_block = aes_ref(key_bytes,"ECB",plaintext_refinput)



    while not dut.RDY_start.value:
        await RisingEdge(dut.CLK)

    dut.start_key.value = int.from_bytes(key_bytes, "big")
    dut.start_intext.value =int.from_bytes(block_bytes, "big")

    dut.start_mode.value = 0
    dut.start_decrypt.value = 0
    dut.start_keylenn.value = 0

    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0
    dut._log.info("Block 1 sent via EN_start")



    while not dut.RDY_put.value and dut.can_take_input.value:
        await RisingEdge(dut.CLK)

    dut.put_nxt_blk.value = int.from_bytes(block_bytes, "big")
    dut.EN_put.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_put.value = 0
    dut._log.info("Block 2 sent via EN_put")







    while not dut.RDY_end_of_text.value:
        await RisingEdge(dut.CLK)

    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0
    dut._log.info("End of Text signaled")


    actual_results = []

    for i in range(2):

        while dut.RDY_get.value == 0:
            await RisingEdge(dut.CLK)

        dut.EN_get.value = 1
        await ReadOnly()
        val = int(dut.get.value)
        actual_results.append(val)

        await RisingEdge(dut.CLK)
        dut.EN_get.value = 0
        dut._log.info(f"Retrieved Block {i+1}: {hex(val)}")


    for i in range(2):
        start_idx = i * 16
        end_idx = start_idx + 16
        ref_chunk = int.from_bytes(expected_block[start_idx:end_idx], "big")

        dut._log.info(f"Checking Block {i+1}: Exp={hex(ref_chunk)} Act={hex(actual_results[i])}")
        assert actual_results[i] == ref_chunk, f"Block {i+1} mismatch!"

    dut._log.info("SUCCESS: Both blocks encrypted correctly in ECB mode.")


@cocotb.test()
async def test_aes_cbc(dut):

    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())

    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0


    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)


    key_bytes = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block_hex = "6bc1bee22e409f96e93d7e117393172a"
    block_bytes = bytes.fromhex(block_hex)
    plaintext_refinput=block_bytes+block_bytes

    expected_block = aes_ref(key_bytes,"CBC",plaintext_refinput,iv)



    while not dut.RDY_start.value:
        await RisingEdge(dut.CLK)

    dut.start_key.value = int.from_bytes(key_bytes, "big")
    dut.start_intext.value =int.from_bytes(block_bytes, "big")
    dut.start_iv.value=int.from_bytes(iv,"big")
    dut.start_mode.value = 1
    dut.start_decrypt.value = 0
    dut.start_keylenn.value = 0

    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0
    dut._log.info("Block 1 sent via EN_start")



    while not dut.RDY_put.value and dut.can_take_input.value:
        await RisingEdge(dut.CLK)

    dut.put_nxt_blk.value = int.from_bytes(block_bytes, "big")
    dut.EN_put.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_put.value = 0
    dut._log.info("Block 2 sent via EN_put")







    while not dut.RDY_end_of_text.value:
        await RisingEdge(dut.CLK)

    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0
    dut._log.info("End of Text signaled")


    actual_results = []

    for i in range(2):

        while dut.RDY_get.value == 0:
            await RisingEdge(dut.CLK)

        dut.EN_get.value = 1
        await ReadOnly()
        val = int(dut.get.value)
        actual_results.append(val)

        await RisingEdge(dut.CLK)
        dut.EN_get.value = 0
        dut._log.info(f"Retrieved Block {i+1}: {hex(val)}")


    for i in range(2):
        start_idx = i * 16
        end_idx = start_idx + 16
        ref_chunk = int.from_bytes(expected_block[start_idx:end_idx], "big")

        dut._log.info(f"Checking Block {i+1}: Exp={hex(ref_chunk)} Act={hex(actual_results[i])}")
        assert actual_results[i] == ref_chunk, f"Block {i+1} mismatch!"

    dut._log.info("SUCCESS: Both blocks encrypted correctly in CBC mode.")











@cocotb.test()
async def test_aes_ofb(dut):

    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())

    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0


    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)


    key_bytes = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block_hex = "6bc1bee22e409f96e93d7e117393172a"
    block_bytes = bytes.fromhex(block_hex)
    plaintext_refinput=block_bytes+block_bytes

    expected_block = aes_ref(key_bytes,"OFB",plaintext_refinput,iv)



    while not dut.RDY_start.value:
        await RisingEdge(dut.CLK)

    dut.start_key.value = int.from_bytes(key_bytes, "big")
    dut.start_intext.value =int.from_bytes(block_bytes, "big")
    dut.start_iv.value=int.from_bytes(iv,"big")
    dut.start_mode.value = 3
    dut.start_decrypt.value = 0
    dut.start_keylenn.value = 0

    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0
    dut._log.info("Block 1 sent via EN_start")



    while not dut.RDY_put.value and dut.can_take_input.value:
        await RisingEdge(dut.CLK)

    dut.put_nxt_blk.value = int.from_bytes(block_bytes, "big")
    dut.EN_put.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_put.value = 0
    dut._log.info("Block 2 sent via EN_put")







    while not dut.RDY_end_of_text.value:
        await RisingEdge(dut.CLK)

    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0
    dut._log.info("End of Text signaled")


    actual_results = []

    for i in range(2):

        while dut.RDY_get.value == 0:
            await RisingEdge(dut.CLK)

        dut.EN_get.value = 1
        await ReadOnly()
        val = int(dut.get.value)
        actual_results.append(val)

        await RisingEdge(dut.CLK)
        dut.EN_get.value = 0
        dut._log.info(f"Retrieved Block {i+1}: {hex(val)}")


    for i in range(2):
        start_idx = i * 16
        end_idx = start_idx + 16
        ref_chunk = int.from_bytes(expected_block[start_idx:end_idx], "big")

        dut._log.info(f"Checking Block {i+1}: Exp={hex(ref_chunk)} Act={hex(actual_results[i])}")
        assert actual_results[i] == ref_chunk, f"Block {i+1} mismatch!"

    dut._log.info("SUCCESS: Both blocks encrypted correctly in OFB mode.")





@cocotb.test()
async def test_aes_ctr(dut):

    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())

    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0


    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)


    key_bytes = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    
    block_hex = "6bc1bee22e409f96e93d7e117393172a"
    block_bytes = bytes.fromhex(block_hex)
    plaintext_refinput=block_bytes+block_bytes

    nonce_bytes = bytes.fromhex("f0f1f2f3f4f5f6f7") 
    initial_count = 0
    
    # Construct the 128-bit IV for the hardware: [Nonce (64-bit) | Counter (64-bit)]
    # This must match how your reference model combines them internally
    iv_for_hardware = nonce_bytes + initial_count.to_bytes(8, "big")


    expected_ciphertext = aes_ref(key_bytes, "CTR",plaintext_refinput, nonce=nonce_bytes, initial_counter=initial_count)


    while not dut.RDY_start.value:
        await RisingEdge(dut.CLK)

    dut.start_key.value = int.from_bytes(key_bytes, "big")
    dut.start_intext.value =int.from_bytes(block_bytes, "big")
    dut.start_iv.value=int.from_bytes(iv_for_hardware,"big")
    dut.start_mode.value = 4
    dut.start_decrypt.value = 0
    dut.start_keylenn.value = 0

    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0
    dut._log.info("Block 1 sent via EN_start")



    while not dut.RDY_put.value and dut.can_take_input.value:
        await RisingEdge(dut.CLK)

    dut.put_nxt_blk.value = int.from_bytes(block_bytes, "big")
    dut.EN_put.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_put.value = 0
    dut._log.info("Block 2 sent via EN_put")







    while not dut.RDY_end_of_text.value:
        await RisingEdge(dut.CLK)

    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0
    dut._log.info("End of Text signaled")


    actual_results = []

    for i in range(2):

        while dut.RDY_get.value == 0:
            await RisingEdge(dut.CLK)

        dut.EN_get.value = 1
        await ReadOnly()
        val = int(dut.get.value)
        actual_results.append(val)

        await RisingEdge(dut.CLK)
        dut.EN_get.value = 0
        dut._log.info(f"Retrieved Block {i+1}: {hex(val)}")


    for i in range(2):
        start_idx = i * 16
        end_idx = start_idx + 16
        ref_chunk = int.from_bytes(expected_ciphertext[start_idx:end_idx], "big")

        dut._log.info(f"Checking Block {i+1}: Exp={hex(ref_chunk)} Act={hex(actual_results[i])}")
        assert actual_results[i] == ref_chunk, f"Block {i+1} mismatch!"

    dut._log.info("SUCCESS: Both blocks encrypted correctly in CTR mode.")
