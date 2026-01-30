import cocotb
from cocotb.triggers import RisingEdge, ReadOnly, Timer
from cocotb.clock import Clock





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
async def test_aes_ecb_two_blocks(dut):
    # --- 1. Clock & Reset ---
    cocotb.start_soon(Clock(dut.CLK, 10, unit="ns").start())

    dut.RST_N.value = 0
    dut.EN_start.value = 0
    dut.EN_put.value = 0
    dut.EN_get.value = 0
    dut.EN_end_of_text.value = 0
    
    await Timer(20, unit="ns")
    dut.RST_N.value = 1
    await RisingEdge(dut.CLK)

    # --- 2. Data Setup ---
    key_bytes = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    # Two identical blocks for this test
    block_hex = "6bc1bee22e409f96e93d7e117393172a"
    block_bytes = bytes.fromhex(block_hex)
    
    # We expect the same result twice because it's ECB mode
    expected_block = 0x47c58d5e21caaf840d015b7d9b910981
    expected_full = [expected_block, expected_block]

    # --- 3. SEND BLOCK 1 (Using Start) ---
    while not dut.RDY_start.value:
        await RisingEdge(dut.CLK)

    dut.start_key.value = int.from_bytes(key_bytes, "big")
    dut.start_intext.value = int.from_bytes(block_bytes, "big")
    dut.start_mode.value = 0
    dut.start_decrypt.value = 0
    dut.start_keylenn.value = 0
    
    dut.EN_start.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_start.value = 0
    dut._log.info("Block 1 sent via EN_start")

    # --- 4. SEND BLOCK 2 (Using Put) ---
    # Crucial: Wait until the core is ready to accept streaming data
    while not dut.RDY_put.value and dut.can_take_input.value:
        await RisingEdge(dut.CLK)

    dut.put_nxt_blk.value = int.from_bytes(block_bytes, "big")
    dut.EN_put.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_put.value = 0
    dut._log.info("Block 2 sent via EN_put")

    




    # --- 5. SIGNAL END OF TEXT ---
    # This tells the core to finish the last block and flush the pipeline
    while not dut.RDY_end_of_text.value:
        await RisingEdge(dut.CLK)
    
    dut.EN_end_of_text.value = 1
    await RisingEdge(dut.CLK)
    dut.EN_end_of_text.value = 0
    dut._log.info("End of Text signaled")

    # --- 6. RECEIVE DATA (Looping twice) ---
    actual_results = []
    
    for i in range(2):
        # Wait for each block to emerge from the pipeline
        while not dut.RDY_get.value:
            await RisingEdge(dut.CLK)
        
        dut.EN_get.value = 1
        await ReadOnly() # Sample while EN is high
        val = dut.get.value.to_unsigned()
        actual_results.append(val)
        
        await RisingEdge(dut.CLK)
        dut.EN_get.value = 0
        dut._log.info(f"Retrieved Block {i+1}: {hex(val)}")

    # --- 7. Final Check ---
    for i in range(2):
        assert actual_results[i] == expected_full[i], f"Block {i} mismatch!"
    
    dut._log.info("SUCCESS: Both blocks encrypted correctly in ECB mode.")
