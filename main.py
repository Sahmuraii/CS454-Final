# Main.py by Madeline Veric 
# Import Statements
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import random
import timeit

# ECB Encrypt function, takes in plaintext and key. 
def ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB) # Sets up Cipher to use by Pycrptodome.
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size)) # Encrypts plaintext
    return ciphertext # Returns Encrypted Plaintext.

# ECB Decrypt function, takes in ciphertext and key.
def ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB) # Set up Cipher to use by Pycrptodome.
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size) #Decrypts plaintext.  
    return plaintext # Returns decrypted plaintext. 

# CBC Encrypt Function, takes in plaintext, key, and iv for round 1 use.
def cbc_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # Sets up Cipher to use by Pycrptodome.
    ciphertext = b"" # Sets Ciphertext to be decoded to binary string. 
    block_size = AES.block_size # Ensures block_size is consistent with AES mode. 

    previous_block = iv # Previous_block starts at IV since no previous block avalible. 

    # For loop that goes block by block and xor's it with the previous block and encrypts it.
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]

        xor_result = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = cipher.encrypt(xor_result)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext # Returns Ciphertext. 

# CBC Decrypt function, takes in ciphertext, key, and iv for round one use. 
def cbc_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # Sets up Cipher to use by Pycrptodome.
    decrypted_text = b"" # Sets plaintext to be decoded to binary string. 
    block_size = AES.block_size # Ensures block_size is consistent with AES mode. 

    previous_block = iv # Previous_block starts at IV since no previous block avalible.

    # For loop that goes block by block and xor's it with the previous block and decrypts it.
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypted_block = cipher.decrypt(block)
        xor_result = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        decrypted_text += xor_result
        previous_block = block

    return decrypted_text # Returns plaintext back as decrypted text. 

# CFB Encryption function, takes in plaintext, key, and iv for round one use. 
def cfb_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # Sets up Cipher to use by Pycrptodome.
    ciphertext = b"" # Sets Ciphertext to be decoded to binary string. 
    block_size = AES.block_size # Ensures block_size is consistent with AES mode. 

    previous_block = iv # Previous_block starts at IV since no previous block avalible.

    # For loop that goes block by block in the message, differs from cbc in how previous block is handled.
    for i in range(0, len(plaintext), block_size):
        encrypted_block = cipher.encrypt(previous_block)
        block = plaintext[i:i+block_size]
        xor_result = bytes(a ^ b for a, b in zip(block, encrypted_block))
        ciphertext += xor_result
        previous_block = xor_result

    return ciphertext # Returns plaintext encrypted as ciphertext.

# CFB Decryption function, takes in ciphertext, key, and iv for round one use. 
def cfb_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # Sets up Cipher to use by Pycrptodome.
    decrypted_text = b"" # Sets Plaintext to be decoded to binary string. 
    block_size = AES.block_size # Ensures block_size is consistent with AES mode. 

    previous_block = iv # Previous_block starts at IV since no previous block avalible.

    # For loop that goes block by block in the message, differs from cbc in how previous block is handled.
    for i in range(0, len(ciphertext), block_size):
        encrypted_block = cipher.encrypt(previous_block)
        block = ciphertext[i:i+block_size]
        xor_result = bytes(a ^ b for a, b in zip(block, encrypted_block))
        decrypted_text += xor_result
        previous_block = block

    return decrypted_text # Returns plaintext. 

# OFB Encryption function, takes in plaintext, key, and iv for round one use. 
def ofb_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # Sets up Cipher to use by Pycrptodome.
    ciphertext = b""  # Sets Ciphertext to be decoded to binary string. 
    block_size = AES.block_size # Ensures block_size is consistent with AES mode. 

    previous_block = iv # Previous_block starts at IV since no previous block avalible.

    # For loop that goes block by block in the message, differs from cbc in how previous block is handled.
    for i in range(0, len(plaintext), block_size):
        encrypted_block = cipher.encrypt(previous_block)
        block = plaintext[i:i+block_size]
        xor_result = bytes(a ^ b for a, b in zip(block, encrypted_block))
        ciphertext += xor_result
        previous_block = encrypted_block

    return ciphertext # Returns Plaintext

# OFB decrpption Function, takes in Ciphertext, key, and iv for round one. 
def ofb_decrypt(ciphertext, key, iv):
    return ofb_encrypt(ciphertext, key, iv)  # OFB decryption is the same as encryption

# CTR Encryption, takes in plaintext, key, and nonce value. 
def ctr_encrypt(plaintext, key, nonce):
    cipher = AES.new(key, AES.MODE_ECB)  # Sets up Cipher to use by Pycrptodome.
    ciphertext = b"" # Sets Ciphertext to be decoded to binary string. 
    block_size = AES.block_size# Ensures block_size is consistent with AES mode. 

    counter = 0 # Counter used in CTR mode intalized here. 

    # For loop that goes block by block in the message, has counter blocks set to big endian.
    for i in range(0, len(plaintext), block_size):
        counter_block = nonce + counter.to_bytes(block_size // 2, byteorder='big')
        encrypted_block = cipher.encrypt(counter_block)
        block = plaintext[i:i+block_size]
        xor_result = bytes(a ^ b for a, b in zip(block, encrypted_block))
        ciphertext += xor_result
        counter += 1

    return ciphertext # Returns ciphertext. 

# CTR Decrption function taking in ciphertext, key, and nonce value. 
def ctr_decrypt(ciphertext, key, nonce):
    return ctr_encrypt(ciphertext, key, nonce)  # CTR decryption is the same as encryption

# Introduce errors in ciphertext by taking in a ciphertext. 
def introduce_error(ciphertext):
    block_size = AES.block_size # Intialize block_size to AES standard.

    # Choose a random block
    block_index = random.randint(0, len(ciphertext) // block_size - 1)
    start_index = block_index * block_size
    end_index = start_index + block_size

    # Choose a random bit within the block
    bit_index = random.randint(start_index, end_index - 1)

    # Flip the chosen bit
    modified_ciphertext = ciphertext[:bit_index] + bytes([ciphertext[bit_index] ^ 1]) + ciphertext[bit_index + 1:]

    return modified_ciphertext # Return Ciphertext with error placed. 

# Counts number of error blocks in plaintext given two different plaintexts. Returns difference between them.
def count_error_blocks_in_plaintext(plaintext1, plaintext2):
    block_size = AES.block_size # Intialize block_size to AES standard.

    # Ensure both plaintexts have the same length
    if len(plaintext1) != len(plaintext2):
        raise ValueError("Plaintexts must have the same length")

    error_count = 0 # Number of errors between plaintexts by block. 

    # Compare plaintexts block by block
    for i in range(0, len(plaintext1), block_size):
        block1 = plaintext1[i:i+block_size]
        block2 = plaintext2[i:i+block_size]

        # Check if the blocks are different
        # print("Block1: ", block1)
        # print("Block2: ", block2)
        if block1 != block2:
            error_count += 1

    return error_count # Returns errors between plaintexts.

# RSA Encrpytion function using built in RSA by Pycrptodome.
def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# RSA Decrpytion Function using built in RSA by Pycrptodome.
def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def main():
    # Key used for ECB Mode
    key = get_random_bytes(16)

    # Keys used for CBC, CFB, and OFB Modes. 
    iv_cbc = get_random_bytes(AES.block_size)
    iv_cfb = get_random_bytes(AES.block_size)
    iv_ofb = get_random_bytes(AES.block_size)

    # Nonce used for CTR Mode. 
    nonce_ctr = get_random_bytes(AES.block_size // 2)

    # Plaintext string message to encrypt, replace with what you want it to be. 
    plaintext = b"This is a multiple-block long message.  It spans multiple blocks and is already the proper size."

    print("----------------- ECB MODE -------------------")
    ecb_ciphertext = ecb_encrypt(plaintext, key)
    ecb_decrypted = ecb_decrypt(ecb_ciphertext, key)

    # Introduce errors in ECB Mode
    ecb_ciphertext_with_errors = introduce_error(ecb_ciphertext)
    ecb_decrypted_with_errors = ecb_decrypt(ecb_ciphertext_with_errors, key)

    print("ECB Ciphertext:", ecb_ciphertext.hex())
    print("ECB Decrypted:", ecb_decrypted.decode())
    print()

    print("ECB Ciphertext with Errors:", ecb_ciphertext_with_errors.hex())
    print("ECB Decrypted with Errors:", ecb_decrypted_with_errors.decode('latin1'))
    error_block_count = count_error_blocks_in_plaintext(plaintext.decode(), ecb_decrypted_with_errors.decode('latin1'))
    print("Number of blocks with errors in ECB:", error_block_count)

    # CBC Mode
    print("----------------- CBC MODE -------------------")
    cbc_ciphertext = cbc_encrypt(plaintext, key, iv_cbc)
    cbc_decrypted = cbc_decrypt(cbc_ciphertext, key, iv_cbc)

    # Introduce errors in CBC Mode
    cbc_ciphertext_with_errors = introduce_error(cbc_ciphertext)
    cbc_decrypted_with_errors = cbc_decrypt(cbc_ciphertext_with_errors, key, iv_cbc)

    print("CBC Ciphertext:", cbc_ciphertext.hex())
    print("CBC Decrypted:", cbc_decrypted.decode())
    print()

    print("CBC Ciphertext with Errors:", cbc_ciphertext_with_errors.hex())
    print("CBC Decrypted with Errors:", cbc_decrypted_with_errors.decode('latin1'))
    error_block_count = count_error_blocks_in_plaintext(plaintext.decode(), cbc_decrypted_with_errors.decode('latin1'))
    print("Number of blocks with errors in CBC:", error_block_count)
    
    # CFB Mode
    print("----------------- CFB MODE -------------------")
    cfb_ciphertext = cfb_encrypt(plaintext, key, iv_cfb)
    cfb_decrypted = cfb_decrypt(cfb_ciphertext, key, iv_cfb)

    cfb_ciphertext_with_errors = introduce_error(cfb_ciphertext)
    cfb_decrypted_with_errors = cfb_decrypt(cfb_ciphertext_with_errors, key, iv_cfb)

    print("CFB Ciphertext:", cfb_ciphertext)
    print("CFB Decrypted:", cfb_decrypted.decode())
    print()

    print("CFB Ciphertext with Errors:", cfb_ciphertext_with_errors.hex())
    print("CFB Decrypted with Errors:", cfb_decrypted_with_errors.decode('latin1'))
    error_block_count = count_error_blocks_in_plaintext(plaintext.decode(), cfb_decrypted_with_errors.decode('latin1'))
    print("Number of blocks with errors in CFB:", error_block_count)

    print("----------------- OFB MODE -------------------")
    # OFB Mode
    ofb_ciphertext = ofb_encrypt(plaintext, key, iv_ofb)
    ofb_decrypted = ofb_decrypt(ofb_ciphertext, key, iv_ofb)

    ofb_ciphertext_with_errors = introduce_error(ofb_ciphertext)
    ofb_decrypted_with_errors = ofb_decrypt(ofb_ciphertext_with_errors, key, iv_ofb)    

    print("OFB Ciphertext with Errors:", ofb_ciphertext_with_errors)
    print("OFB Ciphertext:", ofb_ciphertext)

    print("OFB Decrypted with Errors:", ofb_decrypted_with_errors.decode())
    print("OFB Decrypted:", ofb_decrypted.decode())
    error_block_count = count_error_blocks_in_plaintext(plaintext.decode(), ofb_decrypted_with_errors.decode('latin1'))
    print("Number of blocks with errors in OFB:", error_block_count)

    print("----------------- CTR MODE -------------------")
    # CTR Mode
    ctr_ciphertext = ctr_encrypt(plaintext, key, nonce_ctr)
    ctr_decrypted = ctr_decrypt(ctr_ciphertext, key, nonce_ctr)
    print()

    ctr_ciphertext_with_errors = introduce_error(ctr_ciphertext)
    ctr_decrypted_with_errors = ctr_decrypt(ctr_ciphertext_with_errors, key, nonce_ctr)    

    print("CTR Ciphertext with Errors:", ctr_ciphertext_with_errors)
    print("CTR Ciphertext:", ctr_ciphertext)

    print("CTR Decrypted with Errors:", ctr_decrypted_with_errors.decode())
    print("CTR Decrypted:", ctr_decrypted.decode())
    error_block_count = count_error_blocks_in_plaintext(plaintext.decode(), ctr_decrypted_with_errors.decode('latin1'))
    print("Number of blocks with errors in CTR:", error_block_count)


    # Time AES Encryption

    print("----------------- TIME TRIALS -------------------")

    key = RSA.generate(2048)

    # Generate AES key
    aes_key = get_random_bytes(16)

    plaintext = b"This is a multiple-block long message.  It spans multiple blocks and is already the proper size."

    aes_encryption_time = timeit.timeit(lambda: ecb_encrypt(plaintext, aes_key), number=1000)
    print("AES Encryption Time:", aes_encryption_time)

    # Time AES Decryption
    aes_ciphertext = ecb_encrypt(plaintext, aes_key)
    aes_decryption_time = timeit.timeit(lambda: ecb_decrypt(aes_ciphertext, aes_key), number=1000)
    print("AES Decryption Time:", aes_decryption_time)

    # Time RSA Encryption
    rsa_encryption_time = timeit.timeit(lambda: rsa_encrypt(plaintext, key.publickey()), number=1000)
    print("RSA Encryption Time:", rsa_encryption_time)

    # Time RSA Decryption
    rsa_ciphertext = rsa_encrypt(plaintext, key.publickey())
    rsa_decryption_time = timeit.timeit(lambda: rsa_decrypt(rsa_ciphertext, key), number=1000)
    print("RSA Decryption Time:", rsa_decryption_time)

if __name__ == "__main__":
    main()
