import hashlib
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def xor_blocks(block1, block2):
    return bytes(a ^ b for a, b in zip(block1, block2))

def assign_mac_to_image(encrypted_image_path, key):
    # Read the encrypted image file
    with open(encrypted_image_path, 'rb') as file:
        ciphertext = file.read()

    # Extract the IV from the ciphertext
    iv = ciphertext[:BLOCK_SIZE]

    # Divide the ciphertext into blocks
    ciphertext_blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(ciphertext), BLOCK_SIZE)]

    # Initialize the MAC value with an initial value
    mac = bytes([0] * BLOCK_SIZE)

    # Compute the MAC using CBC mode
    for block in ciphertext_blocks:
        # XOR the current ciphertext block with the MAC value
        xored_block = xor_blocks(block, mac)

        # Encrypt the XORed block using the same encryption algorithm and key
        aes_key = hashlib.sha256(key).digest()[:BLOCK_SIZE]
        cipher = AES.new(aes_key, AES.MODE_ECB)
        mac = cipher.encrypt(pad(xored_block, 32))

    # Append the MAC value to the end of the ciphertext
    #mac_appended_ciphertext = ciphertext + mac

    #return mac_appended_ciphertext
    return mac

def verify_mac_of_image(encrypted_mac, key):
    # Read the MAC-appended image file
    #with open(mac_appended_image_path, 'rb') as file:
    #    mac_appended_ciphertext = file.read()
    mac_appended_ciphertext = encrypted_mac

    # Extract the IV from the ciphertext
    iv = mac_appended_ciphertext[:BLOCK_SIZE]

    # Extract the MAC from the ciphertext
    mac = mac_appended_ciphertext[-BLOCK_SIZE:]

    # Divide the ciphertext into blocks (excluding the MAC)
    ciphertext_blocks = [mac_appended_ciphertext[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(mac_appended_ciphertext)-BLOCK_SIZE, BLOCK_SIZE)]

    # Initialize the MAC value with the extracted MAC
    computed_mac = mac

    # Compute the MAC using CBC mode
    for block in ciphertext_blocks:
        # XOR the current ciphertext block with the computed MAC value
        xored_block = xor_blocks(block, computed_mac)

        # Encrypt the XORed block using the same encryption algorithm and key
        aes_key = hashlib.sha256(key).digest()[:BLOCK_SIZE]
        cipher = AES.new(aes_key, AES.MODE_ECB)
        computed_mac = cipher.encrypt(xored_block)

    # Compare the computed MAC with the extracted MAC
    if computed_mac == mac:
        return True
    else:
        return False