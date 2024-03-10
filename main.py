import random
import base64
import os
from CBC import cbc_encrypt, cbc_decrypt
from ec_elgamal import gen_keypair, ec_elgamal_encrypt, ec_elgamal_decrypt, Curve25519 as curve

# Alice Generates EC ElGamal keys
print(">>> Alice generates a pair of EC ElGamal keys")
alice_private_key, alice_public_key = gen_keypair(curve)
print(">>> Alice shares her public key with Bob")

# Bob Generates EC ElGamal keys
print(">>> Bob generates a pair of EC ElGamal keys")
bob_private_key, bob_public_key = gen_keypair(curve)
print(">>> Bob shares his public key with Alice")

# generates hex key (128 bit) and iv (64 bit) for Cast128 CBC
print(">>> Alice generates private cast128-CBC key and IV")
key = random.getrandbits(128)
iv = hex(random.getrandbits(64))[2:]

# Conceptual placeholder for encrypting the CAST128 key and IV with Bob's public key
# In reality, this step requires proper formatting of (key, iv) to be compatible with EC ElGamal encryption
print(">>> Alice encrypts cast128-CBC key and IV using EC ElGamal with Bob's public key")
# This is a conceptual step - in practice, you need to convert (key, iv) to a suitable format for encryption
# For demonstration purposes only
encrypted_key_iv = ec_elgamal_encrypt(bob_public_key, key, curve)

print(">>> Alice sends encrypted message along with encrypted key and IV to Bob")

image_path = input("Enter the path to the image: ")
with open(image_path, 'rb') as image_file:
    image_data = image_file.read()

message = base64.b64encode(image_data).decode('utf-8')
hex_key = hex(key)[2:]
cipher_text = cbc_encrypt(message, hex_key, iv)
cipher_binary_data = base64.b64decode(cipher_text)
encrypted_image_path = "encrypted_" + os.path.basename(image_path)
with open(encrypted_image_path, 'wb') as encrypted_image_file:
    encrypted_image_file.write(cipher_binary_data)

print(f"Encrypted image saved to {encrypted_image_path}")

# Conceptual placeholder for Bob decrypting the CAST128 key and IV with his private key
print(">>> Bob decrypts the CAST128 key and IV using EC ElGamal with his private key")
# In reality, this step requires converting the decrypted result back into the original (key, iv) format
# For demonstration purposes only
decrypted_key_iv = ec_elgamal_decrypt(bob_private_key, encrypted_key_iv, curve)

# Assuming decrypted_key_iv somehow gives us access to the original key and IV
# This part of the code is conceptual and needs to be adjusted according to your actual implementation
decrypted_key = hex_key  # Placeholder for the actual decrypted key
decrypted_iv = iv        # Placeholder for the actual decrypted IV

print(">>> Bob decrypts the Email")
decryptedEmail = cbc_decrypt(cipher_text, decrypted_key, decrypted_iv)
dimage_data = base64.b64decode(decryptedEmail)
decrypted_image_path = "decrypted_" + os.path.basename(image_path)
with open(decrypted_image_path, 'wb') as decrypted_image_file:
    decrypted_image_file.write(dimage_data)

print(f"Decrypted image saved to {decrypted_image_path}")
