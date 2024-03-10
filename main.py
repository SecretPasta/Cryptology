import random
from hashlib import sha256
import elgamal
import rsa
from CBC import *
import base64
import os
from ec_elgamal import gen_keypair, ec_elgamal_encrypt, ec_elgamal_decrypt, Curve25519 as curve

hash_function = sha256()
key_length = 128

# Bob Generates public and private key of RSA keys,
bit_length = 256
q = rsa.getRandomPrime(bit_length)
p = rsa.getRandomPrime(bit_length)
while p == q:
    q = rsa.getRandomPrime(bit_length)
public, private = rsa.getKeys(p, q)
print(">>> Bob generates a pair of RSA keys and shared the public key")

# Generate a pair of ELGamal keys, public and private and ElGamal sytems
print(">>> Alice generates ElGamal DS system")
alice_elgsys = elgamal.generate_system(key_length, hash_function)
alice_sig_keys = elgamal.generate_keys(alice_elgsys)
print(">>> Alice shares with Bob public key")

# generates hex key (128 bit and iv 64 bit) for Cast128 CBC
print(">>> Alice generates private cast128-CBC key and IV")
key = random.getrandbits(128)
iv = hex(random.getrandbits(64))

# Encrypt the key
encrypted_key = rsa.encrypt(str(key), public)
print(">>> Alice encrypted cast128-CBC key using RSA ")

# Use the ElGamal private key to sign the key
print(">>> Alice signs on the Key cipher-text ")
signatureOnCipher = elgamal.sign(alice_elgsys, ''.join(str(encrypted_key)), alice_sig_keys[0])
# encrypt mail
print(">>> Alice write and encrypt mail and send encrypted message")

image_path = input("Enter the path to the image: ")
# Read the image, pad it, and encrypt it
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
print("-The  Email cipherText : ", cipher_text)

print('>>> Alice shared the encrypted mail,encrypted key ,iv ,digital signature')

# verify digital signature
print('>>> Bob verify the Key')
isVerified = elgamal.verify(alice_elgsys, ''.join(str(encrypted_key)), signatureOnCipher, alice_sig_keys[1])
if not isVerified:
    print("ERROR - the message is fake ")
else:
    # decrypt key
    print(">>> Bob decrypts the CAST128 key using his private RSA key")
    decrypted_key = hex(int(rsa.decrypt(encrypted_key, private)))[2:]
    print("-The CAST128 key in Hex : ",decrypted_key)
    print(">>> Bob decrypts the Email")
    decryptedEmail = cbc_decrypt(cipher_text,decrypted_key,iv)
    dimage_data = base64.b64decode(decryptedEmail)
    decrypted_image_path = "decrypted_" + os.path.basename(image_path)
    with open(decrypted_image_path, 'wb') as decrypted_image_file:
        decrypted_image_file.write(dimage_data)
    print(f"Decrypted image saved to {decrypted_image_path}")
    print("-Decrypted email  :  " + decryptedEmail)
