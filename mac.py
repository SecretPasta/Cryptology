import hashlib
import hmac
import os

def generate_mac(padded_message):

        # generate random key
        mac_key = os.urandom(16)
        if isinstance(mac_key, str):
            mac_key = mac_key.encode('utf-8')
        if isinstance(padded_message, str):
            padded_message = padded_message.encode('utf-8')
    
        hmac_calculated = hmac.new(mac_key, padded_message, hashlib.sha256)
        return mac_key, hmac_calculated.digest()


def verify_mac(plaintext, mac, mac_key):
        if isinstance(mac_key, str):
            mac_key = mac_key.encode('utf-8')
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        hmac_calculated = hmac.new(mac_key, plaintext, hashlib.sha256)
        hmac_digest = hmac_calculated.digest()

        if hmac.compare_digest(mac, hmac_digest):
            print("MAC verification successful.")
        else:
            print("MAC verification failed.")
            
            