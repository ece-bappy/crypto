import os
import time
import hashlib
from Crypto.Cipher import DES3, AES
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from sympy import nextprime
from matplotlib import pyplot as plt
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Key containing required number
base_key = "0424312039"

# Key expansion functions
def expand_key(key, length):
    return hashlib.sha256(key.encode()).digest()[:length]

# File operations
def read_file(filepath):
    with open(filepath, 'rb') as f:
        return f.read()

def write_file(filepath, data):
    with open(filepath, 'wb') as f:
        f.write(data)

# 3DES encryption/decryption
def des3_encrypt_decrypt(data, key):
    key = expand_key(key, 24)  # 192-bit key
    cipher = DES3.new(key, DES3.MODE_CBC)
    start = time.time()
    enc_data = cipher.encrypt(pad(data, DES3.block_size))
    enc_time = time.time() - start

    start = time.time()
    dec_data = unpad(DES3.new(key, DES3.MODE_CBC, cipher.iv).decrypt(enc_data), DES3.block_size)
    dec_time = time.time() - start
    return enc_data, dec_data, enc_time, dec_time

# AES encryption/decryption
def aes_encrypt_decrypt(data, key):
    key = expand_key(key, 32)  # 256-bit key
    cipher = AES.new(key, AES.MODE_CBC)
    start = time.time()
    enc_data = cipher.encrypt(pad(data, AES.block_size))
    enc_time = time.time() - start

    start = time.time()
    dec_data = unpad(AES.new(key, AES.MODE_CBC, cipher.iv).decrypt(enc_data), AES.block_size)
    dec_time = time.time() - start
    return enc_data, dec_data, enc_time, dec_time


def ecc_encrypt_decrypt(data, key):
    # Generate ECC keys
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()

    # Encrypt a symmetric key using ECC
    symmetric_key = get_random_bytes(32)  # AES-256 key
    shared_secret = public_key.pointQ * private_key.d
    derived_key = hashlib.sha256(int(shared_secret.x).to_bytes(32, byteorder='big')).digest()

    cipher_aes = AES.new(derived_key, AES.MODE_CBC)
    start = time.time()
    enc_sym_key = derived_key
    enc_data = cipher_aes.encrypt(pad(data, AES.block_size))
    enc_time = time.time() - start

    # Decrypt symmetric key with ECC
    start = time.time()
    shared_secret_dec = public_key.pointQ * private_key.d
    derived_key_dec = hashlib.sha256(int(shared_secret_dec.x).to_bytes(32, byteorder='big')).digest()
    cipher_aes_dec = AES.new(derived_key_dec, AES.MODE_CBC, cipher_aes.iv)
    dec_data = unpad(cipher_aes_dec.decrypt(enc_data), AES.block_size)
    dec_time = time.time() - start

    return enc_data, dec_data, enc_time, dec_time

# RSA encryption/decryption
def rsa_encrypt_decrypt(data, key):
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    # Encrypting a symmetric key with RSA
    symmetric_key = get_random_bytes(32)  # AES-256 key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    start = time.time()
    enc_sym_key = cipher_rsa.encrypt(symmetric_key)
    cipher_aes = AES.new(symmetric_key, AES.MODE_CBC)
    enc_data = cipher_aes.encrypt(pad(data, AES.block_size))
    enc_time = time.time() - start

    # Decrypting the symmetric key with RSA
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    start = time.time()
    dec_sym_key = cipher_rsa.decrypt(enc_sym_key)
    cipher_aes = AES.new(dec_sym_key, AES.MODE_CBC, cipher_aes.iv)
    dec_data = unpad(cipher_aes.decrypt(enc_data), AES.block_size)
    dec_time = time.time() - start

    return enc_data, dec_data, enc_time, dec_time

# Generate report and graphs
def generate_report(results):
    file_sizes = [res['file_size'] for res in results]
    enc_times = [res['enc_time'] for res in results]
    dec_times = [res['dec_time'] for res in results]
    methods = [res['method'] for res in results]

    # Print report
    print("Encryption/Decryption Report")
    for res in results:
        print(f"Method: {res['method']}")
        print(f"File Size Before: {res['file_size']} bytes")
        print(f"File Size After: {res['enc_size']} bytes")
        print(f"Encryption Time: {res['enc_time']:.15f}s")
        print(f"Decryption Time: {res['dec_time']:.15f}s")
        print("-" * 30)

# Main script
def main():
    input_files = ['1mb.txt', '100mb.txt', '1gb.txt']
    #methods = {'3DES': des3_encrypt_decrypt}
    #methods = {'AES': aes_encrypt_decrypt}
    #methods = {'RSA': rsa_encrypt_decrypt} 
    methods = {'ECC': ecc_encrypt_decrypt }
      
    results = []

    for filepath in input_files:
        data = read_file(filepath)
        file_size = os.path.getsize(filepath)

        for method_name, method in methods.items():
            enc_data, dec_data, enc_time, dec_time = method(data, base_key)
            assert data == dec_data, f"{method_name} decryption failed"
            results.append({
                'method': method_name,
                'file_size': file_size,
                'enc_size': len(enc_data),
                'enc_time': enc_time,
                'dec_time': dec_time,
            })

    generate_report(results)

if __name__ == "__main__":
    main()
