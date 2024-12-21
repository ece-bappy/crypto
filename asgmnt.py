import os
import time
import matplotlib.pyplot as plt
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Helper Functions
def generate_key_with_prefix(prefix, length):
    """Generate a key of the required length containing the prefix."""
    key = prefix.encode() + os.urandom(length - len(prefix))
    return key[:length]

def encrypt_decrypt_file(file_path, cipher_cls, key, iv, block_size):
    """Encrypt and decrypt a file using the given cipher class."""
    with open(file_path, 'rb') as f:
        data = f.read()

    cipher_encrypt = cipher_cls.new(key, cipher_cls.MODE_CBC, iv)
    start_encrypt = time.time()
    encrypted_data = cipher_encrypt.encrypt(pad(data, block_size))
    end_encrypt = time.time()

    cipher_decrypt = cipher_cls.new(key, cipher_cls.MODE_CBC, iv)
    start_decrypt = time.time()
    decrypted_data = unpad(cipher_decrypt.decrypt(encrypted_data), block_size)
    end_decrypt = time.time()

    assert data == decrypted_data, "Decrypted data does not match original!"

    return len(data), len(encrypted_data), end_encrypt - start_encrypt, end_decrypt - start_decrypt

# Encryption and Decryption Implementations
def encryption_analysis(file_paths):
    prefix = "0424312039"
    report = []

    for file_path in file_paths:
        file_name = os.path.basename(file_path)

        # 3DES
        key_3des = generate_key_with_prefix(prefix, 24)
        iv_3des = get_random_bytes(8)
        before, after, enc_time, dec_time = encrypt_decrypt_file(file_path, DES3, key_3des, iv_3des, DES3.block_size)
        report.append((file_name, "3DES", before, after, enc_time, dec_time))

        # AES
        key_aes = generate_key_with_prefix(prefix, 32)
        iv_aes = get_random_bytes(16)
        before, after, enc_time, dec_time = encrypt_decrypt_file(file_path, AES, key_aes, iv_aes, AES.block_size)
        report.append((file_name, "AES", before, after, enc_time, dec_time))

        # RSA (encrypting a symmetric key)
        rsa_key = RSA.generate(2048)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)

        # Generate a symmetric key for file encryption
        symmetric_key = get_random_bytes(32)

        # Encrypt the symmetric key using RSA
        start_encrypt_key = time.time()
        encrypted_key = cipher_rsa.encrypt(symmetric_key)
        end_encrypt_key = time.time()

        # Encrypt the file using AES with the symmetric key
        iv_file = get_random_bytes(16)
        cipher_aes = AES.new(symmetric_key, AES.MODE_CBC, iv_file)
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = cipher_aes.encrypt(pad(data, AES.block_size))

        # Decrypt the symmetric key using RSA
        start_decrypt_key = time.time()
        decrypted_key = cipher_rsa.decrypt(encrypted_key)
        end_decrypt_key = time.time()

        # Decrypt the file using AES with the decrypted symmetric key
        cipher_aes_decrypt = AES.new(decrypted_key, AES.MODE_CBC, iv_file)
        decrypted_data = unpad(cipher_aes_decrypt.decrypt(encrypted_data), AES.block_size)

        assert data == decrypted_data, "Decrypted data does not match original!"

        report.append((file_name, "RSA (via AES)", len(data), len(encrypted_data),
                       (end_encrypt_key - start_encrypt_key), (end_decrypt_key - start_decrypt_key)))

    return report

def generate_graphs(report):
    """Generate graphs for the encryption analysis report."""
    algorithms = [entry[1] for entry in report]
    encryption_times = [entry[4] for entry in report]
    decryption_times = [entry[5] for entry in report]
    file_sizes_before = [entry[2] for entry in report]
    file_sizes_after = [entry[3] for entry in report]

    # Plot encryption and decryption times
    plt.figure(figsize=(10, 5))
    plt.bar(algorithms, encryption_times, color='blue', alpha=0.6, label='Encryption Time')
    plt.bar(algorithms, decryption_times, color='red', alpha=0.6, label='Decryption Time')
    plt.xlabel('Encryption Algorithm')
    plt.ylabel('Time (s)')
    plt.title('Encryption and Decryption Times')
    plt.legend()
    plt.savefig('encryption_times.png')
    plt.show()

    # Plot file sizes before and after encryption
    plt.figure(figsize=(10, 5))
    bar_width = 0.35
    indices = range(len(file_sizes_before))
    
    plt.bar(indices, file_sizes_before, bar_width, color='green', alpha=0.6, label='Before Encryption')
    plt.bar([i + bar_width for i in indices], file_sizes_after, bar_width, color='orange', alpha=0.6, label='After Encryption')
    plt.xlabel('Encryption Algorithm')
    plt.ylabel('File Size (bytes)')
    plt.title('File Sizes Before and After Encryption')
    plt.xticks([i + bar_width / 2 for i in indices], algorithms)
    plt.legend()
    plt.savefig('file_sizes.png')
    plt.show()

# Example usage
file_paths = ["1mb.txt", "100mb.txt", "1gb.txt"]
report = encryption_analysis(file_paths)
generate_graphs(report)
