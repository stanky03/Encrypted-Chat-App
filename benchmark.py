import os
import time
import statistics
import secrets
from crypto_utils import (
    generate_rsa_keypair, generate_ecc_keypair, generate_ed25519_keypair,
    load_rsa_key, load_ecc_key, load_ed25519_key,
    rsa_encrypt, rsa_decrypt, ecc_encrypt, ecc_decrypt,
    sign_bytes, verify_signature, sign_bytes_ed25519, verify_signature_ed25519
)
# fair comparison
from Crypto.Cipher import DES, AES


class CryptoBenchmark:
    def __init__(self, iterations=30):
        self.iterations = iterations
        self.results = {}
        
    def benchmark_key_generation(self):
        print("1. KEY GENERATION")
        print()

        print("Generating RSA keys...")
        rsa_times = []
        for i in range(5): 
            start = time.time()
            generate_rsa_keypair(f"bench_rsa_{i}")
            rsa_times.append(time.time() - start)
            print(f"  RSA key {i+1}/5: {rsa_times[-1]*1000:.2f}ms")
        
        print("\nGenerating ECC keys...")
        ecc_times = []
        for i in range(5):
            start = time.time()
            generate_ecc_keypair(f"bench_ecc_{i}")
            ecc_times.append(time.time() - start)
            print(f"  ECC key {i+1}/5: {ecc_times[-1]*1000:.2f}ms")
        
        self.results['key_generation'] = {
            'RSA': statistics.mean(rsa_times),
            'ECC': statistics.mean(ecc_times)
        }
        
        print(f"\nKEY GENERATION RESULTS:")
        print(f"RSA: {statistics.mean(rsa_times)*1000:.2f}ms avg")
        print(f"ECC: {statistics.mean(ecc_times)*1000:.2f}ms avg")
        
        rsa_to_ecc = statistics.mean(rsa_times) / statistics.mean(ecc_times)
        print(f"\nECC is {round(rsa_to_ecc)} faster than RSA for key generation")

    def benchmark_encryption_decryption(self):
        print(f"\n2. ENCRYPTION/DECRYPTION")
        print()
        
        # use first rsa and ecc key
        username = "bench_rsa_0"  
        ecc_username = "bench_ecc_0"  
        
        rsa_priv = load_rsa_key(username, private=True)
        rsa_pub = load_rsa_key(username, private=False)
        ecc_priv = load_ecc_key(ecc_username, private=True)
        ecc_pub = load_ecc_key(ecc_username, private=False)
        
        test_msg = b"Testing Hello World123 for benchamrking - encryption, decryption purposes only"
        
        print("Testing RSA encryption/decryption...")
        rsa_encrypt_times = []
        rsa_decrypt_times = []
        
        for i in range(self.iterations):
            start = time.time()
            rsa_ciphertext = rsa_encrypt(rsa_pub, test_msg)
            rsa_encrypt_times.append(time.time() - start)
            
            start = time.time()
            rsa_decrypt(rsa_priv, rsa_ciphertext)
            rsa_decrypt_times.append(time.time() - start)
        
        print("Testing ECC encryption/decryption...")
        ecc_encrypt_times = []
        ecc_decrypt_times = []
        
        for i in range(self.iterations):
            start = time.time()
            ecc_ciphertext = ecc_encrypt(ecc_pub, test_msg)
            ecc_encrypt_times.append(time.time() - start)
            
            start = time.time()
            ecc_decrypt(ecc_priv, ecc_ciphertext)
            ecc_decrypt_times.append(time.time() - start)
        
        print("Testing DES encryption/decryption...")
        des_key = secrets.token_bytes(8) 
        des_encrypt_times = []
        des_decrypt_times = []
        
        for i in range(self.iterations):
            start = time.time()
            des_cipher = DES.new(des_key, DES.MODE_ECB)
            padded_message = test_msg + b'\x00' * (8 - len(test_msg) % 8)
            des_ciphertext = des_cipher.encrypt(padded_message)
            des_encrypt_times.append(time.time() - start)
            
            start = time.time()
            des_cipher = DES.new(des_key, DES.MODE_ECB)
            des_plaintext = des_cipher.decrypt(des_ciphertext)
            des_decrypt_times.append(time.time() - start)
        
        print("Testing AES encryption/decryption...")
        aes_key = secrets.token_bytes(16) 
        aes_encrypt_times = []
        aes_decrypt_times = []
        
        for i in range(self.iterations):
            start = time.time()
            aes_cipher = AES.new(aes_key, AES.MODE_ECB)
            padded_message = test_msg + b'\x00' * (16 - len(test_msg) % 16)
            aes_ciphertext = aes_cipher.encrypt(padded_message)
            aes_encrypt_times.append(time.time() - start)
            
            start = time.time()
            aes_cipher = AES.new(aes_key, AES.MODE_ECB)
            aes_plaintext = aes_cipher.decrypt(aes_ciphertext)
            aes_decrypt_times.append(time.time() - start)
            
        
        self.results['encryption'] = {
            'RSA': statistics.mean(rsa_encrypt_times),
            'ECC': statistics.mean(ecc_encrypt_times),
            'DES': statistics.mean(des_encrypt_times),
            'AES': statistics.mean(aes_encrypt_times)
        }
        
        self.results['decryption'] = {
            'RSA': statistics.mean(rsa_decrypt_times),
            'ECC': statistics.mean(ecc_decrypt_times),
            'DES': statistics.mean(des_decrypt_times),
            'AES': statistics.mean(aes_decrypt_times)
        }
        
        print(f"\nENCRYPTION RESULTS:")
        print(f"RSA: {statistics.mean(rsa_encrypt_times)*1000:.2f}ms avg (±{statistics.stdev(rsa_encrypt_times)*1000:.2f}ms)")
        print(f"ECC: {statistics.mean(ecc_encrypt_times)*1000:.2f}ms avg (±{statistics.stdev(ecc_encrypt_times)*1000:.2f}ms)")
        print(f"DES: {statistics.mean(des_encrypt_times)*1000:.2f}ms avg (±{statistics.stdev(des_encrypt_times)*1000:.2f}ms)")
        print(f"AES: {statistics.mean(aes_encrypt_times)*1000:.2f}ms avg (±{statistics.stdev(aes_encrypt_times)*1000:.2f}ms)")
        
        print(f"\nDECRYPTION RESULTS:")
        print(f"RSA: {statistics.mean(rsa_decrypt_times)*1000:.2f}ms avg (±{statistics.stdev(rsa_decrypt_times)*1000:.2f}ms)")
        print(f"ECC: {statistics.mean(ecc_decrypt_times)*1000:.2f}ms avg (±{statistics.stdev(ecc_decrypt_times)*1000:.2f}ms)")
        print(f"DES: {statistics.mean(des_decrypt_times)*1000:.2f}ms avg (±{statistics.stdev(des_decrypt_times)*1000:.2f}ms)")
        print(f"AES: {statistics.mean(aes_decrypt_times)*1000:.2f}ms avg (±{statistics.stdev(aes_decrypt_times)*1000:.2f}ms)")

    def benchmark_digital_signatures(self):
        print(f"\n3. DIGITAL SIGNATURES")
        
        # RSA PSS vs Ed25519
        rsa_username = "bench_rsa_0"  
        # generate new Ed25519 keys
        ed25519_username = "bench_ed25519_0"  
        
        if not os.path.exists(f"keys/{ed25519_username}_ed25519.pem"):
            print("Generating Ed25519 keys...")
            generate_ed25519_keypair(ed25519_username)
        
        rsa_priv = load_rsa_key(rsa_username, private=True) 
        rsa_pub = load_rsa_key(rsa_username, private=False)
        ed25519_priv = load_ed25519_key(ed25519_username, private=True)  
        ed25519_pub = load_ed25519_key(ed25519_username, private=False)
        
        test_msg = b"Testing Hello World123 for benchamrking - signing, verification purposes only"
        
        print("Testing RSA-PSS signatures...")
        rsa_sign_times = []
        rsa_verify_times = []
        
        for i in range(self.iterations):
            start = time.time()
            rsa_signature = sign_bytes(test_msg, rsa_priv)
            rsa_sign_times.append(time.time() - start)
            
            start = time.time()
            verify_signature(test_msg, rsa_signature, rsa_pub)
            rsa_verify_times.append(time.time() - start)
            
        
        print("Testing Ed25519 signatures...")
        ed25519_sign_times = []
        ed25519_verify_times = []
        
        for i in range(self.iterations):
            start = time.time()
            ed25519_signature = sign_bytes_ed25519(test_msg, ed25519_priv)
            ed25519_sign_times.append(time.time() - start)
            
            start = time.time()
            verify_signature_ed25519(test_msg, ed25519_signature, ed25519_pub)
            ed25519_verify_times.append(time.time() - start)
        
        self.results['signing'] = {
            'RSA-PSS': statistics.mean(rsa_sign_times),
            'Ed25519': statistics.mean(ed25519_sign_times)
        }
        
        self.results['verification'] = {
            'RSA-PSS': statistics.mean(rsa_verify_times),
            'Ed25519': statistics.mean(ed25519_verify_times)
        }
        
        print(f"\nSIGNING RESULTS:")
        print(f"RSA-PSS: {statistics.mean(rsa_sign_times)*1000:.2f}ms avg (±{statistics.stdev(rsa_sign_times)*1000:.2f}ms)")
        print(f"Ed25519: {statistics.mean(ed25519_sign_times)*1000:.2f}ms avg (±{statistics.stdev(ed25519_sign_times)*1000:.2f}ms)")
        
        print(f"\nVERIFICATION RESULTS:")
        print(f"RSA-PSS: {statistics.mean(rsa_verify_times)*1000:.2f}ms avg (±{statistics.stdev(rsa_verify_times)*1000:.2f}ms)")
        print(f"Ed25519: {statistics.mean(ed25519_verify_times)*1000:.2f}ms avg (±{statistics.stdev(ed25519_verify_times)*1000:.2f}ms)")


def main():
    print("BenchMark Analysis (RSA, RSA PSS, ECC, Ed25519, DES, AES)")
    print("=" * 80)
    
    benchmark = CryptoBenchmark(iterations=30) 
    benchmark.benchmark_key_generation()
    benchmark.benchmark_encryption_decryption()
    benchmark.benchmark_digital_signatures()        

if __name__ == '__main__':
    main() 
