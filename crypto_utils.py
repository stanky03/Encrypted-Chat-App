import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEYS_DIR = "keys"

def generate_rsa_keypair(username):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    key_pair = RSA.generate(4096)
    with open(os.path.join(KEYS_DIR, f"{username}.pem"), "wb") as priv:
        priv.write(key_pair.export_key())
    with open(os.path.join(KEYS_DIR, f"{username}.pub"), "wb") as pub:
        pub.write(key_pair.publickey().export_key())

def load_rsa_key(username, private=False):
    path = os.path.join(KEYS_DIR, f"{username}.{'pem' if private else 'pub'}")
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def rsa_encrypt(pub_key, message: bytes) -> bytes:
    return PKCS1_OAEP.new(pub_key).encrypt(message)

def rsa_decrypt(priv_key, ciphertext: bytes) -> bytes:
    return PKCS1_OAEP.new(priv_key).decrypt(ciphertext)


def generate_aes_key() -> bytes:
    return get_random_bytes(16)

def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce + tag + ct

def aes_decrypt(blob: bytes, key: bytes) -> str:
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()


def sign_bytes(data: bytes, priv_key) -> bytes:
    # RSA PSS
    h = SHA256.new(data)
    signer = pss.new(priv_key)
    return signer.sign(h)

def verify_signature(data: bytes, signature: bytes, pub_key):
    h = SHA256.new(data)
    verifier = pss.new(pub_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def generate_ecc_keypair(username):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Save private key
    with open(os.path.join(KEYS_DIR, f"{username}_ecc.pem"), "wb") as priv:
        priv.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(os.path.join(KEYS_DIR, f"{username}_ecc.pub"), "wb") as pub:
        pub.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_ecc_key(username, private=False):
    path = os.path.join(KEYS_DIR, f"{username}_ecc.{'pem' if private else 'pub'}")
    with open(path, "rb") as f:
        if private:
            return serialization.load_pem_private_key(f.read(), password=None)
        else:
            return serialization.load_pem_public_key(f.read())


def ecc_encrypt(recipient_pubkey, message: bytes) -> bytes:
    # Generate ephemeral key pair
    temp_private = ec.generate_private_key(ec.SECP256R1())
    temp_public = temp_private.public_key()
    
    # Perform ECDH key exchange
    shared_key = temp_private.exchange(ec.ECDH(), recipient_pubkey)
    
    # Derive AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc_encryption',
    ).derive(shared_key)
    
    # Encrypt message with AES
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(message)
    
    # Combine ephemeral public key + nonce + tag + ciphertext
    temp_pub_bytes = temp_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return temp_pub_bytes + cipher.nonce + tag + ct

def ecc_decrypt(receiver_privkey, ciphertext: bytes) -> bytes:
    # expects (ephemeral_public_key + nonce + tag + ciphertext)

    temp_pub_size = 65  
    nonce_size = 16
    tag_size = 16
    
    temp_pub_bytes = ciphertext[:temp_pub_size]
    nonce = ciphertext[temp_pub_size:temp_pub_size + nonce_size]
    tag = ciphertext[temp_pub_size + nonce_size:temp_pub_size + nonce_size + tag_size]
    ct = ciphertext[temp_pub_size + nonce_size + tag_size:]
    
    temp_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), temp_pub_bytes
    )
    
    shared_key = receiver_privkey.exchange(ec.ECDH(), temp_public)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc_encryption',
    ).derive(shared_key)
    
    # Decrypt message
    cipher = AES.new(derived_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def generate_ed25519_keypair(username):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    with open(os.path.join(KEYS_DIR, f"{username}_ed25519.pem"), "wb") as priv:
        priv.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(os.path.join(KEYS_DIR, f"{username}_ed25519.pub"), "wb") as pub:
        pub.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_ed25519_key(username, private=False):
    path = os.path.join(KEYS_DIR, f"{username}_ed25519.{'pem' if private else 'pub'}")
    with open(path, "rb") as f:
        if private:
            return serialization.load_pem_private_key(f.read(), password=None)
        else:
            return serialization.load_pem_public_key(f.read())

def sign_bytes_ed25519(data: bytes, priv_key) -> bytes:
    return priv_key.sign(data)

def verify_signature_ed25519(data: bytes, signature: bytes, pub_key):
    try:
        pub_key.verify(signature, data)
        return True
    except:
        return False
