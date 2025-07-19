import socket
import threading
import os
import sys
import pwinput
import time
from crypto_utils import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    generate_ecc_keypair,
    load_ecc_key,
    ecc_encrypt,
    ecc_decrypt,
    generate_ed25519_keypair,
    load_ed25519_key,
    sign_bytes_ed25519,
    verify_signature_ed25519
)

HOST = '127.0.0.1'
PORT = 12347
BUFFER = 4096
session_key = None


def mask_input(prompt='Password: '):
    pwd = pwinput.pwinput(prompt=prompt)
    return pwd


def receive_messages(sock, username, peer):
    seen_timestamps = set()

    global session_key
    while True:
        data = sock.recv(BUFFER)
        if not data:
            print("\nSERVER DISCONNECTED")
            break

        if data.startswith(b"KEYX:") and not session_key:
            # format: KEYX:<from>:<to>:<encrypted_session_key>
            _, frm, to, encrypted = data.split(b":", 3)
            sender_name = frm.decode()
            rec_name = to.decode()
            if rec_name == username and sender_name == peer:
                try:
                    priv = load_ecc_key(username, private=True)
                    session_key = ecc_decrypt(priv, encrypted)
                    print("\nSESSION KEY RECEIVED")
                except:
                    print(f"\nKEY DECRYPT FAILED")
            continue

        if session_key:
            try:
                # 2 bytes signature length, ed25519 signature, aes encrypted message
                sig_len = int.from_bytes(data[:2], 'big')
                sig = data[2:2+sig_len]
                aes_encrypted = data[2+sig_len:]

                # decrypt using session key
                plaintext = aes_decrypt(aes_encrypted, session_key).encode()
                full = plaintext.decode()
                sender, msg = full.split(': ', 1)
                sender, rest = full.split(': ', 1)
                if '|' not in rest:
                    print("\n Invalid message format.")
                    continue
                msg, ts = rest.split('|', 1)
                readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
                #if ts in seen_timestamps:
                    #print("\n Replay detected. Message dropped")
                    #continue
                seen_timestamps.add(ts)

                # verify signature of peer
                if sender == peer:
                    pub = load_ed25519_key(sender, private=False)
                    if verify_signature_ed25519(plaintext, sig, pub):
                        print(f"\n{sender}: {msg}\n>> ", end='', flush=True)
                        #print(f"\n{sender} [{readable}]: {msg}\n> ", end='', flush=True)
                    else:
                        print("\nSignature invalid.")
            except Exception:
                pass


def main():
    global session_key, username
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    prompt = sock.recv(BUFFER).decode()
    username = input(prompt)
    sock.sendall(username.encode())

    while True:
        prompt = sock.recv(BUFFER).decode().rstrip('\n')

        if prompt.lower().endswith('password:'):
            pwd = mask_input(prompt + ' ')
            sock.sendall(pwd.encode())
        else:
            print(prompt)

        low = prompt.lower()
        if 'successful' in low or 'created' in low:
            if not os.path.exists(f"keys/{username}_ecc.pem"):
                generate_ecc_keypair(username)
            if not os.path.exists(f"keys/{username}_ed25519.pem"):
                generate_ed25519_keypair(username)
            break
    
    print()
    recipient = input('Enter recipient username to chat: ').strip()

    if username < recipient:
        print(f"Waiting for {recipient} to join...")
    else:
        print(f"Waiting for session key...")

    if username < recipient:
        while True:
            sock.sendall(f"WHOIS:{recipient}".encode())
            if sock.recv(BUFFER).decode() == 'ONLINE':
                break
            time.sleep(1)

        # generate aes key, use recipient public ECC key to encrypt
        session_key = generate_aes_key()
        pub = load_ecc_key(recipient, private=False)
        header = f"KEYX:{username}:{recipient}:".encode()
        sock.sendall(header + ecc_encrypt(pub, session_key))
        print('\nAES SESSION KEY SENT')

    threading.Thread(
        target=receive_messages,
        args=(sock, username, recipient),
        daemon=True
    ).start()

    while session_key is None:
        time.sleep(0.1)

    print("You may now chat..Type 'exit' to leave.\n")

    while True:
        msg = input('>> ').strip()
        if msg.lower() == 'exit':
            break
        timestamp = str(int(time.time()))
        payload = f"{username}: {msg}|{timestamp}".encode()
        # sign using private ed25519 key
        sig = sign_bytes_ed25519(payload, load_ed25519_key(username, private=True))
        sig_len = len(sig).to_bytes(2, 'big')
        
        aes_encrypted = aes_encrypt(payload.decode(), session_key)
        packet = sig_len + sig + aes_encrypted
        sock.sendall(f"MSG:{recipient}:".encode() + packet)

    sock.close()
    print('DISCONNECTED')

if __name__ == '__main__':
    main() 
