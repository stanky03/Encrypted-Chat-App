import socket
import threading
import os
import sys
import pwinput
import time
import base64
from crypto_utils import (
    generate_aes_key,
    rsa_encrypt,
    rsa_decrypt,
    aes_encrypt,
    aes_decrypt,
    load_rsa_key,
    sign_bytes,
    verify_signature
)

HOST = '127.0.0.1'
PORT = 12347
BUFFER = 4096
session_key = None


def mask_input(prompt='Password: '):
    pwd = pwinput.pwinput(prompt=prompt)
    return pwd


def receive_messages(sock, username, peer):
    # to detect replayed messages
    seen_timestamps = set()
    # aes key to decyrpt
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
            rec_name  = to.decode()
            if rec_name == username and sender_name == peer:
                try:
                    priv = load_rsa_key(username, private = True)
                    session_key = rsa_decrypt(priv, encrypted)
                    print("\nSESSION KEY RECEIVED")
                except:
                    print(f"\nKEY DECRYPT FAILED")
            continue
    
        if data.startswith(b"KEYX:"):
            # format: KEYX:<from>:<to>:<encrypted_session_key>:<signature>
            _, frm, to, enc_key, sig = data.split(b":", 4)
            sender_name = frm.decode()
            rec_name = to.decode()
            if rec_name == username and sender_name == peer:
                priv = load_rsa_key(username, private=True)
                encrypted = base64.b64decode(enc_key)
                signature = base64.b64decode(sig)
                session_key = rsa_decrypt(priv, encrypted)
                # Verify signature
                pub = load_rsa_key(sender_name, private=False)
                if verify_signature(session_key, signature, pub):
                    print("SESSION KEY VERIFIED")
                else:
                    print("SESSION KEY SIGNATURE INVALID")
            continue
        
        if session_key:
            try:
                # 2 bytes signature length, rsa signature, aes encrypted message
                sig_len = int.from_bytes(data[:2], 'big')
                sig     = data[2:2+sig_len]
                aes_encrypted = data[2+sig_len:]

                # decrpt using session key
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
                    pub = load_rsa_key(sender, private = False)
                    if verify_signature(plaintext, sig, pub):
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
            # wrong password/new account created
            print(prompt)

        low = prompt.lower()
        if 'successful' in low or 'created' in low:
            break
    
    print()
    recipient = input('Enter recipient username to chat: ').strip()

    # user with smaller name initiates key exchange
    if username < recipient:
        print(f"Waiting for {recipient} to join...")
    else:
        print(f"Waiting for session key...")

    if username < recipient:
        # ask server if recipient online
        while True:
            sock.sendall(f"WHOIS:{recipient}".encode())
            if sock.recv(BUFFER).decode() == 'ONLINE':
                break
            time.sleep(1)

        # generate aes key, use reciepient public RSA key to encrypt
        session_key = generate_aes_key()
        pub = load_rsa_key(recipient, private = False)
        header = f"KEYX:{username}:{recipient}:".encode()
        sock.sendall(header + rsa_encrypt(pub, session_key))
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
        # sign using private rsa key
        sig = sign_bytes(payload, load_rsa_key(username, private = True))
        sig_len = len(sig).to_bytes(2, 'big')
        
        aes_encrypted = aes_encrypt(payload.decode(), session_key)
        packet  = sig_len + sig + aes_encrypted
        sock.sendall(f"MSG:{recipient}:".encode() + packet)

    sock.close()
    print('DISCONNECTED')

if __name__ == '__main__':
    main()
