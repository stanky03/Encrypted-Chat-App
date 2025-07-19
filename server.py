import socket
import threading
import os
import bcrypt
from crypto_utils import generate_rsa_keypair

HOST = '127.0.0.1'
PORT = 12347
USER_FILE = 'users.txt'
clients = {}  

def load_credentials():
    creds = {}
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as f:
            for line in f:
                user, pw_hash = line.strip().split()
                creds[user] = pw_hash
    return creds

def save_credentials(user, password):
    salt = bcrypt.gensalt()
    pw_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    with open(USER_FILE, 'a') as f:
        f.write(f"{user} {pw_hash}\n")
    return pw_hash

def is_valid_password(p):
    return (
        len(p) >= 7 and
        any(c.isupper() for c in p) and
        any(c.islower() for c in p) and
        any(c.isdigit() for c in p)
    )

# find socket associated with target username
# send message bytes to that socket
def send_to_user(username, msg_bytes):
    for s, u in clients.items():
        if u == username:
            try:
                s.sendall(msg_bytes)
            except:
                s.close()
                del clients[s]
            break


def handle_client(sock, addr, creds):
    try:
        sock.sendall(b"Enter Username: ")
        user = sock.recv(1024).decode().strip()
        if user in creds:
            while True:
                sock.sendall(b"Enter Password:") 
                pwd = sock.recv(1024).decode().strip()
                if bcrypt.checkpw(pwd.encode('utf-8'), creds[user].encode()):
                    if not os.path.exists(f"keys/{user}.pem"):
                        generate_rsa_keypair(user)
                    sock.sendall(b"\r\nLogin successful.\n")
                    break
                sock.sendall(b"\r\nWrong password! Try again\n")
        else:
            while True:
                sock.sendall(b"Enter Password:")  
                pwd = sock.recv(1024).decode().strip()
                if is_valid_password(pwd):
                    break
                sock.sendall(
                    b"Invalid (Password needs to be at least 7 characters and include, "
                    b"upper, lower case, number\n" )           
            pw_hash = save_credentials(user, pwd)
            creds[user] = pw_hash
            generate_rsa_keypair(user)
            sock.sendall(b"\r\nNew account created.\n")

        clients[sock] = user

        while True:
            data = sock.recv(4096)
            if not data:
                break

            # check if user online
            if data.startswith(b"WHOIS:"):
                target = data.split(b":", 1)[1].decode()
                sock.sendall(b"ONLINE" if target in clients.values() else b"OFFLINE")
                continue

            # key exchange routing
            if data.startswith(b"KEYX:"):
                # format: KEYX:<from_user>:<to_user>:<encrypted_key>
                parts = data.split(b":", 3)
                _, frm, to, rest = parts
                send_to_user(to.decode(), data)
                continue

            # chat message routing
            if data.startswith(b"MSG:"):
                # format: MSG:<to_user>:<payload>
                # save to bin for replay attack demo
                with open("replayed_msg.bin", "wb") as f:
                    f.write(data)
                parts = data.split(b":", 2)
                _, to, payload = parts
                send_to_user(to.decode(), payload)
                continue

    except Exception as e:
        print(f"ERROR {addr}: {e}")
    finally:
        if sock in clients:
            del clients[sock]
        sock.close()
        print(f"DISCONNECTED {addr}")

def main():
    creds = load_credentials()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"LISTENING ON {HOST}:{PORT}")
    while True:
        client_sock, addr = srv.accept()
        threading.Thread(
            target=handle_client,
            args=(client_sock, addr, creds),
            daemon=True
        ).start()

if __name__ == "__main__":
    main()
