import socket

HOST = "127.0.0.1"
PORT = 12348

with open("replayed_msg.bin", "rb") as f:
    replayed_data = f.read()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

sock.recv(1024)
sock.sendall(b"eve\n")
sock.recv(1024)
sock.sendall(b"Comp6841\n") 

sock.recv(1024)

sock.sendall(replayed_data)

sock.close()
print("Replay sent.")

