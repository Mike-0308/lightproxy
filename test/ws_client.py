import socket, sys

HOST, PORT = "127.0.0.1", int(sys.argv[1])
HOSTHDR = sys.argv[2]

c = socket.create_connection((HOST, PORT), timeout=6)
req = (
    "GET /chat HTTP/1.1\r\n"
    "Host: " + HOSTHDR + "\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n"
)
c.sendall(req.encode())

buf = b""
while b"\r\n\r\n" not in buf:
    d = c.recv(1024)
    if not d:
        break
    buf += d
head = buf.split(b"\r\n\r\n")[0].decode("latin1")
print("响应首行:", head.split("\r\n")[0])
print("包含 101:", "101" in head)
print("包含 Upgrade:", "upgrade" in head.lower())

c.sendall(b"ping")
got = c.recv(1024)
print("回显:", got)
c.close()
