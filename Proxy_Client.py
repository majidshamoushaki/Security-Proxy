from socket import *
from _thread import *
import requests
from requests.models import Response
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

port = 8888
host = "127.0.0.1"
receive_socket = socket(AF_INET, SOCK_STREAM)
receive_socket.bind((host, port))
receive_socket.listen(1)


def encryption(message):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'1',
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(b'majid'))
    f = Fernet(key)
    return f.encrypt(bytes(message, "utf-8")).decode("utf-8")


def decryption(message):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'1',
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(b'majid'))
    f = Fernet(key)
    token = f.decrypt(bytes(message, "utf-8")).decode("utf-8")
    return token


def runner(connection_socket):
    message = connection_socket.recv(1024).decode('utf-8')
    print(message)
    encrypted = encryption(message)
    response = requests.post("http://127.0.0.1:7777", encrypted)
    response = decryption(response.content.decode("utf-8"))
    print(response)
    client_response = "<html>" + response + "</html>"
    res = Response()
    res._content = bytes(client_response, "utf-8")

    connection_socket.send(bytes('HTTP/1.1 {status_code}\n{headers}\n{body}'.format(
        status_code=200,
        headers='\n'.join('{}: {}'.format(k, v) for k, v in res.headers.items()),
        body=str(res.content, "utf-8"),
    ), "utf-8"))

    connection_socket.close()


while True:
    connection_socket, sender_address = receive_socket.accept()
    start_new_thread(runner, (connection_socket,))
