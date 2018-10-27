from socket import *
from _thread import *
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from requests.models import Response

port = 7777
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
    message = connection_socket.recv(1024).decode("utf-8")
    print(message)
    split_message = message.split("\n")
    print(split_message[0].split(" "))
    if split_message[0].split(" ")[0] == "POST":

        body = decryption(split_message[len(split_message) - 1])
        print(body)
        encrypted = encryption(body)
        print(encrypted)

        res = Response()
        res._content = bytes(encrypted, "utf-8")

        connection_socket.send(bytes('HTTP/1.1 {status_code}\n{headers}\n{body}'.format(
            status_code=200,
            headers='\n'.join('{}: {}'.format(k, v) for k, v in res.headers.items()),
            body=str(res.content, "utf-8"),
        ), "utf-8"))
    else:
        res = Response()
        res._content = b'bad request'

        connection_socket.send(bytes('HTTP/1.1 {status_code}\n{headers}\n{body}'.format(
            status_code=200,
            headers='\n'.join('{}: {}'.format(k, v) for k, v in res.headers.items()),
            body=str(res.content, "utf-8"),
        ), "utf-8"))

    connection_socket.close()


while True:
    connection_socket, sender_address = receive_socket.accept()
    start_new_thread(runner, (connection_socket,))
