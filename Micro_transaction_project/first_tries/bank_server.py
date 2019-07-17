import socket
import rsa
import pickle

server_public_key, server_private_key = rsa.newkeys(512)
client_public_key = None
secure_connection = False
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 8002))
s.listen(1)
(connection, address) = s.accept()
print("Connected address:", address)
value = ""


def get_message():
    message = connection.recv(1024)
    decrypted = rsa.decrypt(message, server_private_key)
    connection.send(b"Done")
    return pickle.loads(decrypted)


while True:
    data = connection.recv(100).decode("UTF-8")
    print(data)
    if not data:
        break
    if data == "ClientOk":
        connection.send(server_public_key.save_pkcs1())
        client_public_key = rsa.PublicKey.load_pkcs1(connection.recv(1024))
        connection.send(b"Done")
        secure_connection = True

    if data == "Auth_me" and secure_connection:
        print("received message")
        info_from_client = get_message() + get_message() + get_message()
        hashServer = rsa.sign(info_from_client.encode("UTF-8"), server_private_key, 'SHA-1')
        connection.send(hashServer)

    if "exit" in data:
        break
connection.close()
print("Server closed")
