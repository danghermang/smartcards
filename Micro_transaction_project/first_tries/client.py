import socket
import rsa
import pickle
import random
import string
import hashlib
client_public_key, client_private_key = rsa.newkeys(512)
info = ["name", "24-02-2018", "card_num"]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8002))
print("Connected")

s.send(b"ClientOk")
server_public_key = rsa.PublicKey.load_pkcs1(s.recv(1024))
# print(server_public_key)
s.send(client_public_key.save_pkcs1())
# print(client_public_key)
s.recv(100)


def generate_hash_link(length, initial=None):
    if not initial:
        initial = ''.join(random.choices(string.ascii_uppercase + string.digits, k=500))
    chain = []
    for i in range(length):
        hash_obj= hashlib.sha256(initial.encode("UTF-8"))
        initial = hash_obj.hexdigest()
        chain.append(initial)
    return chain


def send_message(message):
    message = pickle.dumps(message)
    encrypted = rsa.encrypt(message, server_public_key)
    s.send(encrypted)
    s.recv(100)


s.send(b"Auth_me")
send_message(info[0])
send_message(info[1])
send_message(info[2])

message = (info[0] + info[1] + info[2]).encode("UTF-8")
hash_from_server = s.recv(1024)
certficate = rsa.verify(message,hash_from_server,server_public_key)
s.send(b"exit")
s.close()
if certficate:
    print("gen")
    chain_1 = generate_hash_link(100)
    chain_3 = generate_hash_link(100)
    chain_5 = generate_hash_link(100)
    #create commit