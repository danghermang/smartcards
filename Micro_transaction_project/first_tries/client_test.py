import random
import string
import datetime
import rsa
import hashlib
from multiprocessing.connection import Client
first_adress = ('localhost', 6002)


public_key, private_key = rsa.newkeys(512)

def generate_password(length):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length)).encode("UTF-8")

broker_connection = Client(first_adress)
try:
    broker_connection.send(public_key)
    broker_public_key = broker_connection.recv()
    half_pass = generate_password(50)
    encrypted = rsa.encrypt(half_pass,broker_public_key)
    broker_connection.send(encrypted)
    password = half_pass + rsa.decrypt(broker_connection.recv(), private_key)
finally:
    broker_connection.close()
print(password)

broker_connection = Client(first_adress, authkey=password)
# print("aaaaa")
try:
    broker_connection.send("aici")
finally:
    broker_connection.close()