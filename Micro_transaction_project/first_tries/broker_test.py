from multiprocessing.connection import Listener
import random
import string
import datetime
import rsa
import hashlib
first_adress = ('localhost', 6002)


def generate_password(length):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length)).encode("UTF-8")


public_key, private_key = rsa.newkeys(512)

user_listener = Listener(first_adress)
try:
    user_connection = user_listener.accept()
    print("accept")

    user_public_key=user_connection.recv()
    user_connection.send(public_key)
    half_pass = generate_password(50)

    encrypted = rsa.encrypt(half_pass, user_public_key)
    other_half = rsa.decrypt(user_connection.recv(),private_key)
    user_connection.send(encrypted)

    password = other_half + half_pass
finally:
    user_connection.close()
    user_listener.close()
print(password)

user_listener = Listener(first_adress, authkey=password)
try:
    user_connection = user_listener.accept()
    print(user_connection.recv())
finally:
    user_connection.close()
    user_listener.close()
# print('Connection accepted from', user_listener2.last_accepted)