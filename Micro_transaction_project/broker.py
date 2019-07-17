import random
import string
import datetime
import rsa
import hashlib
from multiprocessing.connection import Listener


class Broker(object):
    def __init__(self):
        self.identity = 'broker'
        self.public_key, self.private_key = rsa.newkeys(512)
        self.user_address = None
        self.user_listener = None
        self.user_connection = None
        self.vendor_address = None
        self.vendor_listener = None
        self.vendor_connection = None
        self.vendor_payments = []

    @staticmethod
    def generate_password(length):
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=length)).encode("UTF-8")

    def enable_user_connection(self, address):
        self.user_address = address
        self.user_listener = Listener(self.user_address)
        self.user_connection = self.user_listener.accept()
        user_public_key = self.user_connection.recv()
        self.user_connection.send(self.public_key)
        half_pass = self.generate_password(50)
        encrypted = rsa.encrypt(half_pass, user_public_key)
        other_half = rsa.decrypt(self.user_connection.recv(), self.private_key)
        self.user_connection.send(encrypted)
        password = other_half + half_pass
        self.user_connection.close()
        self.user_listener.close()
        self.user_listener = Listener(self.user_address, authkey=password)
        self.user_connection = self.user_listener.accept()
        print('Connection accepted from', self.user_listener.last_accepted)

    def disable_user_connection(self):
        self.user_connection.close()
        self.user_listener.close()
        print("Disabled user connection.")

    def enable_vendor_connection(self, address):
        self.vendor_address = address
        self.vendor_listener = Listener(self.vendor_address)
        self.vendor_connection = self.vendor_listener.accept()
        print('Connection accepted from', self.vendor_listener.last_accepted)

    def disable_vendor_connection(self):
        print("Disabled vendor connection.")
        self.vendor_connection.close()
        self.vendor_listener.close()

    def sign_json(self, json):
        hashable_str = str(json)
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        return h.hexdigest()

    def authorize(self, authorization_request, ammount):
        for field in ['identity', 'key']:
            if authorization_request.get(field, None) is None:
                return False

        authorization_request['ip'] = self.user_address

        expiration = str((datetime.date.today() + datetime.timedelta(days=1)))
        authorization_request['expiration'] = expiration

        authorization_request['emitting_authority'] = self.identity

        authorization_request['authority_key'] = self.public_key

        authorization_request['credit_limit'] = ammount + 1

        signed_certificate = self.sign_json(authorization_request)

        return {'message': authorization_request, 'signature': signed_certificate}

    def verify_commit(self, commit_request):
        if commit_request['message']['vendor_id'] != self.identity or \
                        commit_request['message']['chain_length'] > \
                        commit_request['message']['payword_certificate']['message']['credit_limit']:
            return None

        hashable_str = str(commit_request['message'])
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        return h.hexdigest() == commit_request['signature'] and \
               self.verify_signature(commit_request['message']['payword_certificate'])

    def verify_vendor_payment(self):
        request = self.vendor_connection.recv()
        if not self.verify_signature(request):
            self.vendor_connection.send(False)
        check = True
        not_used = True
        for i in range(3):
            first_hash = request['message']['first_token_' + str(i + 1)]
            last_hash = request['message']['last_token_' + str(i + 1)]
            length = request['message']['sum_' + str(i + 1)]
            new_hashes = []
            if length <= 0:
                continue
            for i in range(length):
                if last_hash not in self.vendor_payments:
                    new_hashes.append(last_hash)
                else:
                    not_used = False
                    check = False
                    print("Payment already checked")
                    self.vendor_connection.send(False)
                    break
                last_hash = hashlib.sha256(last_hash.encode("UTF-8")).hexdigest()
            if first_hash != last_hash and not_used:
                self.vendor_connection.send(False)
                check = False
                break
        if check:
            self.vendor_connection.send(True)
            self.vendor_payments.extend(new_hashes)

    @staticmethod
    def verify_signature(payword_certificate):
        hashable_str = str(payword_certificate['message'])
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        return h.hexdigest() == payword_certificate['signature']


broker = Broker()
try:
    broker.enable_user_connection(('localhost', 6000))
    while True:
        message = broker.user_connection.recv()
        if message == "get_payword_certificate":
            authorization_request = broker.user_connection.recv()
            print("Received auth request.")
            response = broker.authorize(authorization_request, 100)
            if response:
                print("User authorized.")
            else:
                print("Auth failed. Not enough information.")
            broker.user_connection.send(response)
        elif message == "exit":
            broker.disable_user_connection()
            break
    broker.enable_vendor_connection(('localhost', 6002))
    broker.verify_vendor_payment()
    broker.verify_vendor_payment()
    broker.disable_vendor_connection()
finally:
    broker.user_connection.close()
    broker.user_listener.close()
    broker.vendor_connection.close()
    broker.vendor_listener.close()
