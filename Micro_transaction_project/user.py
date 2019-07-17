from multiprocessing.connection import Client
import rsa
import hashlib
import random
import string


class User(object):
    def __init__(self):
        self.identity = 'user'
        self.public_key, self.private_key = rsa.newkeys(512)
        self.payword_certificate = None
        self.coins = []
        self.last_used_token = []
        self.broker_address = None
        self.broker_connection = None
        self.vendor_address = None
        self.vendor_connection = None

    @staticmethod
    def generate_password(length):
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=length)).encode("UTF-8")

    def enable_vendor_connection(self, address):
        self.vendor_address = address
        self.vendor_connection = Client(self.vendor_address)
        print("Vendor connection enabled.")

    def disable_vendor_connection(self):
        self.vendor_connection.send("exit")
        self.vendor_connection.close()
        print("Vendor connection disabled.")

    def enable_broker_connection(self, address):
        self.broker_address = address
        self.broker_connection = Client(self.broker_address)
        self.broker_connection.send(self.public_key)
        broker_public_key = self.broker_connection.recv()
        half_pass = self.generate_password(50)
        encrypted = rsa.encrypt(half_pass, broker_public_key)
        self.broker_connection.send(encrypted)
        other_half = rsa.decrypt(self.broker_connection.recv(), self.private_key)
        password = half_pass + other_half
        self.broker_connection.close()
        self.broker_connection = Client(self.broker_address, authkey=password)
        print("Vendor connection enabled.")

    def disable_broker_connection(self):
        self.broker_connection.send('exit')
        self.broker_connection.close()
        print("Broker connection disabled.")

    def get_payword_cert(self):
        self.broker_connection.send("get_payword_certificate")
        self.broker_connection.send({'identity': self.identity, 'key': str(self.public_key)})
        payword_certificate = self.broker_connection.recv()
        if self.verify_signature(payword_certificate):
            self.payword_certificate = payword_certificate
            print("Got PayWord certificate")
        else:
            print("Did not get a PayWord certificate")

    @staticmethod
    def min_coins(money, suma):
        if suma <= 0:
            return False
        result = {1: 0, 3: 0, 5: 0}
        idx = 5
        while suma > 0 and idx > 0:
            if money[idx] > 0 and suma >= idx:
                if idx in result.keys():
                    result[idx] += 1
                else:
                    result[idx] = 1
                suma -= idx
                money[idx] -= 1
            else:
                idx -= 2
        if suma > 0:
            return False
        return result

    def get_coins(self):
        for i in range(3):
            coins = []
            length = int(self.payword_certificate['message']['credit_limit'])
            first_token = "".join(random.choices(string.ascii_uppercase + string.digits, k=500)).encode("UTF-8")
            first_token = hashlib.sha256(first_token).hexdigest()
            for idx in range(length):
                hashobj = hashlib.sha256(first_token.encode("UTF-8"))
                first_token = hashobj.hexdigest()
                coins.append(first_token)
            last_used_token = len(coins) - 1
            self.coins.append(coins)
            self.last_used_token.append(last_used_token)
        import pprint
        with open("keychain.txt", "w") as f:
            f.write(pprint.pformat(self.coins))

    def commit_to_vendor(self, vendor_id):
        self.vendor_connection.send("commit")
        commit = {
            'vendor_id': vendor_id,
            'payword_certificate': self.payword_certificate,
            'hash_chain_root_1': self.coins[0][len(self.coins[0]) - 1],
            'chain_length_1': len(self.coins[0]),
            'hash_chain_root_2': self.coins[1][len(self.coins[1]) - 1],
            'chain_length_2': len(self.coins[1]),
            'hash_chain_root_3': self.coins[2][len(self.coins[2]) - 1],
            'chain_length_3': len(self.coins[2])
        }
        self.vendor_connection.send({'message': commit, 'signature': self.sign_json(commit)})
        response_on_commit = self.vendor_connection.recv()
        if response_on_commit:
            print("Commit Successful")
        else:
            print("Commit denied")

    def pay_vendor(self, coin,ammount=1):
        if coin > 10000:
            print("Sum too large")
        else:
            if coin == 0:
                initial = self.last_used_token[0]
                self.vendor_connection.send("payment_1")
                self.last_used_token[0] -= ammount
                commit = {'identity': self.identity,
                          'token': self.coins[0][self.last_used_token[0]], 'sum': ammount}
                self.vendor_connection.send(commit)
                response_on_payment = self.vendor_connection.recv()
                if response_on_payment:
                    print("Payment Successful")
                else:
                    self.last_used_token[0] = initial
                    print("Payment denied from vendor.")
            elif coin == 1:
                initial = self.last_used_token[1]
                self.vendor_connection.send("payment_2")
                self.last_used_token[1] -= ammount
                commit = {'identity': self.identity,
                          'token': self.coins[1][self.last_used_token[1]], 'sum': ammount}
                self.vendor_connection.send(commit)
                response_on_payment = self.vendor_connection.recv()
                if response_on_payment:
                    print("Payment Successful")
                else:
                    self.last_used_token[1] = initial
                    print("Payment denied from vendor.")
            elif coin == 2:
                initial = self.last_used_token[2]
                self.vendor_connection.send("payment_3")
                self.last_used_token[2] -= ammount
                commit = {'identity': self.identity,
                          'token': self.coins[2][self.last_used_token[2]], 'sum': ammount}
                self.vendor_connection.send(commit)
                response_on_payment = self.vendor_connection.recv()
                if response_on_payment:
                    print("Payment Successful")
                else:
                    self.last_used_token[2] = initial
                    print("Payment denied from vendor.")
        print("Balance:", self.last_used_token, "tokens left.")

    def sign_json(self, json):
        hashable_str = str(json)
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        return h.hexdigest()

    @staticmethod
    def verify_signature(payword_certificate):
        hashable_str = str(payword_certificate['message'])
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        # print(type(payword_certificate['message']), payword_certificate['message'])
        return h.hexdigest() == payword_certificate['signature']


user = User()
try:

    user.enable_broker_connection(('localhost', 6000))
    user.get_payword_cert()
    user.disable_broker_connection()
    user.enable_vendor_connection(('localhost', 6001))
    user.get_coins()
    user.commit_to_vendor('vendor')
    print("Balance:", user.last_used_token, "tokens left.")
    while True:
        choice = -1
        while choice < 0:
            try:
                choice = int(input("Introduceti suma pe care o transferati sau 0 daca vreti sa iesiti.\n"))
            except:
                choice = -1
        if choice == 0:
            break
        min_tokens = user.min_coins(
            {1: user.last_used_token[0], 3: user.last_used_token[1], 5: user.last_used_token[2]}, choice)
        if min_tokens:
            for i, element in enumerate(min_tokens):
                if min_tokens[element]>0:
                    user.pay_vendor(i,min_tokens[element])
            print(min_tokens)
        else:
            print("Can't do payment.")

    user.disable_vendor_connection()
finally:
    user.broker_connection.close()
    user.vendor_connection.close()
