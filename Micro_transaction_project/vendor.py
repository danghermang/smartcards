import hashlib
from multiprocessing.connection import Listener, Client


class Vendor(object):
    def __init__(self):
        self.identity = 'vendor'
        self.user = dict()
        self.user_address = None
        self.user_connection = None
        self.user_listner = None
        self.broker_address = None
        self.broker_connection = None

    def enable_user_connection(self, address):
        self.user_address = address
        self.user_listener = Listener(self.user_address)
        self.user_connection = self.user_listener.accept()
        print('Connection accepted from', self.user_listener.last_accepted)

    def disable_user_connection(self):
        print("Disabled user connection.")
        self.user_connection.close()
        self.user_listener.close()

    def enable_broker_connection(self, address):
        self.broker_address = address
        self.broker_connection = Client(self.broker_address)
        print("Broker connection enabled.")

    def disable_broker_connection(self):
        self.broker_connection.send("exit")
        self.broker_connection.close()
        print("Broker connection disabled.")

    def accept_payment(self, payment, chain):
        paying_user = payment['identity']
        token = payment['token']
        ammount = payment['sum']
        for i in range(ammount):
            token = hashlib.sha256(token.encode("UTF-8")).hexdigest()
        if token != self.user['last_token_' + str(chain)]:
            print("Payment failed.")
            return False
        self.user['last_token_' + str(chain)] = payment['token']
        self.user['sum_' + str(chain)] = self.user['sum_' + str(chain)] + ammount
        self.user['payments'].append([paying_user, payment['token'], ammount, chain])
        print("Payment accepted.")
        return True

    def accept_commit(self, commit_request):
        if self.verify_commit(commit_request):
            self.user = {'payword_certificate': commit_request['message']['payword_certificate'],
                         'first_token_1': commit_request['message']['hash_chain_root_1'],
                         'first_token_2': commit_request['message']['hash_chain_root_2'],
                         'first_token_3': commit_request['message']['hash_chain_root_3'],
                         'last_token_1': commit_request['message']['hash_chain_root_1'], 'sum_1': 0,
                         'last_token_2': commit_request['message']['hash_chain_root_2'], 'sum_2': 0,
                         'last_token_3': commit_request['message']['hash_chain_root_3'], 'sum_3': 0,
                         'payments': []}
            print("Commit accepted.")
            return True
        print("Commit failed.")
        return False

    def output_payments(self, path):
        with open(path, "w") as fp:
            for element in self.user['payments']:
                fp.write(str(element) + "\n")

    def verify_commit(self, commit_request):
        if commit_request['message']['vendor_id'] != self.identity or \
                        commit_request['message']['chain_length_1'] > \
                        commit_request['message']['payword_certificate']['message']['credit_limit'] or \
                        commit_request['message']['chain_length_2'] > \
                        commit_request['message']['payword_certificate']['message']['credit_limit'] or \
                        commit_request['message']['chain_length_3'] > \
                        commit_request['message']['payword_certificate']['message']['credit_limit']:
            return None
        hashable_str = str(commit_request['message'])
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        return h.hexdigest() == commit_request['signature'] and \
               self.verify_signature(commit_request['message']['payword_certificate'])

    @staticmethod
    def verify_signature(payword_certificate):
        hashable_str = str(payword_certificate['message'])
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        return h.hexdigest() == payword_certificate['signature']

    def get_payment(self):
        hashable_str = str(self.user)
        h = hashlib.sha256()
        h.update(hashable_str.encode("UTF-8"))
        self.broker_connection.send({"message": self.user, "signature": h.hexdigest()})
        answer = self.broker_connection.recv()
        if answer:
            print("Got money for all payments.")
        else:
            print("Commit already used for payment.")


def on_commit():
    commit = vendor.user_connection.recv()
    response = vendor.accept_commit(commit)
    vendor.user_connection.send(response)


def on_payment(chain):
    payment = vendor.user_connection.recv()
    response = vendor.accept_payment(payment, chain)
    vendor.user_connection.send(response)


vendor = Vendor()
try:
    vendor.enable_user_connection(('localhost', 6001))
    while True:
        message = vendor.user_connection.recv()
        if message == "commit":
            on_commit()
        elif message == "payment_1":
            on_payment(1)
        elif message == "payment_2":
            on_payment(2)
        elif message == "payment_3":
            on_payment(3)
        elif message == "exit":
            vendor.output_payments("export.txt")
            vendor.disable_user_connection()
            break
    vendor.enable_broker_connection(('localhost', 6002))
    vendor.get_payment()
    vendor.get_payment()
    vendor.disable_broker_connection()
finally:
    vendor.user_connection.close()
    vendor.user_listener.close()
    vendor.broker_connection.close()
