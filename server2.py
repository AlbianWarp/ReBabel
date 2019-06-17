import random
import socketserver
import threading
import time
from threading import Thread

echo_load = '40524b28eb000000'

server_ehlo = {
    'host': '192.168.29.1',
    'port': 1337,
    'name': 'ThunderStorm'
}

player_database = {
    'alice': {'id': 123, 'password': "alice"},
    'bob': {'id': 234, 'password': "bob"},
    'ham5ter': {'id': 1337, 'password': "notsecure"},
    'testuser': {'id': 42, 'password': "notsecure"},
    'nac9tar': {'id': 364, 'password': "notsecure"}
}

addrs = {}
requests = {}
threads = {}

def make_bytes_beautifull(payload,color_code='\033[96m'):
    pairs = [payload[i:i+16] for i in range(0, len(payload), 16)]
    print(color_code)
    print('     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F')
    print('    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+')
    for i, pair in enumerate(pairs):
        bytes = [pair[i:i+1] for i in range(0, len(pair), 1)]
        print(' %02x '% i,end='')
        for byte in bytes:
            print('|%s'%byte.hex(),end='')
        print('|')
        print('   ','+--'*len(pair),end='')
        print('+')
    print('\033[00m')

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.
    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        data = self.request.recv(1024)
        make_bytes_beautifull(data,color_code='\033[92m')
        if data[0:4] == bytes.fromhex('25000000'):
            self.package_count = int.from_bytes(data[20:24], byteorder='little')
            username_len = int.from_bytes(data[44:47], byteorder='little') - 1
            password_len = int.from_bytes(data[48:52], byteorder='little') - 1
            self.username = data[52:52 + username_len].decode('latin-1')
            password = data[52 + username_len + 1:52 + username_len + 1 + password_len].decode('latin-1')
            if self.username in player_database and player_database[self.username]['password'] == password:
                self.user_id = player_database[self.username]['id']
                user_id = player_database[self.username]['id'].to_bytes(4, byteorder='little').hex()
                package_type = '0a000000'
                another_value = '01000a00'
                package_count_hex = self.package_count.to_bytes(4, byteorder='little').hex()
                zeros = '0000000000000000'
                data = f'''
                00000000
                01000000
                00000000
                {int(len(server_ehlo['host']) + len(server_ehlo['name'])+22).to_bytes(4, byteorder='little').hex()}
                01000000
                01000000
                01000000
                {server_ehlo['port'].to_bytes(4, byteorder='little').hex()}
                01000000
                {server_ehlo['host'].encode("latin-1").hex()}
                00
                {server_ehlo['name'].encode("latin-1").hex()}
                00
                '''
                header = f'{package_type}{echo_load}{user_id}{another_value}{package_count_hex}{zeros}'
                reply = header + data
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
                print(f'{self.username} has joined!')
                self.session_run = True
            else:  # This package forces the Client to Disconnect, This is used as we don't have a working
                # "failed authentication" and other responses.
                package_type = '0a000000'
                user_id = '00000000'
                another_value = '00000000'
                package_count_hex = self.package_count.to_bytes(4, byteorder='little').hex()
                zeros = '0000000000000000'
                data = '00000000000000000000000000000000000000000000000000000000'
                reply = package_type + '0000000000000000' + user_id + another_value + package_count_hex + zeros + data
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
                return
        else:
            return
        requests[self.user_id] = self
        cur_thread = threading.current_thread()
        threads[self.user_id] = cur_thread
        while self.session_run:
            data = self.request.recv(1024)
            if not data:
                print(f'{self.username} BREAK, NODATA')
                break
            if data[0:4].hex() not in ['13000000','18000000','21020000','0f000000']:
                make_bytes_beautifull(data, color_code='\033[91m')
                print(data.hex())
            else:
                make_bytes_beautifull(data, color_code='\033[92m')
            if data[0:4] == bytes.fromhex('13000000'): # NET: ULIN
                requested_user_id = int.from_bytes(data[12:15], byteorder='little')
                package_count = int.from_bytes(data[20:24], byteorder='little')
                package_count_hex = package_count.to_bytes(4,byteorder='little').hex()
                if requested_user_id in requests:
                    response = bytes.fromhex(f'13000000{echo_load}0000000000000000{package_count_hex}000000000a000000')
                else:
                    response = bytes.fromhex(f'1300000000000000000000000000000000000000{package_count_hex}0000000000000000')
                make_bytes_beautifull(response)
                self.request.sendall(response)
            elif data[0:4] == bytes.fromhex('18000000'):  # NET: STAT
                package_count = int.from_bytes(data[20:24], byteorder='little')
                bytes_received = (12345).to_bytes(4, byteorder='little').hex()
                bytes_sent = (54321).to_bytes(4, byteorder='little').hex()
                player_online = (len(requests)).to_bytes(4, byteorder='little').hex()
                mil_seconds_online = (10602856).to_bytes(4, byteorder='little').hex()
                response = bytes.fromhex('1800000000000000000000000000000000000000' + package_count.to_bytes(4,byteorder='little').hex() + '00000000 00000000' + mil_seconds_online + player_online + bytes_sent + bytes_received)
                make_bytes_beautifull(response)
                self.request.sendall(response)
            elif data[0:4] == bytes.fromhex('21020000'):  # NET: RUSO
                package_count = int.from_bytes(data[20:24], byteorder='little')
                package_count_hex = package_count.to_bytes(4,byteorder='little').hex()
                random_user_id = random.choice(list(requests))
                random_user_id_hex = random_user_id.to_bytes(4,byteorder='little').hex()
                reply = f'21020000{echo_load}{random_user_id_hex}01000a00{package_count_hex}0000000001000000'
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex('0f000000'): # NET: UNIK
                package_count = int.from_bytes(data[20:24], byteorder='little')
                package_count_hex = package_count.to_bytes(4,byteorder='little').hex()
                user_id = int.from_bytes(data[12:16], byteorder='little')
                user_id_hex = data[12:16].hex()
                username = None
                for name, user in player_database.items():
                    if user['id'] == user_id:
                        username = name
                        username_hex = username.encode('latin-1').hex()
                        break
                reply = f'0f000000{echo_load}{user_id_hex}0b000000{package_count_hex}290000000000000029000000{user_id_hex}0b00cccc05000000050000000700000048617070794d65696c69{username_hex}'
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
        del requests[self.user_id]
        print(f' removed {self.user_id} from requests')



def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for request in requests:
        request.sendall(msg)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "0.0.0.0", 1337
    BUFSIZ = 1024

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    ip, port = server.server_address

    # Start a thread with the server -- that thread will then start one
    # more thread for each request
    server_thread = Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    # server_thread.daemon = True
    server_thread.start()
    print("Server loop running in thread:", server_thread.name)
    print("IP: {} Port: {}".format(str(ip), str(port)))
    print("Waiting for connection...")
    while True:
        comand = input('#')
        if comand == "ls":
            print(requests)
        elif comand == "rr":
            print(len(requests))
            if len(requests) > 0:
                print(random.choice(list(requests)))
        elif comand.startswith('mb '):
            make_bytes_beautifull(bytes.fromhex(comand.split(' ')[1]))
        elif comand.startswith('send '):
            comand, recipient, data = comand.split(' ')
            requests[int(recipient)].request.sendall(bytes.fromhex(data))
