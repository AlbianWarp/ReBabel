import random
import socketserver
from socket import SHUT_RDWR
import threading
import time
from threading import Thread

echo_load = "40524b28eb000000"

server_ehlo = {"host": "192.168.0.61", "port": 1337, "name": "ThunderStorm"}

player_database = {
    "alice": {"id": 123, "password": "alice"},
    "bob": {"id": 234, "password": "bob"},
    "ham5ter": {"id": 1337, "password": "notsecure"},
    "testuser": {"id": 42, "password": "notsecure"},
    "nac9tar": {"id": 364, "password": "notsecure"},
}

addrs = {}
requests = {}
threads = {}


def make_bytes_beautifull(payload, color_code="\033[96m"):
    pairs = [payload[i : i + 16] for i in range(0, len(payload), 16)]
    print(color_code)
    print("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F")
    print("    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
    for i, pair in enumerate(pairs):
        bytes = [pair[i : i + 1] for i in range(0, len(pair), 1)]
        print(" %02x " % i, end="")
        for byte in bytes:
            print("|%s" % byte.hex(), end="")
        print("|")
        print("   ", "+--" * len(pair), end="")
        print("+")
    print("\033[00m")


class package_data(bytes):
    @property
    def package_count(self):
        return self.get_int(20)

    def get_int(self, position, length=4):
        return int.from_bytes(self[position : position + length], byteorder="little")

    def get_string(self, position, length):
        return self[position : position + length].decode("latin-1")

    @staticmethod
    def int_to_bytes(integer, length=4):
        return integer.to_bytes(length, byteorder="little")

    @staticmethod
    def str_to_bytes(string):
        return string.encode("latin-1")

    @staticmethod
    def zeros(length=4):
        return int(0).to_bytes(length, byteorder="little")


class package_line(package_data):
    @property
    def username(self):
        return self.get_string(52, self.get_int(44) - 1)

    @property
    def password(self):
        return self.get_string(52 + self.get_int(44), self.get_int(48) - 1)

    @property
    def user_id(self):
        if (
            self.username in player_database
            and player_database[self.username]["password"] == self.password
        ):
            return player_database[self.username]["id"]
        return None


class line_response(package_data):
    def __init__(self, pl, server_ehlo=server_ehlo, echo_load=echo_load):
        if pl.user_id is None:
            self.data = (
                self.int_to_bytes(10)
                + self.zeros(16)
                + self.int_to_bytes(pl.package_count + 1)  # Package Count
                + self.zeros(36)
            )
        else:
            self.data = (
                # header
                self.int_to_bytes(10)  # package type (0a000000)
                + bytes.fromhex(echo_load)  # ECHO
                + self.int_to_bytes(pl.user_id)  # User ID
                + bytes.fromhex("01000a00")  # Unknown Data
                + self.int_to_bytes(pl.package_count + 1)  # Package Count
                + self.zeros(8)
                # end Header / start payload
                + self.zeros()
                + self.int_to_bytes(1)
                + self.zeros()
                + self.int_to_bytes(
                    len(server_ehlo["host"]) + len(server_ehlo["name"]) + 22
                )  # payload Length maybe?
                + self.int_to_bytes(1)
                + self.int_to_bytes(1)
                + self.int_to_bytes(1)
                + self.int_to_bytes(server_ehlo["port"])
                + self.int_to_bytes(1)
                + self.str_to_bytes(server_ehlo["host"])
                + self.zeros(1)
                + self.str_to_bytes(server_ehlo["name"])
                + self.zeros(1)
            )
        self.user_id = pl.user_id


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.
    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        data = self.request.recv(1024)
        make_bytes_beautifull(data, color_code="\033[92m")
        if data[0:4] == bytes.fromhex("25000000"):
            p = package_line(data)
            r = line_response(p)
            make_bytes_beautifull(r.data)
            self.request.sendall(r.data)
            self.user_id = r.user_id
            if self.user_id is not None:
                print(f"{p.username} has joined!")
                self.session_run = True
            else:
                print(f"{p.username} LOGIN, failed")
                return
        else:
            print(f"Whatever that was, It was not a 'NET: LINE' Request! Bye Bye! ;)")
            return
        requests[self.user_id] = self
        threads[self.user_id] = threading.current_thread()
        while self.session_run:
            try:
                data = self.request.recv(1024)
            except ConnectionResetError as exception:
                print(f"{self.user_id} BREAK, {exception}")
                break
            if not data:
                print(f"{self.user_id} BREAK, NODATA")
                break
            if data[0:4].hex() not in ["13000000", "18000000", "21020000", "0f000000"]:
                make_bytes_beautifull(data, color_code="\033[91m")
                print(data.hex())
            else:
                make_bytes_beautifull(data, color_code="\033[92m")
            if data[0:4] == bytes.fromhex("13000000"):  # NET: ULIN
                requested_user_id = int.from_bytes(data[12:15], byteorder="little")
                package_count = int.from_bytes(data[20:24], byteorder="little")
                package_count_hex = package_count.to_bytes(4, byteorder="little").hex()
                if requested_user_id in requests:
                    response = bytes.fromhex(
                        f"13000000{echo_load}0000000000000000{package_count_hex}000000000a000000"
                    )
                else:
                    response = bytes.fromhex(
                        f"1300000000000000000000000000000000000000{package_count_hex}0000000000000000"
                    )
                make_bytes_beautifull(response)
                self.request.sendall(response)
            elif data[0:4] == bytes.fromhex("18000000"):  # NET: STAT
                package_count = int.from_bytes(data[20:24], byteorder="little")
                bytes_received = (12345).to_bytes(4, byteorder="little").hex()
                bytes_sent = (54321).to_bytes(4, byteorder="little").hex()
                player_online = (len(requests)).to_bytes(4, byteorder="little").hex()
                mil_seconds_online = (10602856).to_bytes(4, byteorder="little").hex()
                response = bytes.fromhex(
                    "1800000000000000000000000000000000000000"
                    + package_count.to_bytes(4, byteorder="little").hex()
                    + "00000000 00000000"
                    + mil_seconds_online
                    + player_online
                    + bytes_sent
                    + bytes_received
                )
                make_bytes_beautifull(response)
                self.request.sendall(response)
            elif data[0:4] == bytes.fromhex("21020000"):  # NET: RUSO
                package_count = int.from_bytes(data[20:24], byteorder="little")
                package_count_hex = package_count.to_bytes(4, byteorder="little").hex()
                random_user_id = random.choice(list(requests))
                random_user_id_hex = random_user_id.to_bytes(
                    4, byteorder="little"
                ).hex()
                reply = f"21020000{echo_load}{random_user_id_hex}01000a00{package_count_hex}0000000001000000"
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex("0f000000"):  # NET: UNIK
                package_count = int.from_bytes(data[20:24], byteorder="little")
                package_count_hex = package_count.to_bytes(4, byteorder="little").hex()
                user_id = int.from_bytes(data[12:16], byteorder="little")
                user_id_hex = data[12:16].hex()
                user_hid = int.from_bytes(data[16:20], byteorder="little")
                username = None
                for name, user in player_database.items():
                    if user["id"] == user_id:
                        username = name
                        username_hex = username.encode("latin-1").hex()
                        username_len_hex = len(username).to_bytes(4, byteorder='little').hex()
                        print(f"{username} {username_hex} {username_len_hex} {user_id}+{user_hid}")
                        break
                payld_len = 34 + len(username)
                reply = f"0f000000{echo_load}{user_id_hex}{data[16:20].hex()}{package_count_hex}{payld_len.to_bytes(4,byteorder='little').hex()}00000000{payld_len.to_bytes(4,byteorder='little').hex()}{user_id_hex}0b00cccc0500000005000000{ username_len_hex }48617070794d65696c69{username_hex}"
                print(reply)
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
        del requests[self.user_id]
        print(f" removed {self.user_id} from requests")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "0.0.0.0", 1337
    BUFSIZ = 1024
    ThreadedTCPServer.allow_reuse_address = True
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
    try:
        while True:
            comand = input("#")
            if comand == "ls":
                print(requests)
            elif comand == "rr":
                print(len(requests))
                if len(requests) > 0:
                    print(random.choice(list(requests)))
            elif comand.startswith("mb "):
                make_bytes_beautifull(bytes.fromhex(comand.split(" ")[1]))
            elif comand.startswith("send "):
                comand, recipient, data = comand.split(" ")
                requests[int(recipient)].request.sendall(bytes.fromhex(data))
            elif comand.startswith("quit"):
                tmp = []
                for foo in requests:
                    tmp.append(foo)
                for foo in tmp:
                    print(f"{foo} is still connected ")
                    requests[foo].request.shutdown(SHUT_RDWR)
                    requests[foo].request.close()
                server.shutdown()
                server.server_close()
                break
    except KeyboardInterrupt as exception:
        tmp = []
        for foo in requests:
            tmp.append(foo)
        for foo in tmp:
            print(f"{foo} is still connected ")
            requests[foo].request.shutdown(SHUT_RDWR)
            requests[foo].request.close()
        server.shutdown()
        server.server_close()