import random
import socketserver
from socket import SHUT_RDWR
import threading
from threading import Thread

from prayer.prayer import Pray
from prayer.blocks import TagBlock


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
            reply, self.user_id = net_line_reply_package(data)
            make_bytes_beautifull(reply)
            self.request.sendall(reply)
            if self.user_id is not None:
                self.session_run = True
            else:
                return
        else:
            print(f"Whatever that was, It was not a 'NET: LINE' Request! Bye Bye! ;)")
            return
        requests[self.user_id] = self
        threads[self.user_id] = threading.current_thread()
        while self.session_run:
            try:
                data = self.request.recv(102400)
            except ConnectionResetError as exception:
                print(f"{self.user_id} BREAK, {exception}")
                break
            if not data:
                print(f"{self.user_id} BREAK, NODATA")
                break
            if data[0:4].hex() in [
                "13000000",
                "18000000",
                "21020000",
                "0f000000",
                "10000000",
            ]:
                make_bytes_beautifull(data, color_code="\033[92m")
            elif data[0:4].hex() in ["09000000"]:
                pass
            else:
                make_bytes_beautifull(data, color_code="\033[91m")
                print(data.hex())
            if data[0:4] == bytes.fromhex("13000000"):  # NET: ULIN
                reply = net_ulin_reply_package(data)
                make_bytes_beautifull(reply)
                self.request.sendall(reply)
            elif data[0:4] == bytes.fromhex("18000000"):  # NET: STAT
                reply = net_stat_reply_package(data)
                make_bytes_beautifull(reply)
                self.request.sendall(reply)
            elif data[0:4] == bytes.fromhex("21020000"):  # NET: RUSO
                reply = net_ruso_reply_package(data)
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex("0f000000"):  # NET: UNIK
                reply = net_unik_reply_package(data)
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex("10000000"):
                user_id = int.from_bytes(data[12:16], byteorder="little")
                user_hid = int.from_bytes(data[16:18], byteorder="little")
                reply = user_status_package(user_id=user_id, user_hid=user_hid)
                make_bytes_beautifull(bytes.fromhex(reply))
                self.request.sendall(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex("21030000"):
                make_bytes_beautifull(data[0:24] + bytes.fromhex("0000000000000000"))
                self.request.sendall(data[0:24] + bytes.fromhex("0000000000000000"))
            elif data[0:4] == bytes.fromhex("09000000"):  # PRAY Data :shrug:
                print("PRAY INCOMMING...")
                raw_pray = data[76:]
                pld_len = int.from_bytes(data[24:28], byteorder="little")
                print(pld_len)
                moep = True
                if pld_len == len(data[32:]) - 8:
                    print("Small PRAY, All good :D")
                    moep = False
                while moep:
                    tmp = self.request.recv(1024)
                    if not tmp:
                        print("PRAY CONN BROKE!!!!")
                        moep = False
                    raw_pray = raw_pray + tmp
                    print(".", end="")
                    data = data[:76] + raw_pray
                    if pld_len == len(data[32:]) - 8:
                        moep = False
                print("")
                what, _ = poke_pray(data, sent_by_server=False)
                user_id = data[32:36]
                print(f" recpt user_id: {int.from_bytes(user_id, byteorder='little')}")
                pld_len = 36 + len(raw_pray)
                reply = bytes.fromhex(
                    f"090000000000000000000000000000000000000000000000{pld_len.to_bytes(4,byteorder='little').hex()}00000000{pld_len.to_bytes(4,byteorder='little').hex()}0100cccc{self.user_id.to_bytes(4,byteorder='little').hex()}{(pld_len - 24).to_bytes(4, byteorder='little').hex()}00000000010000000c0000000000000000000000{raw_pray.hex()}"
                )
                poke_pray(reply, sent_by_server=True)
                requests[int.from_bytes(user_id, byteorder="little")].request.sendall(
                    reply
                )
        del requests[self.user_id]
        print(f" removed {self.user_id} from requests")


def poke_pray(pray_request_package, sent_by_server=False):
    what = {
        "tcp_pld_len": {"t": "print", "d": len(pray_request_package)},
        "pld_len_no_header": {"t": "print", "d": len(pray_request_package[32:])},
        "type": {"t": "raw", "d": pray_request_package[0:4]},
        "echo_load": {"t": "raw", "d": pray_request_package[4:12]},
        "user_id_01": {"t": "int", "d": pray_request_package[12:16]},
        "user_hid": {"t": "int", "d": pray_request_package[16:18]},
        "mystery_01": {"t": "raw", "d": pray_request_package[18:20]},
        "mystery_02": {"t": "raw", "d": pray_request_package[20:24]},
        "pld_len_01": {
            "t": "int",
            "d": pray_request_package[24:28],
        },  # Always pld_len_no_header - 8
        "mystery_03": {
            "t": "raw",
            "d": pray_request_package[28:32],
        },  # The Payload len might occupy 8 Bytes ?
        # HEADER END
        "sender_uid": {"t": "int", "d": pray_request_package[32:36]},
        "sender_hid": {"t": "int", "d": pray_request_package[36:38]},
        "mystery_04": {"t": "raw", "d": pray_request_package[38:40]},
        "pld_len_02": {"t": "int", "d": pray_request_package[40:44]},
        "mystery_12": {"t": "int", "d": pray_request_package[44:48]},
        "user_id_02": {"t": "int", "d": pray_request_package[48:52]},
        "pld_len_minus_24_?": {
            "t": "int",
            "d": pray_request_package[52:56],
        },  # SOme Length :shrug:
        "mystery_07": {"t": "raw", "d": pray_request_package[56:60]},
        "mystery_08": {"t": "raw", "d": pray_request_package[60:64]},
        "mystery_09": {"t": "raw", "d": pray_request_package[64:68]},
        "mystery_10": {"t": "raw", "d": pray_request_package[68:72]},
        "mystery_11": {"t": "raw", "d": pray_request_package[72:76]},
        "pray": {"t": "raw", "d": pray_request_package[76:]},
        "pray_filename": {
            "t": "str",
            "d": pray_request_package[76 : 76 + 128]
            .decode("latin-1")
            .rstrip("\0")
            .encode("latin-1"),
        },
    }
    if sent_by_server:
        what = {
            "tcp_pld_len": {"t": "print", "d": len(pray_request_package)},
            "pld_len_no_header": {"t": "print", "d": len(pray_request_package[32:])},
            "type": {"t": "raw", "d": pray_request_package[0:4]},
            "echo_load": {"t": "raw", "d": pray_request_package[4:12]},
            "user_id_01": {"t": "int", "d": pray_request_package[12:16]},
            "user_hid": {"t": "int", "d": pray_request_package[16:18]},
            "mystery_01": {"t": "raw", "d": pray_request_package[18:20]},
            "mystery_02": {"t": "raw", "d": pray_request_package[20:24]},
            "pld_len_01": {
                "t": "int",
                "d": pray_request_package[24:28],
            },  # Always pld_len_no_header - 8
            "mystery_03": {
                "t": "raw",
                "d": pray_request_package[28:32],
            },  # The Payload len might occupy 8 Bytes ?
            # HEADER END
            "pld_len": {"t": "int", "d": pray_request_package[32:36]},
            "mystery_04": {"t": "raw", "d": pray_request_package[36:40]},
            "mystery_12": {"t": "int", "d": pray_request_package[40:44]},
            "pld_len_minus_24_?": {"t": "int", "d": pray_request_package[44:48]},
            "mystery_10": {"t": "int", "d": pray_request_package[48:52]},
            "mystery_06": {
                "t": "int",
                "d": pray_request_package[52:56],
            },  # SOme Length :shrug:
            "mystery_07": {"t": "raw", "d": pray_request_package[56:60]},
            "mystery_08": {"t": "raw", "d": pray_request_package[60:64]},
            "mystery_09": {"t": "raw", "d": pray_request_package[64:68]},
            "pray": {"t": "raw", "d": pray_request_package[68:]},
            "pray_filename": {
                "t": "str",
                "d": pray_request_package[68 : 68 + 128]
                .decode("latin-1")
                .rstrip("\0")
                .encode("latin-1"),
            },
        }
    for key, value in what.items():
        if value["t"] == "int":
            print(
                f"i {key}: {int.from_bytes(value['d'], byteorder='little')} - {value['d'].hex()}"
            )
        elif value["t"] == "raw":
            if len(value["d"]) > 9:
                print(f"r {key}: {value['d'][:8].hex()}... {len(value['d'])}")
            else:
                print(f"r {key}: {value['d'].hex()} {len(value['d'])}")
        elif value["t"] == "str":
            print(f"s {key}: '{value['d'].decode('latin-1')}' - {value['d'].hex()}")
        else:
            print(f"e {key}: {value['d']}")
    with open(
        f"./poke_pray/{what['pray_filename']['d'].decode('latin-1')}.pray", "wb"
    ) as f:
        f.write(what["pray"]["d"])
    pray = None
    try:
        print(f"Praying:")
        pray = Pray(what["pray"]["d"])
        for block in pray.blocks:
            print(f"Block Type: {block.type}\nBlock Name: {block.name}")
            if block.type in ["ICHT", "IMSG", "MESG", "CHAT", "OMSG", "OCHT", "MOEP"]:
                # write tag_block to Disk for analysis.
                tag_block = TagBlock(block.block_data)
                for variable in tag_block.named_variables:
                    if type(variable[1]) == int:
                        print('\tINT Key: "%s" Value: %s' % variable)
                    elif type(variable[1]) == str:
                        print('\tSTR Key: "%s" Value: "%s"' % variable)
                print(f"compressed: {tag_block.compressed}")
                print(f"block_data_length: {len(tag_block.block_data)}")
    except Exception as e:
        print(e)
    return what, pray


def net_line_reply_package(line_request_package):
    package_count = int.from_bytes(line_request_package[20:24], byteorder="little")
    print(f"{package_count}")
    username_len = int.from_bytes(line_request_package[44:48], byteorder="little")
    username = line_request_package[52 : 52 + username_len - 1].decode("latin-1")
    print(f"{username_len} {username}")
    password_len = int.from_bytes(line_request_package[48:52], byteorder="little")
    password = line_request_package[
        52 + username_len : 52 + username_len + password_len - 1
    ].decode("latin-1")
    print(f"{password_len} {password}")
    user_id = None
    if (
        username in player_database
        and player_database[username]["password"] == password
    ):
        user_id = player_database[username]["id"]
    user_hid = 1
    print(f"{user_id}+{user_hid}")
    if user_id is None:
        print(f"{username} LOGIN, failed")
        return (
            bytes.fromhex(
                f"0a00000000000000000000000000000000000000{package_count.to_bytes(4,byteorder='little').hex()}000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            user_id,
        )
    print(f"{username} has joined!")
    return (
        bytes.fromhex(
            f"0a000000{echo_load}{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2,byteorder='little').hex()}0a00{package_count.to_bytes(4, byteorder='little').hex()}0000000000000000"
            + f"00000000"
            + f"01000000"
            + f"00000000"
            + (len(server_ehlo["host"]) + len(server_ehlo["name"]) + 22)
            .to_bytes(4, byteorder="little")
            .hex()
            + f"01000000"
            + f"01000000"
            + f"01000000"
            + server_ehlo["port"].to_bytes(4, byteorder="little").hex()
            + f"01000000"
            + server_ehlo["host"].encode("latin-1").hex()
            + f"00"
            + server_ehlo["name"].encode("latin-1").hex()
            + f"00"
        ),
        user_id,
    )


def net_ulin_reply_package(ulin_request_package):
    requested_user_id = int.from_bytes(ulin_request_package[12:16], byteorder="little")
    package_count = int.from_bytes(ulin_request_package[20:24], byteorder="little")
    package_count_hex = package_count.to_bytes(4, byteorder="little").hex()
    if requested_user_id in requests:
        return bytes.fromhex(
            f"13000000{echo_load}0000000000000000{package_count_hex}000000000a000000"
        )
    else:
        return bytes.fromhex(
            f"1300000000000000000000000000000000000000{package_count_hex}0000000000000000"
        )


def net_stat_reply_package(stat_request_package):
    """This whole thing is a mock, all the date, asside from the Online player count, returned by this is nonsense ;)"""
    package_count = int.from_bytes(stat_request_package[20:24], byteorder="little")
    bytes_received = (12345).to_bytes(4, byteorder="little").hex()
    bytes_sent = (54321).to_bytes(4, byteorder="little").hex()
    player_online = (len(requests)).to_bytes(4, byteorder="little").hex()
    mil_seconds_online = (10602856).to_bytes(4, byteorder="little").hex()
    return bytes.fromhex(
        "1800000000000000000000000000000000000000"
        + package_count.to_bytes(4, byteorder="little").hex()
        + "0000000000000000"
        + mil_seconds_online
        + player_online
        + bytes_sent
        + bytes_received
    )


def net_ruso_reply_package(ruso_request_package):
    package_count = int.from_bytes(ruso_request_package[20:24], byteorder="little")
    package_count_hex = package_count.to_bytes(4, byteorder="little").hex()
    random_user_id = random.choice(list(requests))
    random_user_hid = 1
    return f"21020000{echo_load}{random_user_id.to_bytes(4, byteorder='little').hex()}{random_user_hid.to_bytes(2,byteorder='little').hex()}0a00{package_count_hex}0000000001000000"


def net_unik_reply_package(unik_request_package):
    package_count_hex = unik_request_package[20:24].hex()
    user_id = int.from_bytes(unik_request_package[12:16], byteorder="little")
    user_id_hex = unik_request_package[12:16].hex()
    user_hid = int.from_bytes(unik_request_package[16:18], byteorder="little")
    username = None
    for name, user in player_database.items():
        if user["id"] == user_id:
            username = name
            username_hex = username.encode("latin-1").hex()
            username_len_hex = len(username).to_bytes(4, byteorder="little").hex()
            print(f"{username} {username_hex} {username_len_hex} {user_id}+{user_hid}")
            break
    payld_len = 34 + len(username)
    reply = f"0f000000{echo_load}{user_id_hex}{unik_request_package[16:18].hex()}0000{package_count_hex}{payld_len.to_bytes(4, byteorder='little').hex()}00000000{payld_len.to_bytes(4, byteorder='little').hex()}{user_id_hex}0b00cccc0500000005000000{username_len_hex}48617070794d65696c69{username_hex}"
    print(reply)
    return reply


def user_status_package(user_id, user_hid=1):
    username = None
    for name, user in player_database.items():
        if user["id"] == user_id:
            username = name
            break

    if not username:
        username = "ERROR"
        payld_len = 34 + len(username)
        print(
            f"ERROR - user_status_package: A User that is not in the database was requested!"
        )
        return f"0e0000000000000000000000{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2, byteorder='little').hex()}0a0000000000{payld_len.to_bytes(4, byteorder='little').hex()}00000000{payld_len.to_bytes(4, byteorder='little').hex()}{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2, byteorder='little').hex()}cccc0500000005000000{len(username).to_bytes(4, byteorder='little').hex()}48617070794d65696c69{username.encode('latin-1').hex()}"

    print(
        f"{username} {username.encode('latin-1').hex()} {len(username).to_bytes(4, byteorder='little').hex()} {user_id}+{user_hid}"
    )
    payld_len = 34 + len(username)
    if user_id in requests:
        reply = f"0d0000000000000000000000{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2,byteorder='little').hex()}000000000000{payld_len.to_bytes(4, byteorder='little').hex()}00000000{payld_len.to_bytes(4, byteorder='little').hex()}{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2,byteorder='little').hex()}cccc0500000005000000{len(username).to_bytes(4, byteorder='little').hex()}48617070794d65696c69{username.encode('latin-1').hex()}"
        print(f"{user_id}+{user_hid} is online")
    else:
        reply = f"0e0000000000000000000000{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2,byteorder='little').hex()}0a0000000000{payld_len.to_bytes(4, byteorder='little').hex()}00000000{payld_len.to_bytes(4, byteorder='little').hex()}{user_id.to_bytes(4, byteorder='little').hex()}{user_hid.to_bytes(2,byteorder='little').hex()}cccc0500000005000000{len(username).to_bytes(4, byteorder='little').hex()}48617070794d65696c69{username.encode('latin-1').hex()}"
        print(f"{user_id}+{user_hid} is offline")
    print(reply)
    make_bytes_beautifull(bytes.fromhex(reply))
    return reply


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
            elif comand.startswith("pray "):
                comand, data = comand.split(" ")
                poke_pray(bytes.fromhex(data), sent_by_server=True)

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
