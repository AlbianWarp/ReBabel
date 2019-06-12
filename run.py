import socket
import random

echo_load = '40524b28eb000000'
user_id = (2342).to_bytes(4, byteorder='little').hex()


def _return_failed_login(package_count):
    package_type = '0a000000'
    user_id = '00000000'
    another_value = '00000000'
    package_count_hex = package_count.to_bytes(4, byteorder='little').hex()
    zeros = '0000000000000000'
    data = '''
    00000000
    00000000
    00000000
    00000000
    00000000
    00000000
    00000000
    '''
    return package_type + '0000000000000000' + user_id + another_value + package_count_hex + zeros + data


def _return_succesfull_login(package_count):
    package_type = '0a000000'
    another_value = '01000a00'
    package_count_hex = package_count.to_bytes(4, byteorder='little').hex()
    zeros = '0000000000000000'
    data = '''
    00000000
    01000000
    00000000
    24000000
    01000000
    01000000
    01000000

    39050000
    01000000
    6c6f63616c686f7374
    00
    6c6f63616c
    00
    '''

    header = package_type + echo_load + user_id + another_value + package_count_hex + zeros
    package = header + data
    return package


def server_program():
    print((1337).to_bytes(4, byteorder='big').hex())
    print((1337).to_bytes(4, byteorder='little').hex())
    print(int.from_bytes(bytes.fromhex('68c9a100'), byteorder='little'))
    # get the hostname
    host = socket.gethostname()
    port = 1337  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind(("127.0.0.1", port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024)
        if not data:
            break
        print("< " + data.hex())
        if data[0:4] == bytes.fromhex('25000000'):
            package_count = int.from_bytes(data[20:24], byteorder='little')
            username_len = int.from_bytes(data[44:47], byteorder='little') - 1
            password_len = int.from_bytes(data[48:52], byteorder='little') - 1
            username = data[52:52 + username_len]
            password = data[52 + username_len + 1:52 + username_len + 1 + password_len]
            print("login request received!")
            print("username %s , password %s" % (username, password))
            if password != b"fail":  # Succesfull Login Response
                reply = _return_succesfull_login(package_count)
                print("> " + reply)
                conn.send(bytes.fromhex(reply))
            else:  # This package forces the Client to Disconnect, This is used as we don't have a working
                # "failed authentication" and other responses.
                reply = _return_failed_login(package_count)
                print("> " + reply)
                conn.send(bytes.fromhex(reply))
        elif data[0:4] == bytes.fromhex('13000000'):  # NET: ULIN
            print("NET: ULIN")
            requested_user_id = int.from_bytes(data[12:15], byteorder='little')
            package_count = int.from_bytes(data[20:24], byteorder='little')
            if requested_user_id <= 100:
                conn.send(bytes.fromhex('1300000000000000000000000000000000000000' + package_count.to_bytes(4,
                                                                                                            byteorder='little').hex() + '0000000000000000'))  # Offline Response
            else:
                conn.send(bytes.fromhex('13000000acc5eed6000000000000000000000000' + package_count.to_bytes(4,
                                                                                                            byteorder='little').hex() + '000000000a000000'))  # Online Response
        elif data[0:4] == bytes.fromhex('18000000'):  # NET: STAT
            print("NET: STAT")
            package_count = int.from_bytes(data[20:24], byteorder='little')
            bytes_received = (12345).to_bytes(4, byteorder='little').hex()
            bytes_sent = (54321).to_bytes(4, byteorder='little').hex()
            player_online = (0).to_bytes(4, byteorder='little').hex()
            mil_seconds_online = (10602856).to_bytes(4, byteorder='little').hex()
            conn.send(bytes.fromhex('1800000000000000000000000000000000000000' + package_count.to_bytes(4,
                                                                                                        byteorder='little').hex() + '00000000 00000000' + mil_seconds_online + player_online + bytes_sent + bytes_received))
        elif data[0:4] == bytes.fromhex('21020000'):  # NET: RUSO
            print('NET: RUSO')
            package_count = int.from_bytes(data[20:24], byteorder='little')
            reply = '21020000' + echo_load + random.randint(1, 9999).to_bytes(4,byteorder='little').hex() + '01000a00' + package_count.to_bytes(4, byteorder='little').hex() + '0000000001000000'
            print("> " + reply)
            conn.send(bytes.fromhex(reply))
            conn.send(bytes.fromhex(
                '0900000000000000000000000000000000000000000000005600000000000000560000000100cccc1b0000003e00000000000000010000000c0000000100000000000000130000006164645f746f5f636f6e746163745f626f6f6ba40900000200000007000000313431312b31300200000000000000'))
        elif data[0:4] == bytes.fromhex('0f000000'):  # NET: UNIK
            package_count = int.from_bytes(data[20:24], byteorder='little')
            print('NET: UNIK')
            user_id = int.from_bytes(data[12:16], byteorder='little')
            username = 'wonbato'
            if user_id == 1337:
                username = 'ham5ter'
            if user_id == 123:
                username = 'herpidy'
            if user_id == 42:
                username = 'derpidy'
            reply = '0f000000' + echo_load + data[12:16].hex() + '0b000000' + package_count.to_bytes(4,byteorder='little').hex() + '290000000000000029000000' + data[12:16].hex() + '0b00cccc05000000050000000700000048617070794d65696c69' + username.encode(
                'latin-1').hex()
            print("> " + reply)
            conn.send(bytes.fromhex(reply))
        elif data[0:4] in [bytes.fromhex('1e000000'), bytes.fromhex('14000000'),
                           bytes.fromhex('1f000000')]:  # NET: WRIT
            print("ECHO---LOL")
            conn.send(data)
        else:
            print("# unknown # " + data.hex())
    conn.close()


if __name__ == '__main__':
    server_program()
