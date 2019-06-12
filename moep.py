import asyncio
import random

player_database = {
    'ham5ter': {'id': 1337, 'password': "herpderp"},
    'testuser': {'id': 42, 'password': "hurrdurr"},
    'nac9tar': {'id': 364, 'password': "hurrdurr"}
}

connected_clients = {}

echo_load = '40524b28eb000000'
user_id = (1337).to_bytes(4, byteorder='little').hex()

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



def forward(writer, addr, message):
    for w in connected_clients:
        if w != writer:
            w.write(f"{addr!r}: {message!r}\n".encode())


async def handle(reader, writer):
    addr = writer.get_extra_info('peername')
    message = f"{addr!r} is connected !!!!"
    print(message)
    forward(writer, addr, message)
    while True:
        try:
            data = await reader.read(1024)
            if data:
                print("< " + data.hex())
            if data[0:4] == bytes.fromhex('25000000'):
                package_count = int.from_bytes(data[20:24], byteorder='little')
                username_len = int.from_bytes(data[44:47], byteorder='little') - 1
                password_len = int.from_bytes(data[48:52], byteorder='little') - 1
                username = data[52:52 + username_len].decode('latin-1')
                password = data[52 + username_len + 1:52 + username_len + 1 + password_len].decode('latin-1')
                print("login request received!")
                print("username %s , password %s" % (username, password))
                if username in player_database:
                    if player_database[username]['password'] == password:
                        writer.write(bytes.fromhex(_return_succesfull_login(package_count=package_count)))
                        client_user_id = player_database[username]['id']
                        connected_clients[client_user_id] = (writer)
                        print(f'{connected_clients}')
                else:
                    writer.write(bytes.fromhex(_return_failed_login(package_count=package_count)))
                    writer.close()
                    break
            elif data[0:4] == bytes.fromhex('13000000'):  # NET: ULIN
                print("NET: ULIN")
                requested_user_id = int.from_bytes(data[12:15], byteorder='little')
                package_count = int.from_bytes(data[20:24], byteorder='little')
                if requested_user_id in connected_clients:
                    writer.write(bytes.fromhex('13000000acc5eed6000000000000000000000000' + package_count.to_bytes(4,                                                                                byteorder='little').hex() + '0000000000000000'))  # Offline Response
                else:
                    writer.write(bytes.fromhex('1300000000000000000000000000000000000000' + package_count.to_bytes(4,                                                                                                                          byteorder='little').hex() + '0000000000000000'))
            elif data[0:4] == bytes.fromhex('21020000'):  # NET: RUSO
                random_online_user_id = random.choice(list(connected_clients)).to_bytes(4,byteorder="little").hex()
                reply = f'21020000{echo_load}{random_online_user_id}01000a00{data[20:24].hex()}0000000001000000'
                writer.write(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex('0f000000'):  # NET: UNIK
                request_user_id = int.from_bytes(data[12:16], byteorder='little')
                username = None
                for user in player_database:
                    if player_database[user]['id'] == request_user_id:
                        username = user
                        break
                if username:
                    reply = f'0f000000{echo_load}{data[12:16].hex()}0b000000{data[20:24].hex()}290000000000000029000000{data[12:16].hex()}0b00cccc05000000050000000700000048617070794d65696c69{username.encode("latin-1").hex()}'
                writer.write(bytes.fromhex(reply))
            elif data[0:4] == bytes.fromhex('18000000'):  # NET: STAT
                package_count = int.from_bytes(data[20:24], byteorder='little')
                bytes_received = (12345).to_bytes(4, byteorder='little').hex()
                bytes_sent = (54321).to_bytes(4, byteorder='little').hex()
                player_online = (len(connected_clients)).to_bytes(4, byteorder='little').hex()
                mil_seconds_online = (10602856).to_bytes(4, byteorder='little').hex()
                writer.write(bytes.fromhex('1800000000000000000000000000000000000000' + package_count.to_bytes(4,
                                                                                                            byteorder='little').hex() + '00000000 00000000' + mil_seconds_online + player_online + bytes_sent + bytes_received))
            await writer.drain()
        except ConnectionResetError as connection_reset_error:
            print(f"Connection Reset: {addr} {connection_reset_error}")
            break
    try:
        client_user_id_to_delete = None
        for client_user_id, client_writer in connected_clients.items():
            if client_writer == writer:
                client_user_id_to_delete = client_user_id
                break
        if client_user_id_to_delete:
            del connected_clients[client_user_id_to_delete]
            print(f'deleted: {client_user_id_to_delete}')
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(
        handle, '127.0.0.1', 1337)
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')
    async with server:
        await server.serve_forever()

asyncio.run(main())
