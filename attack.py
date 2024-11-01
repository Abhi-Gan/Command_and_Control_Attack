# listen for incoming connections
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

# '0.0.0.0' # listen to incoming connections from anywhere
# '192.168.x.x' # listen to only within same LAN
# 'localhost' # on same machine
# LISTEN_IP = '0.0.0.0'
# LISTEN_PORT = 5050
# read in config vars
with open("server_config.json") as config_f:
    config = json.load(config_f)

LISTEN_IP = config['LISTEN_IP']
LISTEN_PORT = config['LISTEN_PORT']


def read_key(key_fpath):
    with open(key_fpath, 'r') as key_f:
        hex_key = key_f.read()
        symm_key = bytes.fromhex(hex_key)
    return symm_key

def get_encrypted_msg(symmetric_key, msg: str):
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    msg_bytes = msg.encode()
    ct = aesgcm.encrypt(nonce=nonce, 
                        data=msg_bytes,
                        associated_data=None)
    return nonce + ct

def decrypt_ct(symmetric_key, msg_ct):

    try:
        # we are given nonce + ct
        nonce_length = 12
        nonce = msg_ct[:nonce_length]
        ct = msg_ct[nonce_length:]
        # decrypt
        aesgcm = AESGCM(symmetric_key)
        dec_msg_bytes = aesgcm.decrypt(nonce=nonce,
                    data=ct,
                    associated_data=None)
        dec_msg = dec_msg_bytes.decode()
        return dec_msg
    except Exception as e:
        error_msg = f"Error: Received bad message. Client likely has incorrect key!"
        return error_msg


# def receive_msg(connection, buffer_size=1024):
#     print(f"received message from {connection.getsockname()}")
#     # receive message from server
#     # load in in chunks of buffer size
#     buffer_size = 1024
#     in_msg_list = []
#     while True:
#         msg_part = connection.recv(buffer_size)
#         print(msg_part)
#         if not msg_part:
#             break
#         else:
#             in_msg_list.append(msg_part)
#     full_msg = b"".join(in_msg_list)
#     return full_msg

def send_msg(connection, out_bytes):
    # first send message length
    msg_len = len(out_bytes)
    connection.send(msg_len.to_bytes(8, 'big'))
    # then send message
    connection.send(out_bytes)

def receive_msg(connection, buffer_size=1024):
    # first receive msg length
    len_data = connection.recv(8)
    if not len_data:
        return b"" # no length received
    
    in_msg_len = int.from_bytes(len_data, "big")

    # receive message
    bytes_received = 0
    in_msg_list = []
    while bytes_received < in_msg_len:
        bytes_to_receive = min(buffer_size, in_msg_len - bytes_received)
        msg_part = connection.recv(bytes_to_receive)
        if not msg_part:
            break # connection closed prematurely
        else:
            in_msg_list.append(msg_part)
            bytes_received += len(msg_part)
            
    full_msg = b"".join(in_msg_list)
    return full_msg

def run_server(ip, port):
    print(f"server running :{port} <- {ip}")
    host = ip  # socket.gethostname()
    # create socket
    server_socket = socket.socket() # socket.AF_INET, socket.SOCK_STREAM
    # bind socket to (host, port)
    server_socket.bind((host, port))
    # listen for incoming connection (only 1)
    server_socket.listen(5)

    while True:
        # accept connection
        conn, address = server_socket.accept()
        print(f"accepted conn from {address}")

        # read code to run on target
        with open("run_on_target.sh", 'r') as file:
            message = file.read()
            
        # read private key
        symm_key = read_key("symm_key.txt")

        encrypted_msg = get_encrypted_msg(symmetric_key=symm_key,
                                          msg=message)
        # send msg to target
        send_msg(
            connection=conn,
            out_bytes=encrypted_msg,
            )

        # receive output from running code on client side
        output_ct = receive_msg(
            connection=conn,
            buffer_size=1024
        )

        script_output = decrypt_ct(
            symmetric_key=symm_key,
            msg_ct=output_ct
        )

        # write out output
        script_fname = "script_output.txt"
        with open(script_fname, "w") as f:
            f.write(script_output)

        # close connection
        conn.close()        

if __name__ == '__main__':
    run_server(LISTEN_IP, LISTEN_PORT)