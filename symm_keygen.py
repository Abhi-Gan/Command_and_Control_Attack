import os

def generate_key():
    symmetric_key = os.urandom(32)
    with open("symm_key.txt", "wb") as f:
        hex_key = bytes(symmetric_key).hex()
        f.write(hex_key)

if __name__ == '__main__':
    generate_key()