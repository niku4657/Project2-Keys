"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Niharika Kunapuli, Kathleen Tran, Yifei Niu



"""

import socket
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import hashlib


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)

# #Added function to unpad message before decrypting
# def unpad_message(message):
#     return message[:-ord(message[len(message)-1:])]
def unpad_message(message):
    return message.rstrip()

# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    return os.urandom(16)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    public = RSA.importKey(open('ppkey.txt.pub','r').read())
    encrypt = str(public.encrypt(session_key, 32))
    return encrypt


# # Encrypts the message using AES. Same as server function
# def encrypt_message(message, session_key):
#     # TODO: Implement this function
#     message = pad_message(message)
#     iv = Random.new().read(16)
#     cipher = AES.new(session_key, AES.MODE_CBC, iv)
#     return base64.b64encode(cipher.encrypt(message))
#
#
# # Decrypts the message using AES. Same as server function
# def decrypt_message(message, session_key):
#     # TODO: Implement this function
#     iv = message[:16]
#     message = base64.b64decode(message)
#
#     cipher = AES.new(session_key, AES.MODE_CBC, iv)
#     return unpad_message(cipher.decrypt(message[16:])).decode('utf-8')


# def encrypt_message(message, session_key):
#     # TODO: Implement this function
#     message = pad_message(message)
#     # ivector = Random.new().read(16)
#     ivector = message
#     cipher = AES.new(session_key, AES.MODE_CBC, ivector)
#
#     return base64.b64encode(cipher.encrypt(message))
#
#
# # Decrypts the message using AES. Same as server function
# def decrypt_message(message, session_key):
#     # TODO: Implement this function
#     ivector = message
#     decode_message = base64.b64decode(message)
#     # ivector = Random.new().read(16)
#
#
#     cipher = AES.new(session_key, AES.MODE_CBC, ivector)
#
#     return unpad_message(cipher.decrypt(decode_message)).decode('utf-8')

# TODO: Write a function that decrypts a message using the session key

# def decrypt_message(client_message, session_key, ):
#
#
#     decoded_message = base64.b64decode(client_message)
#
#
#
#     cipher = AES.new(session_key, AES.MODE_ECB)
#
#     decrypted_message = cipher.decrypt(decoded_message)
#
#     return unpad_message(decrypted_message).decode('utf-8')
#
#
#
#
#
# # TODO: Encrypt a message using the session key
#
# def encrypt_message(message, session_key):
#
#     padded_message = pad_message(message)
#
#
#     cipher = AES.new(session_key, AES.MODE_ECB)
#
#     return base64.b64encode(cipher.encrypt(padded_message))

# def encrypt_message(message, session_key):
#     # TODO: Implement this function
#     # ivector = message[:16]
#     ivector = os.urandom(16)
#     message = pad_message(message)
#     # ivector = Random.new().read(16)
#
#     cipher = AES.new(session_key, AES.MODE_CBC, ivector)
#
#     return base64.b64encode(cipher.encrypt(message))
#
#
# # Decrypts the message using AES. Same as server function
# def decrypt_message(message, session_key):
#     # TODO: Implement this function
#     # ivector = message[:16]
#     decode_message = base64.b64decode(message)
#     # ivector = Random.new().read(16)
#     ivector = message[:16]
#
#     cipher = AES.new(session_key, AES.MODE_CBC, ivector)
#
#     return unpad_message(cipher.decrypt(decode_message)).decode('utf-8')


def encrypt_message(message,session_key):
    cipher = AES.new(session_key)
    return cipher.encrypt(pad_message(message))

def decrypt_message(message,session_key):
    cipher = AES.new(session_key)
    return cipher.decrypt(unpad_message(message))

# Sends a message over TCP
def send_message(sock, message):
    if type(message) != bytes:
        message = message.encode()
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data



def main():


    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        encrypted_message = encrypt_message(message, key)
        send_message(sock, encrypted_message)

        # TODO: Receive and decrypt response from server
        received_message = receive_message(sock)
        print(decrypt_message(received_message, key))

        # send_message(sock,"WIRESHARK".endcode())

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
