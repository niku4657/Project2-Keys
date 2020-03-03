"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""
import base64
import hashlib
import hashlib
import os
import socket
import uuid
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
import string
import random

letters = string.ascii_lowercase + string.digits
iv = ''.join(random.choice(letters) for i in range(16))
host = "localhost"
port = 10001


# Pads message with enough space to make its length a multiple of 16
def pad_message(message):
    addOn = " "*((16-len(message))%16)
    return message+addOn

# removes spaces from the end (see pad_message description)
# however, if message intentionally had spaces at the end ... tough
def unpad_message(m):
	return m.rstrip()

# TODO: Generate a random AES key
# done
def generate_key():
    return os.urandom(16)


# TODO: Takes an AES session key and encrypts it using the server's
# TODO: public key and returns the value
def encrypt_handshake(session_key):
    # ALL of id_rsa.pub is the public key
    pubRSAKey = RSA.importKey(open('ppkey.txt.pub','r').read())
    encrypted_key = str(pubRSAKey.encrypt(session_key, 32))
    return encrypted_key

# TODO: Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
	padded_message = pad_message(message)

	# MODE_CBC = cipher block chaining
	cipher = AES.new(session_key, AES.MODE_CBC, iv)
	return base64.b64encode(cipher.encrypt(padded_message))


# TODO: Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    decoded_message = base64.b64decode(message)

    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(decoded_message)
    return unpad_message(decrypted_message).decode('utf-8')

# Sends a message over TCP
def send_message(sock, message):
    if not message:
        print("Can't send empty string")
        return
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

        # TODO: Generate random AES key
        aes_key = generate_key()

        # TODO: Encrypt the session key using server's public key
        encrypted_session_key = encrypt_handshake(aes_key)

        # encrypting user info using aes key
       	encrypted_message = encrypt_message(message, aes_key)

        # TODO: Initiate handshake
        send_message(sock, encrypted_session_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        send_message(sock, encrypted_message)

        # TODO: Receive and decrypt response from server and print
        # should be getting back encrypted aes key
        received_message = receive_message(sock)
        if received_message:
            print("client received_message", decrypt_message(received_message, aes_key))

    finally:
        print('closing socket')
        sock.close()

if __name__ in "__main__":
    main()
