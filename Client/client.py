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
from Crypto import Random
import base64
import hashlib


host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)

#Added function to unpad message before decrypting
def unpad_message(message):
    return message[:-ord(message[len(message)-1:])]

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


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function
    message = pad_message(message)
    iv = Random.new().read(16)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(message))


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    message = base64.b64decode(message)
    iv = message[:16]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return unpad_message(cipher.decrypt(message[16:])).decode('utf-8')


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    generate_key()
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
        encryptedMessage = encrypt_message(message, key)
        send_message(sock, em)

        # TODO: Receive and decrypt response from server
        if(receive_message(sock)):
            print("client received_message", decrypt_message(receive_message(sock), key))
     
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()