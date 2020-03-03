"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
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

iv = "G4XO4L\X<J;MPPLD"

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

# TODO: Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    private_key = RSA.importKey(open('ppkey.txt', 'r').read())
    encrypted_tuple = eval(session_key)
    return private_key.decrypt(encrypted_tuple)

# TODO: Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    decoded_message = base64.b64decode(client_message)

    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(decoded_message)
    return unpad_message(decrypted_message).decode('utf-8')


# TODO: Encrypt a message using the session key
def encrypt_message(message, session_key):
    padded_message = pad_message(message)

    # MODE_CBC = cipher block chaining
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(padded_message))


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                salt_string = line[1]
                hashed_password = hashlib.sha512((password + salt_string).encode()).hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive public-key encrypted aes-key from client
                encrypted_aes_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_aes_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # Decrypt message from client
                plaintext_message = decrypt_message(ciphertext_message, plaintext_key)

                # Split response from user into the username and password
                user, password = plaintext_message.split()
                if verify_hash(user, password):
                    plaintext_response = "User successfully authenticated!"
                else:
                    plaintext_response = "Password or username incorrect"
                # Encrypt response to client
                ciphertext_response = encrypt_message(plaintext_response, plaintext_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()

if __name__ in "__main__":
    main()
