"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
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


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)

# Added function to unpad message before decrypting
def unpad_message(message):
    return message.rstrip()

# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    privatekey = RSA.importKey(open('ppkey.txt', 'r').read())
    encrypted_tuple = eval(session_key)
    return privatekey.decrypt(encrypted_tuple)


# Write a function that decrypts a message using the session key
# MODE_CBC = cipher block chaining
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    message = base64.b64decode(client_message)
    ivector = Random.new().read(16) #message[:16]
    cipher = AES.new(session_key, AES.MODE_CBC, ivector )
    d_message = cipher.decrypt(message)
    return unpad_message(d_message).decode('utf-8')


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    message = pad_message(message)
    ivector = Random.new().read(16)
    cipher = AES.new(session_key, AES.MODE_CBC, ivector)
    return base64.b64encode(ivector + cipher.encrypt(message))


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
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
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

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                original = decrypt_message(ciphertext_message, plaintext_key)

                # TODO: Split response from user into the username and password
                splitOriginal = original.splitlines(0)
                user = splitOriginal[0]
                password = splitOriginal[1]
                if verify_hash(user, password):
                    response = "User successfully authenticated!"
                else:
                    response = "Password or username incorrect"

                # TODO: Encrypt response to client
                response2client = encrypt_message(response, plaintext_key)#encrypted_key)

                # Send encrypted response
                send_message(connection, response2client)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
