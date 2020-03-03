"""

    add_user.py - Stores a new username along with salt/password



    CSCI 3403

    Authors: Matt Niemiec and Abigail Fernandes

    The solution contains the same number of lines (plus imports)

"""

from Crypto import Random
from Crypto.Hash import SHA256
import sys
import os

user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password
salt = str(Random.get_random_bytes(32))
password_and_salt = password+salt
hashed_password = SHA256.new(str.encode(password_and_salt)).hexdigest()

# print(os.path.join(sys.path[0], "passfile.txt"))

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass
with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")
