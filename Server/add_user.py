"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""
import hashlib
from Crpto import Random



user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password
# salt = Kathleen implemented this
# hashed_password = Kathleen created this
salt = str(random.get_random_bytes(32))#salt()
hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()


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
