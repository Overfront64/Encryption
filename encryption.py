#!/usr/bin/env python

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key():
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend())

    userKey = base64.urlsafe_b64encode(kdf.derive(password))
    return userKey


def encrypt_details():
    service = str(input("Enter service name (Must be unique): "))
    serviceUserName = str(input("Enter service username: ")).encode()
    servicePassword = str(input("Enter service password: ")).encode()
    service2FA = str(input("Is 2 factor-authentication being used? (y/n): ")).lower()

    service2FA = True if service2FA in ("y", "yes", "t", "true") else False

    encryptedUserName = fernetKey.encrypt(serviceUserName).decode()
    encryptedPassword = fernetKey.encrypt(servicePassword).decode()

    with open(f"{username}.txt", "a") as userFile:
        userFile.write(f"{service},{encryptedUserName},{encryptedPassword},{service2FA},\n")


def decrypt_details():
    lookupName = str(input("Enter service to find: "))
    with open(f"{username}.txt", "r") as userFile:
        for line in userFile:
            if (lineArray := line.split(","))[0] == lookupName:
                print(f"Service {lineArray[0]} found")
                break
        else:
            print("Service not found")
            return

    lineArray[3] = "Enabled" if lineArray[3] == "True" else "Disabled"

    try:
        print(f"""
Username: {fernetKey.decrypt(lineArray[1].encode()).decode()}
Password: {fernetKey.decrypt(lineArray[2].encode()).decode()}
2 Factor Authentication: {lineArray[3]}""")

    except InvalidToken:
        print("Invalid key, unable to decrypt")


def decrypt_dump():
    with open(f"{username}.txt", "r") as userFile:
        dumpArray = [line.split(",") for line in userFile.readlines()]

    for service in dumpArray:
        service[3] = "Enabled" if service[3] == "True" else "Disabled"
        print(f"""
Service: {service[0]}
Username: {fernetKey.decrypt(service[1].encode()).decode()}
Password: {fernetKey.decrypt(service[2].encode()).decode()}
2 Factor Authentication: {service[3]}""")


def clear_console():
    os.system("cls")


if __name__ == "__main__":
    salt = b'\xff\x8b\xaa\xdf\xe0M\x93\x90\xe6\xcf\x9a\xd1w\x89\x0c\xe2'
    username = str(input("Enter username: "))
    password = str(input("Enter password: ")).encode()
    key = generate_key()
    fernetKey = Fernet(key)

    # ---------------- Menu ----------------
    while True:
        choice = int(input("""
---------------- MENU ----------------
1. Encrypt login details
2. Decrypt login details
3. Dump decrypted details
4. Clear console
5. Exit
Please select an option by its number: """))

        if choice == 1:
            encrypt_details()

        elif choice == 2:
            decrypt_details()

        elif choice == 3:
            decrypt_dump()

        elif choice == 4:
            clear_console()

        elif choice == 5:
            raise SystemExit
