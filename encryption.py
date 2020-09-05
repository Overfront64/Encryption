#!/usr/bin/env python3

import base64
import os
import random
import string

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key():
    if os.path.exists(f"User Files/{username}.salt"):
        with open(f"User Files/{username}.salt", "rb") as saltFile:
            salt = saltFile.read()
    else:
        with open(f"User Files/{username}.salt", "wb") as saltFile:
            salt = os.urandom(64)
            saltFile.write(salt)

    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend())

    return Fernet(base64.urlsafe_b64encode(kdf.derive(password)))


def encrypt_details(service="", generated_password=""):
    if service == "":
        service = str(input("Enter service name (Must be unique): "))

    serviceUserName = str(input("Enter service username: ")).encode()

    if generated_password != "":
        servicePassword = generated_password.encode()
    else:
        servicePassword = str(input("Enter service password: ")).encode()

    service2FA = str(input("Is 2 factor-authentication being used? (y/n): ")).lower()
    service2FA = True if service2FA in ("y", "yes", "t", "true") else False

    encryptedUserName = fernetKey.encrypt(serviceUserName).decode()
    encryptedPassword = fernetKey.encrypt(servicePassword).decode()

    with open(f"User Files/{username}.txt", "a") as userFile:
        userFile.write(f"{service},{encryptedUserName},{encryptedPassword},{service2FA},\n")


def gen_password(service="", to_encrypt=""):
    characters = string.ascii_letters + string.digits + string.punctuation
    length = int(input("Enter length of password (recommended 12): "))
    password_gen = "".join(random.choice(characters) for i in range(length))

    print(f"Your generated password: {password_gen}")

    if to_encrypt == "":
        to_encrypt = str(input("Would you like to use this for a service? (y/n): ")).lower()

    if to_encrypt in ("y", "yes", "t", "true"):
        encrypt_details(service, password_gen)


def decrypt_details():
    try:
        with open(f"User Files/{username}.txt", "r") as userFile:
            lookupName = str(input("Enter service to find: "))
            for line in userFile:
                if (lineArray := line.split(","))[0] == lookupName:
                    print(f"Service {lineArray[0]} found")
                    lineArray[3] = "Enabled" if lineArray[3] == "True" else "Disabled"
                    break
            else:
                print("Service not found")
                return

    except FileNotFoundError:
        print("The folder or folder containing details does not exist. Please encrypt details first. ")
        return

    try:
        print(f"""
Username: {fernetKey.decrypt(lineArray[1].encode()).decode()}
Password: {fernetKey.decrypt(lineArray[2].encode()).decode()}
2 Factor Authentication: {lineArray[3]}""")

    except InvalidToken:
        print("Invalid key, unable to decrypt")


def decrypt_dump():
    try:
        with open(f"User Files/{username}.txt", "r") as userFile:
            dumpArray = [line.split(",") for line in userFile.readlines()]
            dumpArray = sorted(dumpArray)

        for service in dumpArray:
            service[3] = "Enabled" if service[3] == "True" else "Disabled"

            try:
                print(f"""
Service: {service[0]}
Username: {fernetKey.decrypt(service[1].encode()).decode()}
Password: {fernetKey.decrypt(service[2].encode()).decode()}
2 Factor Authentication: {service[3]}""")

            except InvalidToken:
                print("Invalid key, unable to decrypt")
                return
    except FileNotFoundError:
        print("The folder or folder containing details does not exist. Please encrypt details first. ")
        return


def delete_service(to_delete=""):
    if to_delete == "":
        to_delete = str(input("What service are you deleting? "))
        toReturn = True
    else:
        toReturn = False

    try:
        with open(f"User Files/{username}.txt", "r") as userFile:
            serviceList = [line.split(",") for line in userFile.readlines()]

    except FileNotFoundError:
        print("The folder or folder containing details does not exist. Please encrypt details first. ")
        return

    for pos, service in enumerate(serviceList):
        if service[0] == to_delete:
            del serviceList[pos]
            break
    else:
        print("Service not found")
        return

    with open(f"User Files/{username}.txt", "w") as userFile:
        for service in serviceList:
            userFile.write(f"{service[0]},{service[1]},{service[2]},{service[3]},\n")

    if toReturn:
        print(f"Deleted service {to_delete}")


def replace_details():
    toReplaceName = str(input("What service are you updating? "))
    delete_service(toReplaceName)

    genChoice = str(input("Would you like to use a generated password? ")).lower()
    if genChoice in ("y", "yes", "t", "true"):
        gen_password(toReplaceName, "y")
    else:
        encrypt_details(service=toReplaceName)

    print(f"Details for {toReplaceName} have been updated")


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":
    if not os.path.exists("User Files"):
        os.mkdir("User Files")
    username = str(input("Enter username: "))
    password = str(input("Enter password: ")).encode()
    fernetKey = generate_key()
    del password

    # ---------------- Menu ----------------
    while True:
        choice = int(input("""
---------------- MENU ----------------
1. Encrypt login details
2. Generate password
3. Decrypt login details
4. Dump decrypted details
5. Replace details
6. Delete details
7. Clear console (only if ran from terminal)
8. Exit
Please select an option by its number: """))

        if choice == 1:
            encrypt_details()

        elif choice == 2:
            gen_password()

        elif choice == 3:
            decrypt_details()

        elif choice == 4:
            decrypt_dump()

        elif choice == 5:
            replace_details()

        elif choice == 6:
            delete_service()

        elif choice == 7:
            clear_console()

        elif choice == 8:
            raise SystemExit
