# task1_auth.py

import os
import json
import re
import time
import hashlib
import getpass

database_file = "users.json"


# -----------------------------
# Load Existing Users
# -----------------------------
def load_users():
    if os.path.exists(database_file):
        try:
            with open(database_file, "r") as file:
                return json.load(file)
        except:
            return {}
    return {}


# -----------------------------
# Save Users
# -----------------------------
def save_users(users):
    with open(database_file, "w") as file:
        json.dump(users, file, indent=4)


# -----------------------------
# Password Complexity Check
# -----------------------------
def password_valid(password):

    if len(password) < 12:
        return False

    if re.search(r"[0-9]", password) is None:
        return False

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password) is None:
        return False

    return True


# -----------------------------
# Hash Password Using Salt
# -----------------------------
def generate_hash(password, salt):

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000
    )

    return hashed.hex()


# -----------------------------
# Register User
# -----------------------------
def register_user():

    users = load_users()

    print("\n--- Register ---")

    username = input("Enter username: ").strip()

    if username == "":
        print("Username cannot be empty.")
        return

    if username in users:
        print("Username already exists.")
        return

    password = getpass.getpass("Enter password: ")

    if not password_valid(password):
        print("\nWeak Password")
        print("Rules:")
        print("- Minimum 12 characters")
        print("- At least one number")
        print("- At least one special symbol")
        return

    salt = os.urandom(16)

    final_hash = generate_hash(password, salt)

    users[username] = {
        "salt": salt.hex(),
        "password": final_hash
    }

    save_users(users)

    print("User registered successfully.")


# -----------------------------
# Login User
# -----------------------------
def login_user():

    users = load_users()

    print("\n--- Login ---")

    username = input("Enter username: ").strip()

    if username not in users:
        print("Invalid username.")
        time.sleep(2)
        return

    password = getpass.getpass("Enter password: ")

    stored_salt = bytes.fromhex(users[username]["salt"])
    stored_hash = users[username]["password"]

    entered_hash = generate_hash(password, stored_salt)

    if entered_hash == stored_hash:
        print("Login successful.")
    else:
        print("Incorrect password.")
        print("Please wait...")
        time.sleep(2)


# -----------------------------
# View Users (Optional Testing)
# -----------------------------
def show_users():

    users = load_users()

    if len(users) == 0:
        print("No users found.")
        return

    print("\nRegistered Users:")
    for user in users:
        print("-", user)


# -----------------------------
# Main Menu
# -----------------------------
def main():

    while True:

        print("\n===== Secure Authentication System =====")
        print("1. Register")
        print("2. Login")
        print("3. View Users")
        print("4. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            register_user()

        elif choice == "2":
            login_user()

        elif choice == "3":
            show_users()

        elif choice == "4":
            print("Program closed.")
            break

        else:
            print("Invalid choice. Try again.")


# -----------------------------
# Run Program
# -----------------------------
main()