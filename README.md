# Password_Manager
A password manager that encrypts and stores passwords, generating a key if missing. Users can securely add or retrieve passwords by searching for an account. It ensures security by handling errors, preventing empty inputs, and offering a simple interface.

from cryptography.fernet import Fernet
import os

def write_key():
    """Generate and save a new encryption key"""
    key = Fernet.generate_key()  # Fixed: Changed from Password_director() to generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """Load the encryption key from file or create if not exists"""
    if not os.path.exists("key.key"):
        print("Key file not found! Generating a new key...")
        write_key()
    
    with open("key.key", "rb") as file:
        key = file.read()
    return key

def view():
    """View stored passwords"""
    if not os.path.exists('passwords.txt'):
        print("No passwords stored yet!")
        return
    
    search_user = input("Enter the account name to search for: ").strip()
    if not search_user:
        print("Account name cannot be empty!")
        return
        
    found = False
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            try:
                user, passw = data.split("|")
                if user.lower() == search_user.lower():
                    decrypted_pass = fer.decrypt(passw.encode()).decode()
                    print("Account:", user, "| Password:", decrypted_pass)
                    found = True
            except Exception as e:
                print(f"Error reading entry: {data}")
    
    if not found:
        print(f"No password found for account: {search_user}")

def add():
    """Add a new password"""
    name = input('Account Name: ').strip()
    if not name:
        print("Account name cannot be empty!")
        return
        
    pwd = input("Password: ").strip()
    if not pwd:
        print("Password cannot be empty!")
        return

    encrypted_pwd = fer.encrypt(pwd.encode()).decode()
    
    with open('passwords.txt', 'a') as f:
        f.write(f"{name}|{encrypted_pwd}\n")
    print("Password added successfully!")

# Initialize encryption
key = load_key()
fer = Fernet(key)

def main():
    while True:
        print("\nPassword Manager")
        print("1. View passwords (view)")
        print("2. Add password (add)")
        print("3. Quit (q)")
        
        mode = input("\nWhat would you like to do? ").lower().strip()
        
        if mode == "q":
            print("Goodbye!")
            break

        if mode == "view":
            view()
        elif mode == "add":
            add()
        else:
            print("Invalid mode. Please try again.")

if __name__ == "__main__":
    main()
