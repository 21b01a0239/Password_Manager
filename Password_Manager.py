from cryptography.fernet import Fernet
import os
import re

def write_key():
    """Generate and save a new encryption key"""
    key = Fernet.generate_key()
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

def validate_password(pwd):
    """Validate password based on given requirements"""
    if len(pwd) > 8:
        print("Password must be at most 8 characters long.")
        return False
    if not re.search(r"[A-Z]", pwd):
        print("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", pwd):
        print("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[0-9]", pwd):
        print("Password must contain at least one number.")
        return False
    if not re.search(r"[@$!%*?&#^+=-_]", pwd):
        print("Password must contain at least one special character (@$!%*?&#^+=-_).")
        return False
    return True

def view():
    """View stored passwords (single account or all)"""
    if not os.path.exists('passwords.txt'):
        print("No passwords stored yet!")
        return
    
    search_user = input("Enter the account name (or type 'all' to view all): ").strip()
    if not search_user:
        print("Input cannot be empty!")
        return
    
    found = False
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            try:
                user, passw = data.split("|")
                decrypted_pass = fer.decrypt(passw.encode()).decode()
                
                if search_user.lower() == "all":  # Show all accounts
                    print("Account:", user, "| Password:", decrypted_pass)
                    found = True
                elif user.lower() == search_user.lower():  # Match single account
                    print("Account:", user, "| Password:", decrypted_pass)
                    found = True
            except Exception as e:
                print(f"Error reading entry: {data}")
    
    if not found:
        if search_user.lower() == "all":
            print("No accounts stored yet!")
        else:
            print(f"No password found for account: {search_user}")

def add():
    """Add a new password"""
    name = input('Account Name: ').strip()
    if not name:
        print("Account name cannot be empty!")
        return
        
    pwd = input("Password: ").strip()
    if not validate_password(pwd):  # Validate password
        return

    encrypted_pwd = fer.encrypt(pwd.encode()).decode()
    
    with open('passwords.txt', 'a') as f:
        f.write(f"{name}|{encrypted_pwd}\n")
    print("Password added successfully!")

def delete():
    """Delete password(s)"""
    if not os.path.exists('passwords.txt'):
        print("No passwords stored yet!")
        return

    target = input("Enter the account name to delete (or type 'all' to delete all): ").strip()
    if not target:
        print("Input cannot be empty!")
        return

    with open('passwords.txt', 'r') as f:
        lines = f.readlines()

    if target.lower() == "all":
        confirm = input("Are you sure you want to delete ALL accounts? (yes/no): ").strip().lower()
        if confirm == "yes":
            open('passwords.txt', 'w').close()  # Clear file
            print("All accounts deleted.")
        else:
            print("Deletion cancelled.")
        return

    new_lines = []
    deleted = False
    for line in lines:
        user, _ = line.rstrip().split("|")
        if user.lower() != target.lower():
            new_lines.append(line)
        else:
            deleted = True

    if deleted:
        with open('passwords.txt', 'w') as f:
            f.writelines(new_lines)
        print(f"Account '{target}' deleted successfully.")
    else:
        print(f"No account found with the name: {target}")

# Initialize encryption
key = load_key()
fer = Fernet(key)

def main():
    while True:
        print("\nPassword Manager")
        print("1. View passwords (view)")
        print("2. Add password (add)")
        print("3. Delete password (delete)")
        print("4. Quit (q)")
        
        mode = input("\nWhat would you like to do? ").lower().strip()
        
        if mode == "q":
            print("Goodbye!")
            break

        if mode == "view":
            view()
        elif mode == "add":
            add()
        elif mode == "delete":
            delete()
        else:
            print("Invalid mode. Please try again.")

if __name__ == "__main__":
    main()
