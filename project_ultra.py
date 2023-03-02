#!/usr/bin/env python3
#Symohn Alasa-as, Tevanah Charlemagne, Eric Deshield, Adrian Pineda
#Fullstack Academy Final Project
#Project Ultra
import sys
import hashlib
import base64
import tkinter as tk

class CaesarCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plain_text):
        cipher_text = ""

        for _ in plain_text:
            if _.isalpha():
                if _.isupper():
                    cipher_text += chr((ord(_) + self.key - 65) % 26 + 65)
                else:
                    cipher_text += chr((ord(_) + self.key - 97) % 26 + 97)
            elif _.isnumeric():
                cipher_text += chr((ord(_) + self.key - 48) % 10 + 48)
            else:
                cipher_text += _
        
        return cipher_text

    def decrypt(self, cipher_text):
        plain_text = ""

        for _ in cipher_text:
            if _.isalpha():
                if _.isupper():
                    plain_text += chr((ord(_) - self.key - 65) % 26 + 65)
                else:
                    plain_text += chr((ord(_) - self.key - 97) % 26 + 97)
            elif _.isnumeric():
                plain_text += chr((ord(_) - self.key - 48) % 10 + 48)
            else:
                plain_text += _
        
        return plain_text

    def decrypt_bf(self, cipher_text):
        possible_text = []

        for i in self.key:
            plain_text = ""

            for _ in cipher_text:
                if _.isalpha():
                    if _.isupper():
                        plain_text += chr((ord(_) - i - 65) % 26 + 65)
                    else:
                        plain_text += chr((ord(_) - i - 97) % 26 + 97)
                elif _.isnumeric():
                    plain_text += chr((ord(_) - i - 48) % 10 + 48)
                else:
                    plain_text += _
                
            possible_text.append((plain_text, i))
        
        return possible_text

def caesar():
    options = [1, 2, 3,4]
    keys = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]

    banner = """
       _________    ___________ ___    ____ 
      / ____/   |  / ____/ ___//   |  / __ \\
     / /   / /| | / __/  \__ \/ /| | / /_/ /
    / /___/ ___ |/ /___ ___/ / ___ |/ _, _/ 
    \____/_/  |_/_____//____/_/  |_/_/ |_|   
    """
    print(banner)

    while True:
        print("\nCaesar Cipher Algorithm Options:")
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Brute Force Decryption")
        print("4. Enter 4 to exit tool")

        while True:
            try:
                option = int(input("\nEnter Number to Select Option: "))
                while option not in options:
                    option = int(input("Invalid Entry! Enter options '1', '2', '3', '4': "))
                break
            except ValueError:
                print("Invalid input! Please enter a valid integer.")

        if option == 4:
            return

        try:
            user_input = input("Enter MESSAGE to encrypt/decrypt: ")
        except:
            print("An Error occurred processing input.")
        
        if option == 1 or option == 2:
            while True:
                try:
                    key = int(input("\nEnter encryption/decryption KEY value: "))
                    while key not in keys:
                        key = int(input("Invalid Entry! Enter a key value between 1 and 25."))
                    break
                except ValueError:
                    print("Invalid input! Please enter a valid integer.")
            
            cipher = CaesarCipher(key)
            
            if option == 1:
                result = cipher.encrypt(user_input)
            else:
                result = cipher.decrypt(user_input)

            print(f"\nMessage: {user_input}, Key: {key}")
            print("Processing.....................")
            print(f"\n{user_input} ==> {result}")

        elif option == 3:
            cipher = CaesarCipher(keys)
            result = cipher.decrypt_bf(user_input)

            mid_column = max(len(str(_[0])) for _ in result)
            print(f"\n{'Key':<3}\t{'Text':<{mid_column}}")
            for i in range(len(result)):
                print(f"{result[i][1]:<3}\t{result[i][0]:<{mid_column}}")
        else:
            return
        
def hashes():
    options = [1,2,3]

    print(".---.  .---.    ____       .-'''-. .---.  .---.         .---.  .---.    ____     _______  .-./`)  _______  .-./`  ")
    print("|   |  |_ _|  .'  __ `.   / _     \|   |  |_ _|         |   |  |_ _|  .'  __ `. \  ____  \\ .-.')\  ____  \\ .-.') ")
    print("|   |  ( ' ) /   '  \  \ (`' )/`--'|   |  ( ' )         |   |  ( ' ) /   '  \  \| |    \ |/ `-' \| |    \ |/ `-' \ ")
    print("|   '-(_{;}_)|___|  /  |(_ o _).   |   '-(_{;}_)        |   '-(_{;}_)|___|  /  || |____/ / `-'`\"\"| |____/ / `-'`\"\" ")
    print("|      (_,_)    _.-`   | (_,_). '. |      (_,_)         |      (_,_)    _.-`   ||   _ _ '. .---. |   _ _ '. .---.  ")
    print("| _ _--.   | .'   _    |.---.  \  :| _ _--.   |         | _ _--.   | .'   _    ||  ( ' )  \|   | |  ( ' )  \|   |  ")
    print("|( ' ) |   | |  _( )_  |\    `-'  ||( ' ) |   |         |( ' ) |   | |  _( )_  || (_{;}_) ||   | | (_{;}_) ||   |  ")
    print("|_{;}_)|   | \ (_ o _) / \       / |_{;}_)|   |         |_{;}_)|   | \ (_ o _) /|  (_,_)  /|   | |  (_,_)  /|   |  ")
    print("|(_,_) '---'  '.(_,_).'   `-...-'  '(_,_) '---'         '(_,_) '---'  '.(_,_).' /_______.' '---' /_______.' '---'  ")

    while True:
        print("Select an option:")
        print("1. Identify a hash")
        print("2. Generate a hash")
        print("3. Enter 3 to exit tool")

        while True:
            try:
                option = int(input("\nEnter Number to Select Option: "))
                while option not in options:
                    option = int(input("Invalid Entry! Enter options '1', '2', '3': "))
                break
            except ValueError:
                print("Invalid input! Please enter a valid integer.")
        
        if option == 1:
            identify_hash()
        elif option == 2:
            generate_hash()
        else:
            return

def identify_hash():
        hash_input = input("Enter a Hash to Identify: ")
        if check_hash(hash_input, hashlib.md5):
            print(f"Hash Type: MD5, {hash_input}")
        elif check_hash(hash_input, hashlib.sha1):
            print(f"Hash Type: SHA1, {hash_input}")
        elif check_hash(hash_input, hashlib.sha256):
            print(f"Hash Type: SHA256, {hash_input}")
        else:
            print(f"Hash Type Unknown: {hash_input}")

def check_hash(hash, type):
    if len(hash) != type().digest_size * 2:
        return False
    
    try:
        int(hash, 16)
    except ValueError:
        return False

    return True

def generate_hash():
    hashes = [1,2,3,4]

    while True:
        print("\nSelect a hash algorithm:")
        print("1. MD5")
        print("2. SHA1")
        print("3. SHA256")
        print("4. Enter 4 to exit tool")

        while True:
            try:
                option = int(input("\nEnter Number to Select Hash Type: "))
                while option not in hashes:
                    option = int(input("Invalid Entry! Enter options '1', '2', '3', '4': "))
                break
            except ValueError:
                print("Invalid input! Please enter a valid integer.")
        
        if option == 4:
            return

        message = input("Enter a Value to Hash: ")
        
        if option == 1:
            hash_algo = hashlib.md5
            result = hash_converter(message, hash_algo)
            print(f"MD5, {message}:\n{result}")
        elif option == 2:
            hash_algo = hashlib.sha1
            result = hash_converter(message, hash_algo)
            print(f"SHA1, {message}:\n{result}")
        elif option == 3:
            hash_algo = hashlib.sha256
            result = hash_converter(message, hash_algo)
            print(f"SHA256, {message}:\n{result}")
        else:
            return

def hash_converter(m, ha):
    hash_obj = ha()
    hash_obj.update(m.encode())
    return hash_obj.hexdigest()

class EncoderDecoder:
    def __init__(self, message):
        self.message = message

    def base64_encode(self):
        message_bytes = self.message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def base64_decode(self):
        base64_bytes = self.message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        decoded = message_bytes.decode('ascii')
        return decoded
    
    def binary_encode(self):
        return ''.join(format(ord(c), '08b') for c in self.message)
    
    def binary_decode(self):
        bytes_list = [self.message[i:i+8] for i in range(0, len(self.message), 8)]
        int_list = [int(byte, 2) for byte in bytes_list]
        char_list = [chr(num) for num in int_list]
        original_str = ''.join(char_list)
        return original_str

def encoding():
    encoding_types = [1,2,3,4,5]

    banner = """
     _____ _   _  ____ ___  ____  _____ ____      ______  _____ ____ ___  ____  _____ ____  
    | ____| \ | |/ ___/ _ \|  _ \| ____|  _ \    / /  _ \| ____/ ___/ _ \|  _ \| ____|  _ \ 
    |  _| |  \| | |  | | | | | | |  _| | |_) |  / /| | | |  _|| |  | | | | | | |  _| | |_) |
    | |___| |\  | |__| |_| | |_| | |___|  _ <  / / | |_| | |__| |__| |_| | |_| | |___|  _ < 
    |_____|_| \_|\____\___/|____/|_____|_| \_\/_/  |____/|_____\____\___/|____/|_____|_| \_\
    """
    print(banner)

    while True:
        print("\nSelect Option:")
        print("1. Encode Base64")
        print("2. Decode Base64")
        print("3. Encode Binary")
        print("4. Decode Binary")
        print("5. Enter 5 to exit tool")

        while True:
            try:
                option = int(input("\nEnter Number to Select Option: "))
                while option not in encoding_types:
                    option = int(input("Invalid Entry! Enter options '1', '2', '3', '4', or '5': "))
                break
            except ValueError:
                print("Invalid input! Please enter a valid integer.")

        if option == 5:
            return

        try:
            message = input("Enter MESSAGE to encode/decode: ")
        except:
            print("An Error occurred processing input.")
        
        code = EncoderDecoder(message)
        
        if option == 1:
            result = code.base64_encode()
            print(f"Input: {message} ==> Base64: {result}")
        elif option == 2:
            result = code.base64_decode()
            print(f"Base 64: {message} ==> Decoded Base64: {result}")
        elif option == 3:
            result = code.binary_encode()
            print(f"Input: {message} ==> Binary: {result}")
        elif option == 4:
            result = code.binary_decode()
            print(f"Binary: {message} ==> Decoded Binary: {result}")
        else:
            return

def generate_hashes(input_text, md5_output, sha1_output, sha256_output, base64_output):
    # Generate the MD5
    md5_hash = hashlib.md5(input_text.encode()).hexdigest()
    md5_output.config(text=md5_hash)

    # Generate the SHA-1
    sha1_hash = hashlib.sha1(input_text.encode()).hexdigest()
    sha1_output.config(text=sha1_hash)

    # Generate the SHA-256
    sha256_hash = hashlib.sha256(input_text.encode()).hexdigest()
    sha256_output.config(text=sha256_hash)

    # Generate the Base64
    base64_encoded = base64.b64encode(input_text.encode()).decode()
    base64_output.config(text=base64_encoded)

    # Change color of hash
    md5_output.config(fg='blue')
    sha1_output.config(fg='green')
    sha256_output.config(fg='purple')
    base64_output.config(fg='orange')

def gui():
    # Create the main window
    window = tk.Tk()
    window.title("Hash Generator and Base64 Encoder")
    window.geometry("500x350")

    # Create the input field and label
    input_label = tk.Label(window, text="Input text:")
    input_label.pack()
    input_field = tk.Entry(window)
    input_field.pack()

    # Create the buttons for generating the hashes
    generate_button = tk.Button(window, text="Generate Hashes and Encode", 
                                command=lambda: generate_hashes(input_field.get(), 
                                                                md5_output, 
                                                                sha1_output, 
                                                                sha256_output, 
                                                                base64_output))
    generate_button.pack()

    # Create the labels for displaying the hashes and the Ceaser Cipher
    md5_label = tk.Label(window, text="MD5 Hash:")
    md5_label.pack()
    md5_output = tk.Label(window, text="")
    md5_output.pack()

    sha1_label = tk.Label(window, text="SHA-1 Hash:")
    sha1_label.pack()
    sha1_output = tk.Label(window, text="")
    sha1_output.pack()

    sha256_label = tk.Label(window, text="SHA-256 Hash:")
    sha256_label.pack()
    sha256_output = tk.Label(window, text="")
    sha256_output.pack()

    base64_label = tk.Label(window, text="Base64 Encoding of Input:")
    base64_label.pack()
    base64_output = tk.Label(window, text="")
    base64_output.pack()

    # Run the GUI main loop
    window.mainloop()

def main(argv):
    tools = [1,2,3,4,5]

    banner = """
     _   _ _   _____ ____      _    
    | | | | | |_   _|  _ \    / \   
    | | | | |   | | | |_) |  / _ \  
    | |_| | |___| | |  _ <  / ___ \ 
     \___/|_____|_| |_| \_\/_/   \_\
    """
    print(banner)

    while True:
        print("This is a multi-functional tool. Follow prompts to utilize the proper functions.")
        print("Select tool: ")
        print("1. Hash Generator/Identifier")
        print("2. Encoding/Decoding Methods")
        print("3. Hashing w/ Graphical User Interface")
        print("4. Caesar Cipher Encrypter/Decrypter and Brute Force Decrypter")
        print("5. Enter 5 to quit")

        while True:
            try:
                option = int(input("\nEnter a Number to Select Tool: "))
                while option not in tools:
                    option = int(input("Invalid Entry! Enter options '1', '2', '3', '4', or '5': "))
                break
            except ValueError:
                print("Invalid input! Please enter a valid integer.")
        
        if option == 1:
            hashes()
        elif option == 2:
            encoding()
        elif option == 3:
            gui()
        elif option == 4:
            caesar()
        else:
            break


if __name__ == "__main__":
    main(sys.argv[1:])
