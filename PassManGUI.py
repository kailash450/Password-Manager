# -*- coding: utf-8 -*-
"""
Created on Fri Mar 22 22:11:51 2024

@author: Kailash
"""
import tkinter as tk
from tkinter import messagebox,simpledialog,ttk
from cryptography.fernet import Fernet
import os
import base64
import string
import secrets
    
# Function to generate encryption key
def generate_key():
    return Fernet.generate_key()

# Function to save key to file
def save_key_to_file(key, file_path):
    with open(file_path, 'wb') as file:
        file.write(key)

# Function to load key from file
def load_key_from_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            return file.read()
    else:
        key = generate_key()
        save_key_to_file(key, file_path)
        return key

# Encrypt password
def encrypt_password(key, password):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt password
def decrypt_password(key, encrypted_password):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password)
    return decrypted_password.decode()

# Read passwords from file
def read_passwords_from_file(file_path, key):
    passwords = {}
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            data = file.read()
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(data)
            lines = decrypted_data.decode().split('\n')
            for line in lines:
                if line:
                    category, encrypted_password = line.strip().split(':')
                    passwords[category] = encrypted_password
    return passwords

# Write passwords to file
def write_passwords_to_file(file_path, key, passwords):
    with open(file_path, 'wb') as file:
        data = '\n'.join([f"{category}:{encrypted_password}" for category, encrypted_password in passwords.items()])
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        file.write(encrypted_data)

# Generate random password
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

# Main GUI class
class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.key_file = 'encryption_key.key'
        self.passwords_file = 'passwords.txt'
        self.key = load_key_from_file(self.key_file)
        self.passwords = read_passwords_from_file(self.passwords_file, self.key)

        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self.master, text="Password Manager")
        self.label.pack()

        self.generate_button = tk.Button(self.master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack()

        self.add_button = tk.Button(self.master, text="Add Password", command=self.add_password)
        self.add_button.pack()

        self.retrieve_button = tk.Button(self.master, text="Retrieve Password", command=self.retrieve_password_dialog)
        self.retrieve_button.pack()

        self.list_button = tk.Button(self.master, text="List Categories", command=self.list_categories)
        self.list_button.pack()

        self.exit_button = tk.Button(self.master, text="Exit", command=self.exit_program)
        self.exit_button.pack()
    
    def copy_clip(self,password):
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        self.master.update()
        
    def generate_password(self):
        length = 12
        password = generate_password(length)
        messagebox.showinfo("Generated Password", f"Generated Password: {password}")
        self.copy_clip(password)
        
    def add_password(self):
        category = simpledialog.askstring("Input", "Enter category:")
        if category:
            password = simpledialog.askstring("Input", "Enter password:", show='*')
            if password:
                encrypted_password = encrypt_password(self.key, password)
                self.passwords[category] = base64.urlsafe_b64encode(encrypted_password).decode()
                write_passwords_to_file(self.passwords_file, self.key, self.passwords)
                messagebox.showinfo("Success", "Password added successfully!")
    
    def retrieve_password_dialog(self):
        if self.passwords:
            RetrieveDialog(self.master, self.key, self.passwords, self.copy_clip)
        else:
            messagebox.showerror("Error", "No passwords found.")

    def list_categories(self):
        categories = list(self.passwords.keys())
        messagebox.showinfo("Categories", f"Categories: {categories}")

    def exit_program(self):
        self.master.destroy()
        
class RetrieveDialog(tk.Toplevel):
    def __init__(self, master,key,passwords,copy_clip):
        super().__init__(master)
        self.title("Retrieve Password")
        self.geometry("300x150")

        self.key=key        
        self.passwords = passwords
        self.copy_clipboard=copy_clip

        self.category_label = tk.Label(self, text="Select Category:")
        self.category_label.pack()

        self.category_var = tk.StringVar()
        self.category_dropdown = ttk.Combobox(self, textvariable=self.category_var)
        self.category_dropdown.pack()

        self.update_category_dropdown()

        self.retrieve_button = tk.Button(self, text="Retrieve", command=self.retrieve_password)
        self.retrieve_button.pack()
       
    def update_category_dropdown(self):
        categories = list(self.passwords.keys())
        self.category_dropdown['values'] = categories

    def retrieve_password(self):
        category = self.category_var.get()
        if category in self.passwords:
            encrypted_password = base64.urlsafe_b64decode(self.passwords[category])
            decrypted_password = decrypt_password(self.key, encrypted_password)
            messagebox.showinfo("Retrieved Password", f"Retrieved Password: {decrypted_password}")
            self.copy_clipboard(decrypted_password)
        else:
            messagebox.showerror("Error", "Password not found for the category.")
        self.destroy()                

def main():
    root = tk.Tk()
    PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
