from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from os.path import exists
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
from os.path import splitext


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def browse_file():
    filepath = filedialog.askopenfilename(
        title="Select a File",
        filetypes=(("All files", "*.*"),)
    )
    if filepath:
        path.set(filepath)
        browse_button.config(text=os.path.basename(filepath))
        encrypt_button.config(state='enabled')
        decrypt_button.config(state='enabled')


def encrypt():
    encoded_key = derive_key(key.get().encode(), b'nemo')
    cipher = Fernet(encoded_key)
    if exists(path.get()):
        with open(path.get(), 'rb') as file:
            content = file.read()
        encrypted_content = cipher.encrypt(content)
        file_name, file_extension = splitext(path.get())
        with open(file_name + '_encriptado' + file_extension, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_content)
        output_label.configure(text="Archivo encriptado")


def decrypt():
    encoded_key = derive_key(key.get().encode(), b'nemo')
    cipher = Fernet(encoded_key)
    if exists(path.get()):
        with open(path.get(), 'rb') as file:
            content = file.read()
        try:
            decrypted_content = cipher.decrypt(content)
            file_name, file_extension = splitext(path.get())
            with open(file_name + '_desencriptado' + file_extension, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)
            output_label.configure(text="Archivo desencriptado")
        except InvalidToken:
            output_label.configure(text="Error de llave")


root = Tk()
root.title("Encriptador")

mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky='NWES')
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

ttk.Label(mainframe, text="Archivo:").grid(column=1, row=1, sticky=E)

path = StringVar()
browse_button = ttk.Button(mainframe, text="Seleccionar Archivo", command=browse_file, width=20)
browse_button.grid(column=2, row=1, sticky='WE')

ttk.Label(mainframe, text="Llave:").grid(column=1, row=2, sticky=E)

key = StringVar()
key_entry = ttk.Entry(mainframe, width=7, textvariable=key)
key_entry.grid(column=2, row=2, sticky='WE')

encrypt_button = ttk.Button(mainframe, text="Encriptar", command=encrypt, width=20, state='disabled')
encrypt_button.grid(column=1, row=3, sticky=W)

decrypt_button = ttk.Button(mainframe, text="Desencriptar", command=decrypt, state='disabled')
decrypt_button.grid(column=2, row=3, sticky='WE')


output = StringVar()
output_label = ttk.Label(mainframe, text="")
output_label.grid(column=2, row=4, sticky=E)

for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

root.resizable(False, False)
key_entry.focus()
root.bind("<Return>", browse_file)

root.mainloop()
