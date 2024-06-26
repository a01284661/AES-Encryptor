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


# Funcion para derivar una llave valida AES a partir de la contraseña del usuario
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


# Funcion para seleccionar el archivo a encriptar
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
        output_label.configure(text="")


# Función para encriptar el archivo del usuario
def encrypt():
    if key.get() == key2.get():
        encoded_key = derive_key(key.get().encode(), b'aeaea') # Se deriva la llave a partir de alguna sal
        cipher = Fernet(encoded_key) # Se crea el cipher
        if exists(path.get()):
            with open(path.get(), 'rb') as file:
                content = file.read() # Se lee el archivo
            encrypted_content = cipher.encrypt(content) # Se encripta el contenido del archivo
            file_name, file_extension = splitext(path.get())
            with open(file_name + '_encriptado' + file_extension, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content) # Se guarda el resultado en un archivo nuevo
            output_label.configure(text="Archivo Encriptado")
            os.remove(path.get())
            browse_button.config(text='Seleccionar Archivo')
            key.set("")
            key2.set("")
    else:
        output_label.configure(text="Error: Las llaves no coinciden")


# Función para desencriptar el archivo del usuario
def decrypt():
    if key.get() == key2.get():
        encoded_key = derive_key(key.get().encode(), b'aeaea') # Se deriva la llave a partir de alguna sal
        cipher = Fernet(encoded_key)
        if exists(path.get()):
            with open(path.get(), 'rb') as file:
                content = file.read() # Se lee el archivo
            try:
                decrypted_content = cipher.decrypt(content) # Se desencripta el contenido del archivo
                file_name, file_extension = splitext(path.get())
                with open(file_name + '_desencriptado' + file_extension, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_content) # Se guarda el resultado en un archivo nuevo
                output_label.configure(text="Archivo Desencriptado")
                os.remove(path.get())
                browse_button.config(text='Seleccionar Archivo')
                key.set("")
                key2.set("")
            except InvalidToken:
                output_label.configure(text="Error: La llave es incorrecta o el archivo no está encriptado") # Si hay algún error en la encriptación se muestra esto.
    else:
        output_label.configure(text="Error: Las llaves no coinciden")

root = Tk()
root.title("Encriptador")

mainframe = ttk.Frame(root, padding="3 3 12 12")
mainframe.grid(column=0, row=0, sticky='NWES')
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

ttk.Label(mainframe, text="Archivo:").grid(column=1, row=1, sticky=E)

path = StringVar()
browse_button = ttk.Button(mainframe, text="Seleccionar Archivo", command=browse_file, width=25)
browse_button.grid(column=2, row=1, sticky='WE')

ttk.Label(mainframe, text="Llave:").grid(column=1, row=2, sticky=E)

key = StringVar()
key_entry = ttk.Entry(mainframe, width=7, textvariable=key, show="•")
key_entry.grid(column=2, row=2, sticky='WE')

ttk.Label(mainframe, text="Confirmar Llave:").grid(column=1, row=3, sticky=E)

key2 = StringVar()
key_entry2 = ttk.Entry(mainframe, width=7, textvariable=key2, show="•")
key_entry2.grid(column=2, row=3, sticky='WE')

encrypt_button = ttk.Button(mainframe, text="Encriptar", command=encrypt, width=25, state='disabled')
encrypt_button.grid(column=1, row=4, sticky=W)

decrypt_button = ttk.Button(mainframe, text="Desencriptar", command=decrypt, width=25, state='disabled')
decrypt_button.grid(column=2, row=4, sticky='WE')

output = StringVar()
output_label = ttk.Label(mainframe, text="")
output_label.grid(column=1, row=5, columnspan=2, sticky=E)

for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

root.resizable(False, False)
key_entry.focus()
root.bind("<Return>", browse_file)

root.mainloop()
