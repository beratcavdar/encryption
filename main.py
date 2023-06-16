import binascii
from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image
from cryptography.fernet import Fernet
import base64

# Variables
path = "secret_icon.png"
padding = 2
font = "sobel,20,bold"

# Create a Window
window = Tk()
window.title("Calculator :D")
window.geometry("450x700")
window.config(background="gray70", pady=25)

# Put the image to topside
image = Image.open(path)
resize_image = image.resize(((100, 100)))
img = ImageTk.PhotoImage(resize_image)
image_label = Label(image=img)
image_label.image = img






image_label.pack(pady=20)
# Title label
title_label = Label(text="Enter Your Title", font=font)
# Title Entry
title_entry = Entry(width=30)
print(title_entry.get())
# Secret Label
secret_label = Label(text="Enter your information :D", font=font)
# Secret text

secret_text = Text(width=30, height=15)
secret_text1 = Label(text="",)
# Master key label
master_label = Label(text="Enter a master key.", font=font)
# Master entry
master_entry = Entry(width=30)

def generate_key():
    key = Fernet.generate_key()
    return key

def encryption():
    # Check for valid entries
    if not title_entry.get() or not secret_text.get("1.0", END).strip():
        messagebox.showerror("Invalid Entry", "Please enter a valid title and secret information.")
        return

    try:
        entry_input = open("secretfile.txt", "w")
        to_be_encrypted = secret_text.get("1.0", END).encode("utf-8")
        entry_input.write(title_entry.get())
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encMessage = fernet.encrypt(to_be_encrypted)
        entry_input.write("\n")
        entry_input.write(encMessage.decode("utf-8"))
        entry_input.write("\n")
        entry_input.write(key.decode("utf-8"))
        entry_input.close()
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred during encryption:\n{str(e)}")

def decryption():
    # Check for valid entry
    if not secret_text.get("1.0", END).strip():
        messagebox.showerror("Invalid Entry", "Please enter a valid encrypted message.")
        return

    try:
        encMessage = secret_text.get("1.0", END).encode("utf-8")
        key = master_entry.get().encode("utf-8")
        try:
            with open("secretfile.txt", "r") as entry_input:
                entry_lines = entry_input.readlines()
                saved_key = entry_lines[-1].strip()
                fernet = Fernet(saved_key)
                decMessage = fernet.decrypt(encMessage).decode("utf-8")
                secret_text.delete("1.0", END)
                secret_text.insert("1.0", decMessage)
        except IndexError:
            messagebox.showerror("Decryption Error", "Invalid encrypted message. Please try again.")
    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred during decryption:\n{str(e)}")







# Save button
save_button = Button(text="Save & Encrypt", command=encryption)
# Decrypting button


decrypt_button = Button(text="Decrypt", command=decryption)


title_label.pack(pady=padding)
title_entry.pack(pady=padding)
title_entry.focus()
secret_label.pack(pady=padding)
secret_text.pack(pady=padding)
master_label.pack(pady=padding)
master_entry.pack(pady=padding)
save_button.pack(pady=padding, )
decrypt_button.pack(pady=padding)




mainloop()
