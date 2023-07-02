import tkinter
from tkinter import END
from tkinter import messagebox
import base64

window=tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=300,height=300)


#functions

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#encrypt_function
def encrypt():
   title =title_entry.get()
   secret = secret_text.get("1.0",END)
   master_secret= master_entry.get()
   if (len(title)==0 or len(secret)==0 or len(master_secret)==0):
       messagebox.showinfo(title="Hata",message="Her bilgiyi giriniz")
   else:
       message_encrypted = encode(master_secret, secret)
       try:
           with open("secret.txt", "a") as file:
               file.write(f"\n{title}\n{secret}")
       except:
           with open("secret.txt", "w") as file:
               file.write(f"\n{title}\n{secret}")
       finally:
           title_entry.delete(0,END)
           master_entry.delete(0,END)
           secret_text.delete("1.0",END)
#decrypt_function
def decrypt():
    secret_decrypt = secret_text.get("1.0",END)
    master_secret=master_entry.get()
    if(len(secret_decrypt)==0 or len(master_secret)==0):
        messagebox.showinfo(title="Hata", message="Her bilgiyi giriniz")
    else:
        try:
            decrypted_message = decode(master_secret, secret_decrypt)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", END)
        except:
            messagebox.showinfo(title="HATA",message="Doğru değer giriniz")

#image
image=tkinter.PhotoImage(file="C:\\Users\\umut\\PycharmProjects\\Secret_Notes\\test.png",)
image_label=tkinter.Label(image=image)
image_label.pack()


#label info 1
info1_label=tkinter.Label(
    text="Enter your title",
)
info1_label.pack()



#title_entry
title_entry=tkinter.Entry()
title_entry.pack()




#label info 2
info2_label=tkinter.Label(
    text="Enter your secret",
)
info2_label.pack()



#Text
secret_text= tkinter.Text(
    width=30,
    height=10
)
secret_text.pack()





#label info 3
info3_label=tkinter.Label(
    text="Enter your master key",
)
info3_label.pack()



#master_entry
master_entry=tkinter.Entry()
master_entry.pack()



#Encrypt_button
encrypt_button=tkinter.Button(
    text="Save & Encrypt",
    command=encrypt
)
encrypt_button.pack()



#Decrypt_button
decrypt_button=tkinter.Button(
    text="decrypt",
    command=decrypt
)
decrypt_button.pack()




tkinter.mainloop()