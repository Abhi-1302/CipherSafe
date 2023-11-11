import sqlite3,hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


backend=default_backend()
salt=b'1302'
kdf=PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=10000,
    backend=backend
)

encryptionKey=0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

with sqlite3.connect("CipherSafe.db") as db:
    cursor=db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoverykey TEXT NOT NULL);
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS safe(
id INTEGER PRIMARY KEY,
website text NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

def popup(txt):
    answer=simpledialog.askstring("input string",txt)
    return answer


window=Tk()
window.title("cipherSafe")


def hashPassword(pwd):
    hash=hashlib.sha256(pwd)
    hash=hash.hexdigest()
    return hash


def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")
    lbl=Label(window,text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    
    txt=Entry(window,width=25,show="*")
    txt.pack()
    txt.focus()

    lbl1=Label(window,text="Re-Enter password")
    lbl1.pack()

    txt1=Entry(window,width=25,show="*")
    txt1.pack()
    txt1.focus()

    lbl2=Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get()==txt1.get():
            sql="DELETE FROM masterpassword WHERE id=1"
            cursor.execute(sql)
            hashedPass=hashPassword(txt.get().encode('utf-8'))
            key=str(uuid.uuid4().hex)
            recoverykey=hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey=base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
            insert_password="""INSERT INTO masterpassword(password,recoverykey)
            VALUES(?,?)"""
            cursor.execute(insert_password,((hashedPass),(recoverykey)))
            db.commit()
            recoveryScreen(key)
        else:
            lbl2.config(text="passwords do not match")
    btn=Button(window,text="Submit",command=savePassword)
    btn.pack(pady=10)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")
    lbl=Label(window,text="Save this recovery key:")
    lbl.config(anchor=CENTER)
    lbl.pack()
    

    lbl1=Label(window,text=key)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    lbl2=Label(window)
    lbl2.pack()

    btn=Button(window,text="Copy Key",command=copyKey)
    btn.pack(pady=10)

    def done():
        vault()

    btn1=Button(window,text="Done",command=done)
    btn1.pack()

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")
    lbl=Label(window,text="Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()
    

    txt=Entry(window,width=25)
    txt.pack()
    txt.focus()

    lbl1=Label(window)
    lbl1.pack()

    def getrecoveryKey():
        recoveryKeyCheck=hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute("SELECT * from masterpassword WHERE id=1 AND recoverykey = ?",[(recoveryKeyCheck)])
        return cursor.fetchall()
    
    def checkrecoveryKey():
        check=getrecoveryKey()
        if check:
            firstScreen()
        else:
            txt.delete(0,'end')
            lbl1.config(text="wrong key")
    
    btn=Button(window, text="Submit", command=checkrecoveryKey)
    btn.pack()

def loginScreen():
    window.geometry("250x150")
    lbl=Label(window,text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()
    
    

    txt=Entry(window,width=25,show="*")
    txt.pack()
    txt.focus()

    lbl1=Label(window)
    lbl1.pack()

    def getMasterPass():
        checkhashedpass=hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey=base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND password=?",[(checkhashedpass)])
        return cursor.fetchall()

    def checkPassword():
        pwd=getMasterPass()
        if pwd:
            vault()
        else:
            txt.delete(0,'end')
            lbl1.config(text="wrong password")
    
    def resetPassword():
        resetScreen()

    btn=Button(window,text="Submit",command=checkPassword)
    btn.pack(pady=10)

    btn1=Button(window,text="Reset Password",command=resetPassword)
    btn1.pack(pady=10)
def vault():
    for widget in window.winfo_children():
        widget.destroy()
    

    def addEntry():
        text1="website"
        text2="username"
        text3="password"
        website=encrypt(popup(text1).encode(),encryptionKey)
        username=encrypt(popup(text2).encode(),encryptionKey)
        password=encrypt(popup(text3).encode(),encryptionKey)

        insert_fields="""
        INSERT INTO safe(website,username,password) VALUES(?,?,?)"""
        cursor.execute(insert_fields,(website,username,password))
        db.commit()
        vault()
    def remove_Entry(input):
        cursor.execute("DELETE FROM safe where id = ?",(input,))
        db.commit()
        vault()

    window.geometry("700x350")
    lbl=Label(window,text="Your own CipherSafe")
    lbl.grid(column=1)

    btn=Button(window, text="NEW", command=addEntry)
    btn.grid(column=1,pady=10)

    lbw=Label(window,text="Website")
    lbw.grid(row=2,column=0,padx=80)

    lbu=Label(window,text="Username")
    lbu.grid(row=2,column=1,padx=80)

    lbp=Label(window,text="Password")
    lbp.grid(row=2,column=2,padx=80)

    cursor.execute("SELECT * from safe")
    if cursor.fetchall() !=None:
        i=0
        while True:
            cursor.execute("SELECT * from safe")
            arr=cursor.fetchall()

            if len(arr)==0:
                break


            lbl1=Label(window,text=decrypt(arr[i][1],encryptionKey),font=['Helvetica',12])
            lbl1.grid(column=0,row=i+3)

            lbl2=Label(window,text=decrypt(arr[i][2],encryptionKey),font=['Helvetica',12])
            lbl2.grid(column=1,row=i+3)

            lbl3=Label(window,text=decrypt(arr[i][3],encryptionKey),font=['Helvetica',12])
            lbl3.grid(column=2,row=i+3)

            btn=Button(window,text="REMOVE",command=partial(remove_Entry,arr[i][0]))
            btn.grid(column=3,row=i+3,pady=10)

            i+=1

            cursor.execute("SELECT * from safe")
            if len(cursor.fetchall())<=i:
                break



cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
window.mainloop()