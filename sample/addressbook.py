import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import sample.pw_encrypt as pw_encrypt
import sample.wallet as wallet


# Functions to load / save address data
def load_addressbook(username: str, password: str, salt) -> list:
    filename = f"{username}_addressbook.json"
    if not os.path.exists(filename):
        return []
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = pw_encrypt.decrypt_data(encrypted_data, password, salt)
    return json.loads(decrypted_data)


def save_addressbook(username: str, password: str, salt, data: list):
    filename = f"{username}_addressbook.json"
    try:
        encrypted_data = pw_encrypt.encrypt_data(json.dumps(data), password, salt)
        with open(filename, "wb") as file:
            file.write(encrypted_data)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save addressbook: {e}")


# entry window
def add_entry_gui(tree, username, password, salt, bg, fg):

    def save_entry():
        name = name_var.get()
        address = address_var.get()
        if wallet.verify_address(address):
            addressbook.append({"name": name, "address": address})
            save_addressbook(username, password, salt, addressbook)
            tree.insert('', 'end', values=(name, address))
            add_win.destroy()
        else:
            messagebox.showerror("Error", "Not a valid VECO address!")

    add_win = tk.Toplevel()
    add_win.geometry("360x90")
    add_win.title("Add Addressbook Entry")
    add_win.config(bg=bg)

    tk.Label(add_win, text="Name:", fg=fg, bg=bg).grid(row=0, column=0)
    name_var = tk.StringVar()
    tk.Entry(add_win, width=34, textvariable=name_var).grid(row=0, column=1)

    tk.Label(add_win, text="Address:", fg=fg, bg=bg).grid(row=1, column=0)
    address_var = tk.StringVar()
    tk.Entry(add_win, width=34, textvariable=address_var).grid(row=1, column=1)

    tk.Button(add_win, text="   Save   ", command=save_entry, fg=fg, bg=bg).grid(row=2, column=0, columnspan=2, padx=20)


def remove_entry(tree, username, password, salt):
    try:
        selected_item = tree.selection()[0]  # ID of selected item
        selected_name = tree.item(selected_item)['values'][0] # save its name before deletion to also remove it from the file.
        tree.delete(selected_item)
        global addressbook
        addressbook = [entry for entry in addressbook if entry['name'] != selected_name]

        # Save updated List.
        save_addressbook(username, password, salt, addressbook)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


# Main function for addressbook GUI
def addressbook_gui(username: str, password: str, salt, bg, fg):
    global modal, addressbook
    addressbook = load_addressbook(username, password, salt)

    def select_entry(event):  # Event-Parameter hinzugefügt
        selected_item = tree.selection()[0]
        if selected_item:  # Überprüfen, ob ein Item ausgewählt wurde
            selected_address = tree.item(selected_item)['values'][1]
            modal.result = selected_address
            modal.destroy()

    modal = tk.Toplevel()
    modal.geometry("400x300")
    modal.title("Addressbook")
    modal.config(bg=bg)

    # Table (treeview) for addresses
    tree = ttk.Treeview(modal, columns=('Name', 'Address'), show='headings', selectmode='browse')
    tree.heading('Name', text='Name')
    tree.heading('Address', text='Address')
    tree.column('Name', width=40, anchor='center')
    tree.column('Address', width=240, anchor='center')

    #scrollbar = tk.Scrollbar(modal, orient="vertical", command=tree.yview)
    #scrollbar.pack(side="right", fill="y")
    #tree.configure(yscrollcommand=scrollbar.set)
    tree.bind('<Double-1>', select_entry)
    tree.pack(side="top", fill="both", expand=True)

    for entry in addressbook:
        tree.insert('', 'end', values=(entry['name'], entry['address']))

    addressbook_frame = tk.Frame(modal, bg=bg)
    addressbook_frame .pack(padx=0, pady=2, side="top")

    tk.Button(addressbook_frame , text="Select entry", command=lambda: select_entry(tree), bg=bg, fg=fg).\
        pack(side=tk.LEFT, padx=6)
    tk.Button(addressbook_frame , text="Add entry", command=lambda: add_entry_gui(tree, username, password, salt, bg, fg), bg=bg, fg=fg).\
        pack(side=tk.LEFT, padx=6)
    tk.Button(addressbook_frame , text="Remove entry", command=lambda: remove_entry(tree, username, password, salt), bg=bg, fg=fg).\
        pack(side=tk.LEFT, padx=6)



    modal.wait_window()  # Wait until closed

    try:
        return modal.result  # Returns selected address
    except AttributeError:
        return None  # Or nothing if nothing was selected
