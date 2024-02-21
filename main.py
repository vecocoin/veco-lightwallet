import json
import os
import sys
import tkinter as tk
import tkinter.font as font
from tkinter import scrolledtext
from tkinter import simpledialog, ttk, messagebox

from cryptography.fernet import InvalidToken

import sample.UTXO_RPC as UTXO_RPC
import sample.pw_encrypt as pw_encrypt
import sample.wallet as wallet

fg = "white"
bg = "gray22"
relief = "ridge"


def center_window(window, width, height):
    # Get the screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # Calculate the position for the window to be centered
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2

    # Set the geometry string for the window
    window.geometry(f"{width}x{height}+{x}+{y}")


def custom_ask_string(title, prompt, show=None):
    dialog = tk.Toplevel(bg=bg)
    dialog.title(title)
    center_window(dialog, 250, 130)

    tk.Label(dialog, text=prompt, bg=bg, fg=fg).pack(pady=10)
    entry = tk.Entry(dialog, show=show)
    entry.pack(padx=10)
    result = ""

    def on_submit(event=None):
        nonlocal result
        result = entry.get()
        dialog.destroy()

    submit_button = tk.Button(dialog, text="Submit", command=on_submit, bg=bg, fg=fg, relief=relief)
    submit_button.pack(pady=10)

    entry.bind('<Return>', lambda event: on_submit())

    entry.focus_set()  # Focus on the entry widget
    entry.select_range(0, 'end')  # Select all text in the entry widget

    dialog.wait_window()  # Wait until the dialogue is closed.
    return result


def validate_username(username):
    invalid_chars = '<>:"/\\|?*'
    if username is None:
        return False
    elif not username.strip():
        return False
    elif any(char in invalid_chars for char in username):
        return False
    else:
        return True


def create_profile(start_window):
    global username
    global password
    global salt
    global profile_data

    username = custom_ask_string("Create New Profile", "Enter username:")
    # username = simpledialog.askstring("Create New Profile", "Enter username:")
    # password = simpledialog.askstring("Password", "Enter your password for this account:", show='*')
    # password_check = simpledialog.askstring("Password", "Confirm Password:", show='*')
    validuser = validate_username(username)
    if validuser:
        file_path = f"{username}_profile.json"
        password = custom_ask_string("Password", "Enter your password for this account:", show='*')
        password_check = custom_ask_string("Password", "Confirm Password:", show='*')
        if password != password_check:
            messagebox.showerror(title="Error", message="Passwords do not match!")
            return  # Passwords do not match, so exit the function
        else:
            # Check whether the account already exists
            if os.path.exists(file_path):
                messagebox.showerror(title="Error", message="Account already exists!")
                return
            else:
                # Generate first address with CWIF for a new wallet
                cwif, address = wallet.generate_cwif_and_address()
                profile_data = {
                    "username": username,
                    "wallet_addresses": [address],
                    "cwifs": [cwif]
                }

                salt = os.urandom(16)
                json_profile_data = json.dumps(profile_data)
                encrypted_data = pw_encrypt.encrypt_data(json_profile_data, password, salt)
                data_to_save = {
                    "encrypted_data": encrypted_data.decode(),  # Assuming encrypted_data is a byte object
                    "salt": salt.hex()  # Convert salt to a hexadecimal string for storage
                }
                # Convert the entire object into a JSON string and save it in profile file
                json_data_to_save = json.dumps(data_to_save)
                with open(file_path, "w") as file:
                    file.write(json_data_to_save)

                start_window.destroy()
                show_wallet_window(profile_data)  # Show main window
    else:
        messagebox.showerror(title="Error", message="You have to enter a valid username!")
        return  # Exit the function without creating the profile


def load_profile(start_window):
    global username
    global password
    global salt

    username = custom_ask_string("Profile", "Enter your profile name:")

    # username = simpledialog.askstring("Load Profile", "Enter Username:")
    # password = simpledialog.askstring("Password", "Enter Password:", show='*')

    try:
        with open(f"{username}_profile.json", "r") as file:
            password = custom_ask_string("Password", "Enter your password for this account:", show='*')
            data = json.load(file)
            encrypted_data = data["encrypted_data"]
            salt = bytes.fromhex(data["salt"])  # Convert the hexadecimal string back to bytes

        decrypted_data = pw_encrypt.decrypt_data(encrypted_data.encode(), password, salt)
        global profile_data
        profile_data = json.loads(decrypted_data)

        start_window.destroy()
        show_wallet_window(profile_data)  # Show main window

    except FileNotFoundError:
        messagebox.showerror(title="Error", message="Profile not found!")
    except NameError:
        messagebox.showerror(title="Error", message="Profile not found!")
    except InvalidToken:
        messagebox.showerror(title="Error", message="Wrong password!")
    except Exception as e:
        messagebox.showerror(title="Error", message=f"An error occurred: {e}")


def show_wallet_window(profile_data):
    global logo_small
    wallet_window = tk.Tk()
    wallet_window.geometry("400x600")
    wallet_window.title("Veco Light Wallet")
    wallet_window.config(bg=bg)

    logo_small = tk.PhotoImage(file="sample/veco_light_400.png")
    window_width = 450
    window_height = 650
    center_window(wallet_window, window_width, window_height)
    label_logo = tk.Label(wallet_window, image=logo_small, bg="#3B3B3B")
    label_logo.pack(side="top", pady=15)

    frame_address = tk.Frame(wallet_window, bg=bg)
    frame_address.pack(side="top", padx=3, pady=3)

    balance_label = tk.Label(frame_address, text=f"Current Address:", bg=bg, fg=fg)
    balance_label.pack(side="top", padx=0, pady=3)

    # Create a combo box widget with the available wallet addresses
    address_combobox = ttk.Combobox(frame_address, width=34, values=profile_data['wallet_addresses'], state="readonly")
    address_combobox.pack(side="right", padx=0, pady=3)
    address_combobox.set(profile_data['wallet_addresses'][0])  # Set the first address as the default value

    # Bind the update_balance function to the selection change of the combo box
    address_combobox.bind('<<ComboboxSelected>>', lambda event: update_balance())

    class StdoutRedirector(object):
        def __init__(self, text_widget):
            self.text_widget = text_widget
            self.text_widget.configure(state='normal')

        def write(self, string):
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, string)
            self.text_widget.configure(state='disabled')
            self.text_widget.see(tk.END)

        def flush(self):
            pass

    def redirect_print_to_console(console):
        sys.stdout = StdoutRedirector(console)

    def copy_address_to_clipboard():
        wallet_window.clipboard_clear()
        wallet_window.clipboard_append(address_combobox.get())
        wallet_window.update()  # The address is now in the clipboard

    def create_new_address():
        global profile_data, password  # Assuming these variables are globally available
        new_cwif, new_address = wallet.generate_cwif_and_address()
        profile_data['wallet_addresses'].append(new_address)
        profile_data['cwifs'].append(new_cwif)

        # Update combobox
        address_combobox['values'] = profile_data['wallet_addresses']
        address_combobox.set(new_address)  # Set the new address as the current selection
        update_balance()
        # Encryption and storage
        encrypted_data = pw_encrypt.encrypt_data(json.dumps(profile_data), password,
                                                 salt)  # Assuming salt is available globally
        data_to_save = {"encrypted_data": encrypted_data.decode(), "salt": salt.hex()}
        with open(f"{profile_data['username']}_profile.json", "w") as file:
            file.write(json.dumps(data_to_save))

        print(f"\nCreated new address:\n {new_address}")

    def remove_address():
        user_password = simpledialog.askstring("Password required!",
                                               "The address cannot be reimported without its CWIF!\nPlease confirm deletion!",
                                               show='*')
        global profile_data, password  # Declare globally

        if user_password == password:
            selected_address = address_combobox.get()
            address_index = profile_data['wallet_addresses'].index(selected_address)
            # Remove address and associated CWIF
            del profile_data['wallet_addresses'][address_index]
            del profile_data['cwifs'][address_index]

            # Update combobox
            address_combobox['values'] = profile_data['wallet_addresses']
            if profile_data['wallet_addresses']:
                address_combobox.set(profile_data['wallet_addresses'][0])
                update_balance()
            else:
                address_combobox.set("")

            # Save updated user profile
            encrypted_data = pw_encrypt.encrypt_data(json.dumps(profile_data), password, salt)
            data_to_save = {"encrypted_data": encrypted_data.decode(), "salt": salt.hex()}
            with open(f"{profile_data['username']}_profile.json", "w") as file:
                file.write(json.dumps(data_to_save))
            print(f"\nDeleted address:\n {selected_address}")
        else:
            print(f"\nIncorrect password!")
            messagebox.showerror(title="Error!", message="Incorrect Password")
            pass

    def copy_private_key():
        user_password = simpledialog.askstring("Password required!", "Confirm password to copy the CWIF "
                                                                     "of this address!", show='*')
        if user_password == password:  # Assuming `password` is a global variable
            selected_address_index = profile_data['wallet_addresses'].index(address_combobox.get())
            wallet_window.clipboard_clear()
            wallet_window.clipboard_append(profile_data['cwifs'][selected_address_index])
            # messagebox.showinfo("Private Key", f"Your CWIF for the selected address is: {cwif}")
        else:
            print(f"\nIncorrect password!")
            messagebox.showerror(title="Error!", message="Incorrect Password")
            pass

    def import_address():
        cwif = simpledialog.askstring("Import CWIF", "Enter CWIF:")
        if cwif:  # Check whether a CWIF has been entered
            try:
                new_address = wallet.cwif_to_address(cwif)  # Attempts to convert the CWIF into an address
                profile_data['wallet_addresses'].append(new_address)
                profile_data['cwifs'].append(cwif)
                update_combobox_and_save(profile_data)
                update_balance()
                print(f"\nImported address:\n {new_address}")
            except Exception as e:  # Intercepts all errors that could be thrown by cwif_to_address
                print(f"\nFailed to import address. Error: {e}")
                messagebox.showerror(title="Error", message=f"Failed to import CWIF: {e}")

    def update_combobox_and_save(profile_data):
        try:
            # Update the combo box with the new wallet addresses
            address_combobox['values'] = profile_data['wallet_addresses']
            address_combobox.set(
                profile_data['wallet_addresses'][-1])  # Set the newly added address as the selected address.

            # Encryption of the updated profile data
            encrypted_data = pw_encrypt.encrypt_data(json.dumps(profile_data), password, salt)
            data_to_save = {
                "encrypted_data": encrypted_data.decode(),
                "salt": salt.hex()
            }

            # Saving the updated and encrypted data in the profile file
            with open(f"{profile_data['username']}_profile.json", "w") as file:
                file.write(json.dumps(data_to_save))
        except Exception as e:
            messagebox.showerror(title="Error", error=f"An error occurred while updating and saving profile: {e}")

    def update_balance():
        # Fetch current balance by adding all up all available UTXOs
        curr_wallet = address_combobox.get()
        balance = UTXO_RPC.calculate_total_balance(curr_wallet)
        balance_label.config(text=f"Address Balance: {round(balance, 4)} VECO")
        wallet_window.after(23500, update_balance)

    def send_veco():
        curr_wallet = address_combobox.get()
        send_window = tk.Toplevel(wallet_window)
        send_window.geometry("400x240")
        send_window.title("Send VECO")
        send_window.config(bg=bg)

        window_width = 400
        window_height = 254
        center_window(send_window, window_width, window_height)

        sender_label = tk.Label(send_window, text=f"Sender address:", fg=fg, bg=bg)
        sender_label.pack()

        # Create a combo box widget with the available wallet addresses
        sender_address_combobox = ttk.Combobox(send_window, width=34, values=profile_data['wallet_addresses'],
                                               state="readonly")
        sender_address_combobox.pack(pady=3)
        sender_address_combobox.set(curr_wallet)  # Set the address selected in the main window as the default value

        tk.Label(send_window, text="Receiver address:", bg=bg, fg=fg).pack()
        receiver_entry = tk.Entry(send_window, width=36)
        receiver_entry.pack(pady=6)

        tk.Label(send_window, text="Amount to send:", fg=fg, bg=bg).pack()

        def set_max_amount():
            selected_sender_address = sender_address_combobox.get()
            if UTXO_RPC.calculate_total_balance(selected_sender_address) > 0:
                max_amount = round(UTXO_RPC.calculate_total_balance(selected_sender_address) - 0.00002, 8)
            else:
                max_amount = 0
            amount_entry.delete(0, tk.END)
            amount_entry.insert(0, max_amount)

        amount_frame = tk.Frame(send_window, bg=bg)
        amount_frame.pack(padx=0, pady=2)

        amount_entry = tk.Entry(amount_frame, width=21, font='sans 12 bold', justify='right')
        amount_entry.pack(side=tk.LEFT, pady=2)
        max_button = tk.Button(amount_frame, text="MAX", command=set_max_amount, pady=2, padx=0, width=6,
                               bg=bg,
                               fg=fg,  # Text color
                               borderwidth=1,  # Border width
                               highlightthickness=1,  # Highlight thickness for focus
                               relief=relief,
                               )
        max_button.pack(side=tk.LEFT)

        def prepare_tx():
            receiver = receiver_entry.get()
            if wallet.verify_address(receiver):
                amount = float(amount_entry.get())
                selected_sender_address = sender_address_combobox.get()
                selected_sender_address_index = profile_data['wallet_addresses'].index(sender_address_combobox.get())

                if UTXO_RPC.calculate_total_balance(selected_sender_address) <= amount:
                    print("\nError! Balance of selected address too low!")
                    messagebox.showerror(title="Error", message="Not enough VECO!")
                    return
                else:
                    selected_utxos, total_amount = UTXO_RPC.select_utxos_for_amount(selected_sender_address, amount)
                    if selected_utxos and total_amount > 0:
                        raw_tx = UTXO_RPC.create_raw_transaction(receiver, selected_utxos, amount,
                                                                 selected_sender_address)
                        # print(raw_tx)
                        if raw_tx:
                            cwif = profile_data['cwifs'][selected_sender_address_index]
                            sign_tx = UTXO_RPC.sign_raw_tx_with_utxos(raw_tx, selected_utxos, cwif)
                            if sign_tx:
                                confirm_transaction_dialog(sign_tx)
                            else:
                                print("\nError while signing the UTXO transactions!")
                                messagebox.showerror(title="Error",
                                                     message="Error while signing the UTXO transactions!")
                                return
                        else:
                            print("\nError while generating the UTXO transactions!")
                            messagebox.showerror(title="Error", message="Error while signing the UTXO transactions!")
                            return
                    else:
                        print("\nError while selecting the UTXOs to generate the transaction")
                        messagebox.showerror(title="Error",
                                             message="Error while selecting the UTXOs to generate the transaction!")
                        return
            else:
                print(f"\nError! Receiver address is not a valid VECO address!")
                messagebox.showerror(title="Error", message="Receiver address is not a valid VECO address!")
                return

        def confirm_transaction_dialog(sign_tx):
            confirmtx = tk.Toplevel(wallet_window, bg=bg)
            confirmtx.title("Confirm Transaction")

            window_width = 300
            window_height = 200
            center_window(confirmtx, window_width, window_height)

            tk.Label(confirmtx, bg=bg, fg=fg,
                     text=f"Please confirm that you want to send\n {amount_entry.get()} VECO\n  from\n  {sender_address_combobox.get()}\n  TO\n  {receiver_entry.get()}\n!",
                     wraplength=300).pack()

            def on_confirm():
                tx_sent = UTXO_RPC.send_raw_tx(sign_tx)
                txinfo = tk.Toplevel(confirmtx, bg=bg)
                send_window.geometry("300x150")
                txinfo.title("Transaction Submitted")
                window_width = 300
                window_height = 150
                center_window(txinfo, window_width, window_height)

                if tx_sent['error'] is None:
                    print(f"\nTransaction submitted to mempool! tixd:\n {tx_sent['result']}")
                    txid_entry = tk.Entry(txinfo, state='readonly', width=50)
                    txid_var = tk.StringVar()
                    txid_entry.config(textvariable=txid_var, relief="flat")  # 'flat' for less visible frame
                    txid_var.set(tx_sent['result'])
                    txid_entry.pack()

                    def copy_txid_to_clipboard():
                        txinfo.clipboard_clear()
                        txinfo.clipboard_append(txid_var.get())  # Add the txid to the clipboard
                        txinfo.update()  # Refresh the clipboard window to save the new content

                    copy_tx_button = tk.Button(txinfo, text="Copy txid",
                                               command=copy_txid_to_clipboard,
                                               bg=bg,
                                               fg=fg,  # Text color
                                               borderwidth=1,  # Border width
                                               highlightthickness=1,  # Highlight thickness for focus
                                               relief=relief,
                                               )
                    copy_tx_button.pack()

                    tk.Label(txinfo, bg=bg, fg=fg,
                             text="Transaction sent to Mempool! Please note it can take a while until it is indexed.",
                             wraplength=300).pack()

                    # confirmtx.destroy()
                else:
                    print(f"\nTransaction failed with error message\n {tx_sent['error']}")
                    tk.Label(txinfo, bg=bg, fg=fg,
                             text=f"Transaction failed. Error: {tx_sent['error']}.",
                             wraplength=300).pack()
                    # confirmtx.destroy()

                def ok():
                    txinfo.destroy()
                    confirmtx.destroy()

                tk.Button(txinfo, text="OK", pady=2, padx=0, width=16,
                          command=ok,
                          bg=bg,
                          fg=fg,  # Text color
                          borderwidth=1,  # Border width
                          highlightthickness=1,  # Highlight thickness for focus
                          relief=relief,
                          font=buttonFont
                          ).pack()

                # Button, to copy the generated txid

            def on_cancel():
                # Cancel logic
                messagebox.showinfo(title="Transaction cancelled!", message="Transaction cancelled!")
                print("\nTransaction cancelled!")
                confirmtx.destroy()

            # Buttons
            confirm_frame = tk.Frame(confirmtx, bg=bg)
            confirm_frame.pack()

            tk.Button(confirm_frame, text="Confirm", command=on_confirm, pady=2, padx=0, width=16,
                      bg=bg,  # Light orange background
                      fg=fg,  # Text color
                      borderwidth=1,  # Border width
                      highlightthickness=1,  # Highlight thickness for focus
                      relief=relief,
                      # font=buttonFont
                      ).pack(side="right", padx=0, pady=2)

            tk.Button(confirm_frame, text="Cancel", command=on_cancel, pady=2, padx=0, width=16,
                      bg=bg,  # Light orange background
                      fg=fg,  # Text color
                      borderwidth=1,  # Border width
                      highlightthickness=1,  # Highlight thickness for focus
                      relief=relief,
                      # font=buttonFont
                      ).pack(side="right", padx=0, pady=2)

        buttonFont = font.Font(weight='bold')
        send_button = tk.Button(send_window, text="Create Transaction", command=prepare_tx, pady=2, padx=0, width=24,
                                bg=bg,  # Light orange background
                                fg=fg,  # Text color
                                borderwidth=1,  # Border width
                                highlightthickness=1,  # Highlight thickness for focus
                                relief=relief,
                                font=buttonFont
                                )
        send_button.pack(side="bottom", padx=0, pady=7)

    def log_out(wallet_window):
        wallet_window.destroy()
        show_start_window()

    # Create frame for the text box and the refresh button
    frame_balance = tk.Frame(wallet_window, bg=bg)
    frame_balance.pack(side="top", padx=0, pady=3)

    balance_label = tk.Label(frame_balance, text=f"Balance: Loading...", bg=bg, fg=fg)  # Text color)
    balance_label.pack(side="left", padx=0, pady=1)

    balance_button = tk.Button(frame_balance, text="\u27F3", command=update_balance,
                               bg=bg,
                               fg=fg,  # Text color
                               borderwidth=1,  # Border width
                               highlightthickness=1,  # Highlight thickness for focus
                               relief=relief,
                               )

    balance_button.pack(side="left", padx=0, pady=1)

    copy_button = tk.Button(frame_address, text="\U0001F4CB", command=copy_address_to_clipboard,
                            bg=bg,
                            fg=fg,  # Text color
                            borderwidth=1,  # Border width
                            highlightthickness=1,  # Highlight thickness for focus
                            relief=relief,
                            )
    copy_button.pack(side="right", padx=0, pady=1)

    send_veco_button = tk.Button(wallet_window, text="Send VECO", pady=4, padx=0, width=28, command=send_veco,
                                 bg=bg,
                                 fg=fg,  # Text color
                                 borderwidth=1,  # Border width
                                 highlightthickness=1,  # Highlight thickness for focus
                                 relief=relief,
                                 )
    send_veco_button.pack(side="top")

    create_new_address_button = tk.Button(wallet_window, text="Create New Address", pady=4, padx=0, width=28,
                                          command=create_new_address,
                                          bg=bg,
                                          fg=fg,  # Text color
                                          borderwidth=1,  # Border width
                                          highlightthickness=1,  # Highlight thickness for focus
                                          relief=relief,
                                          )
    create_new_address_button.pack(side="top")

    import_address_button = tk.Button(wallet_window, text="Import Address", pady=4, padx=0, width=28,
                                      command=import_address,
                                      bg=bg,
                                      fg=fg,  # Text color
                                      borderwidth=1,  # Border width
                                      highlightthickness=1,  # Highlight thickness for focus
                                      relief=relief,
                                      )
    import_address_button.pack(side="top")

    remove_address_button = tk.Button(wallet_window, text="Remove Address", pady=4, padx=0, width=28,
                                      command=remove_address,
                                      bg=bg,
                                      fg=fg,  # Text color
                                      borderwidth=1,  # Border width
                                      highlightthickness=1,  # Highlight thickness for focus
                                      relief=relief,
                                      )
    remove_address_button.pack(side="top")

    show_private_key_button = tk.Button(wallet_window, text="Copy Private Key to Clipboard", pady=4, padx=0, width=28,
                                        command=copy_private_key,
                                        bg=bg,
                                        fg=fg,  # Text color
                                        borderwidth=1,  # Border width
                                        highlightthickness=1,  # Highlight thickness for focus
                                        relief=relief,
                                        )
    show_private_key_button.pack(side="top")

    log_out_button = tk.Button(wallet_window, text="Log Out", pady=4, padx=0, width=28,
                               command=lambda: log_out(wallet_window),
                               bg=bg,
                               fg=fg,  # Text color
                               borderwidth=1,  # Border width
                               highlightthickness=1,  # Highlight thickness for focus
                               relief=relief,
                               )
    log_out_button.pack()

    # Status bar at the lower end of the window
    status_frame = tk.Frame(wallet_window, bg=bg)
    status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=0, pady=5)

    # Status light t (green = connected, red = not connected)
    status_light = tk.Label(status_frame, text='\u25CF', fg='red', bg=bg)
    status_light.pack(side=tk.LEFT)

    status_label = tk.Label(status_frame, text="RPC Connection: ", bg=bg, fg=fg)
    status_label.pack(side=tk.LEFT)

    # Hinzufügen eines ScrolledText-Widgets für die Konsolen-Ausgabe
    console = scrolledtext.ScrolledText(wallet_window, height=10, bg=bg, fg=fg)  # Höhe auf 10 Zeilen gesetzt
    console.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    console.config(state='disabled')  # Verhindert direkte Bearbeitung durch den Benutzer

    redirect_print_to_console(console)

    print(f"Profile <{username}> loaded.")

    def update_rpc_status():
        connected, blocknumber = UTXO_RPC.get_current_block()
        if connected:
            status_light.config(fg='green3')
            status_label.config(text=f"RPC connection established. Current block height: {blocknumber}")
        else:
            status_light.config(fg='red')
            status_label.config(text="RPC connection not available")
            print("\nCan't establish RPC connection to server!")
        # Fetch connection status and block number every 10 s.
        wallet_window.after(30000, update_rpc_status)

    # Initialize balance and status update upon starting the window
    update_rpc_status()

    update_balance()


def show_start_window():
    start_window = tk.Tk()
    start_window.title("Veco Light Wallet")
    logo = tk.PhotoImage(file="sample/veco_light.png")
    window_width = 750
    window_height = 274
    start_window.config(bg=bg)
    center_window(start_window, window_width, window_height)
    label = tk.Label(start_window, image=logo)
    label.grid(row=0, columnspan=2)

    login_frame = tk.Frame(start_window, bg=bg)
    login_frame.grid(row=1, columnspan=2)

    '''
    # Create a BooleanVar to hold the state of the Checkbutton
    custom_rpc_var = tk.BooleanVar(value=False)

    
    # Function to update the global variable based on the Checkbutton's state
    def update_custom_rpc():
        # Directly modify the custom_RPC variable in the config module
        config.custom_RPC = custom_rpc_var.get()

    # Add the Checkbutton to the window
    custom_rpc_checkbutton = tk.Checkbutton(login_frame, text="Use custom RPC settings",
                                            variable=custom_rpc_var,
                                            onvalue=True, offvalue=False, command=update_custom_rpc,
                                            bg=bg, fg=fg, selectcolor=bg)
    custom_rpc_checkbutton.pack(side=tk.BOTTOM, padx=20)
    '''
    create_button = tk.Button(login_frame, text="Create Profile", command=lambda: create_profile(start_window), pady=5,
                              width=40,
                              bg=bg,
                              fg=fg,  # Text color
                              borderwidth=1,  # Border width
                              highlightthickness=1,  # Highlight thickness for focus
                              relief=relief,
                              )
    # create_button.grid(row=0, column=0, sticky="EW",ipadx=80)
    create_button.pack(side=tk.LEFT, padx=20)
    load_button = tk.Button(login_frame, text="Load Profile", command=lambda: load_profile(start_window), pady=5,
                            width=40,
                            bg=bg,
                            fg=fg,  # Text color
                            borderwidth=1,  # Border width
                            highlightthickness=1,  # Highlight thickness for focus
                            relief=relief,
                            )
    # load_button.grid(row=0, column=1, columnspan=2,ipadx=80)
    load_button.pack(side=tk.LEFT, padx=20)

    start_window.mainloop()


show_start_window()
