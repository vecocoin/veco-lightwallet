# Veco Lightwallet Client

## Introduction

The Veco Lightwallet Client is a lightweight, user-friendly GUI wallet designed for people who want to participate in the Veco blockchain without the complexity of a full node. It allows users to easily create, import and export Veco addresses, manage their contacts and conduct transactions securely over a TSL-encrypted tunnel connection.

## Features

- Effortless Transaction Management: Conduct Veco transactions or receive mining rewards without the need for a full node.
- Wallet Management: Create, import, and export your Veco addresses for multiple user profiles with ease.
- Address book: Save and manage your contacts in an encrypted address book.
- Secure Communication: Default TSL-encrypted stunnel connection to the wallet RPC server.
- Flexible Server Configuration: Switch the wallet RPC server to a local server or a personal VPS by modifying an .env file.

![grafik](https://github.com/vecocoin/veco-lightwallet/assets/155781737/b1d89a6c-3c52-4db1-9148-fffbddadc34d)



## Custom RPC Server Usage

Ensure your VPS or local server's full-node is running with the specified settings in the config file:

```plaintext
rpcallowip=1
listen=1
daemon=1
server=1
rpcport=26920
txindex=1
addressindex=1
spentindex=1
```

Adjust the `.env` file in root folder of main.py (or the binary) based on the `.env-example` provided in the installation folder for configuration.
When using your own VPS, the use of SSH tunneling for secure RPC communication between server and client is highly recommended!

## Build

To compile the client locally using PyInstaller perform the following steps:

```bash
git clone https://github.com/vecocoin/veco-lightwallet
cd veco-lightwallet-client
python setup.py install
pyinstaller main.py -w --clean -n veco-light
```

Alternatively, run `main.py` directly.

## Backup your wallet profiles and address books
The individual wallet addresses, including their private keys of a profile, are stored in a password-encrypted json file names {username}_profile.json in the root directory of the wallet. This is the only place where your keys and addresses are stored. Therefore, you should back up these files from time to time and / or store private keys of your most important addresses in a secure offline environment. You will need the file + password to restore your full wallet profile or the private keys of your individual addresses. If you lose both, all your funds (on these addresses) will be lost forever. The address books for each profile are stored in a password-encrypted file named {username}_addressbook.json.
