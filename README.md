# Veco Lightwallet Client

## Introduction

The Veco Lightwallet Client is a streamlined, user-friendly GUI wallet designed for individuals seeking to engage with the Veco blockchain without the complexity of running a full node. It empowers users to easily create, import, and export Veco addresses, as well as perform transactions securely through a TSL-encrypted stunnel connection.

## Features

- Effortless Transaction Management: Conduct Veco transactions or receive mining rewards without the need for a full node.
- Address Management: Create, import, and export Veco addresses with ease.
- Secure Communication: Default TSL-encrypted stunnel connection to the wallet RPC server.
- Flexible Server Configuration: Switch the wallet RPC server to a local server or a personal VPS by modifying an .env file.

![grafik](https://github.com/vecocoin/veco-lightwallet/assets/155781737/777c16b8-b6d8-40b7-96e0-78cc770939ec)


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
