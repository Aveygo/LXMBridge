# LXMBridge

This script allows users to run a 'bridge' between the Meshtastic network and LXM. When running, LXM clients can send messages to the mesh and vise-versa

If the script is running, you can visit it on the nomad network here: ```06fb193ff7c307fc796251fcc66709d2:/page/index.mu```

## Features

 - Allow meshtastic nodes to send messages to any LXMF address (once established, it can be done vise-versa)
 - Allow any LXMF node to send a message to LongFast
 - Allow LXMF nodes to read LongFast messages

## Running

I didn't really intend for anyone to run my script, but if you insist:

### Hardware

1. A PC / raspberry pi to run the bridge as our host
2. A meshtastic node (eg, a Heltec V3) connected via serial / usb to the main host
3. (optional, but recommended) an rnode-compatible device on the network

### Please read

If you already have a bridge running within your local area, I would suggest that you do not run another. Try to keep both networks clean for long term use.

### Instructions

1. Download this repo to your server, ```git clone https://github.com/Aveygo/LXMBridge.git && cd LXMBridge```
2. Download the requirements: ```pip install toml meshtastic pubsub dotenv RNS LXMF better_profanity peewee git+https://github.com/Aveygo/LXMKit.git```
3. Edit ```config.toml``` with your bridge configurations. Do not skip this step.
4. Run ```python3 main.py``` and copy the delivery destination hash
5. Message the node (the copied hash) with ```\help``` to get started.

## Donations

If you found this project helpful, then consider donating to my monero address: 42Hw15daCMuBXKEnTjfv6Y79Rt5N5wKxjHBqCD2STLP6fG5ARYr8aK5PEkEFn28boP5w7Ht8MadciB5jBiboM1Xe1JLW9eC
