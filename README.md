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

### Instructions

1. Download this repo to your server ([link](git@github.com:Aveygo/LXMBridge.git))
2. Download the requirements: ```pip install meshtastic pubsub dotenv RNS LXMF better_profanity peewee git+https://github.com/Aveygo/LXMKit.git```
3. Create a file with the name: ```.env```, and fill in the following details:

```bash
BRIDGE_NAME = "My Epic Bridge"      # Your bridge name here
BRIDGE_SECRET = "1234567890"        # smash your keyboard or whatever to generate a key
MESHTASTIC_REMOTE = "192.168.1.10"  # if using wifi, enter the meshtasic node's ip address
```

4. Run ```python3 main.py``` and copy the delivery destination hash
5. Message the node (the copied hash) ```\help``` to get started.

