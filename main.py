"""

Hi! This is the source code of the Meshtastic-to-Reticulum Bridge. If you are reading this, then 
you probably want to be a bridge runner. Please see the readme for more details.

Please note that some deliberate choices were made to preserve user privacy and prevent spam. 
For instance, I only allowed users to message one another if they run the '/listen' command 
on their respective networks.

Feel free to modify the code to suit your needs, but please remain respectful and remember the human. 
"""

import meshtastic, time, base64, json, hashlib, base64, os
import meshtastic.tcp_interface
import meshtastic.serial_interface
import traceback
from pubsub import pub
from db import database, MeshtasticNode, MeshtasticMessage, LXMFUser

from LXMKit.app import LXMFApp, Message, Author

import RNS, LXMF
from log_f import logger
from page import create_canvas
from config import config
from cooldown import AntiSpam

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from better_profanity import profanity
from fixed_interface import Injector

profanity.load_censor_words()

SECRET = config['bridge']['secret']
assert not SECRET == '1234567890', "Config file was not edited. Did you read the github instructions?"
assert config['sanity']['i_did_a_good_job'], "Hey! Don't skip on the config! Go through it carefully."
assert len(SECRET) > 8, "Secret from config.toml is too short. Please edit it to be longer."


class Bridge(LXMFApp):
    """
    Primary class that handles communication between the 
    'meshtastic' and 'LXMF' networks. 
    """
    def __init__(self, app_name, storage_path="tmp"):
        LXMFApp.__init__(self, storage_path=storage_path, app_name=app_name, announce=config["advanced"]["announce"])

        # Use our special injector to create the meshtastic 
        # interface, see fixed_interface.py for more details
        self.mesh = Injector(self.create_interface) 

        self.routers:dict[str, LXMF.LXMRouter] = {} # meshtastic_node_id: LXMRouter
        self.build_routers()

        @self.request_handler("/page/index.mu")
        def sample(path:str, link:RNS.Link):
            return self.handle_LXMF_index(path, link)

        @self.delivery_callback
        def delivery_callback(message: Message):
            self.handle_LXMF_message(message)

        logger.info('Bridge is ready!')

        # Because anyone can make an identity on LXM, I would rather limit
        # the number of messages that get sent to the mesh as opposed to 
        # the other way around
        self.LXMF_global_cooldown = AntiSpam()

        self.router.enable_propagation()

    def create_interface(self):
        """
        Create the meshtastic interface.
        Here, we try the remote address, then if it fails, the serial interface,
        then the automatic serial interface as a last resort. 
        """

        remote_address = config["meshtastic"]["remote"]
        serial_port = config["meshtastic"]["serial"]
     
        if remote_address:
            interface = meshtastic.tcp_interface.TCPInterface(hostname=remote_address)    
        elif serial_port:
            interface = meshtastic.serial_interface.SerialInterface(devPath=serial_port)
        else:
            interface = meshtastic.serial_interface.SerialInterface()
        
        assert hasattr(interface, "stream"), "Could not detect & open a meshtastic device via wifi or serial..."
        pub.subscribe(self.onReceive, 'meshtastic.receive')
        return interface

    def create_router(self, user: MeshtasticNode):
        """
        Each meshtastic user has an associated LXMF address. This function
        creates a reticulum router that other LXMF users can send messages to.

        By default, on receive, the router sends any received messages to the 
        meshtastic network.
        """
        if user.node_id in self.routers:
            del self.routers[str(user.node_id)]

        identity = self.meshtastic_user_to_identity(user)
        router = LXMF.LXMRouter(identity, storagepath=self.storage_path)

        def send_to_meshtastic_node(lxmessage: LXMF.LXMessage):
            logger.info("Received message from LXMF")
            to_node = str(user.node_id)
            
            content = lxmessage.content_as_string()
            message_source = lxmessage.source_hash

            assert isinstance(message_source, bytes), "bad hash"
            assert isinstance(content, str), "bad message"
            from_display_name = self.get_name(message_source)
            from_display_name = ''.join(c for c in from_display_name.decode('ascii', errors='ignore') if c.isprintable())

            msg = f"{from_display_name}: {content}"
            
            if not self.LXMF_global_cooldown.try_perform_action():
                logger.info("Blocked message due to cooldown")
                source = list(router.delivery_destinations.values())[0]
                router.announce(source.hash)
                message = Message(lxmessage, router, source, self.get_name)
                message.author.send(f"Sorry, a global cooldown has been activated to prevent spam from reaching the meshtastic network. Current cooldown timer is {int(self.LXMF_global_cooldown.cooldown)} seconds")
                return
            
            logger.info(msg)
            self.mesh.interface.sendText(profanity.censor(msg), to_node, wantAck=True)

        router.register_delivery_callback(send_to_meshtastic_node)
        self.routers[str(user.node_id)] = router

        source = router.register_delivery_identity(
            identity,
            display_name=user.long_name
        )

        router.announce(source.hash) # type: ignore

        logger.info(f"Ready to receive messages for {user.long_name}")

    def build_routers(self):
        """
        For each user, create a router; see self.create_router for why
        """
        for user in MeshtasticNode.select():
            self.create_router(user)

    def handle_LXMF_message(self, message:Message):
        """
        This function handles messages that are sent to the bridge via LXMF.
        """
        logger.info(f'Received LXMF message: "{message.content}"')
        user = LXMFUser.get_or_none(LXMFUser.identity_hash==base64.b64encode(message.author.identity_hash))
        if user is None:
            display_name = message.author.display_name
            user = LXMFUser.create(
                identity_hash = base64.b64encode(message.author.identity_hash),
                name = "UNK" if display_name is None else display_name,
                is_subscribed = False,
                log = "{}"
            )

        log = json.loads(user.log)

        if not message.content.startswith("/"):
            message.author.send("Please type '/help' to view available commands.")

        if message.content == "/help":
            message.author.send("Commands:\n/help, shows available commands\n/listen, start receiving messages\n/stop, stop receiving messages\n/send <message>, send a message to the public channel\n/whoami, shows user configuration")
            return
        
        if message.content == "/listen":
            user.is_subscribed = True
            user.save()
            message.author.send("Congrats! You are now listening to the public channel!")
            return

        if message.content == "/stop":
            user.is_subscribed = False
            user.save()
            message.author.send("Stopped sharing the public channel!")
            return
        
        if message.content == "/whoami":
            message.author.send(f"You are '{user.name}'.\nYou are {'not ' if not user.is_subscribed else ''}subscribed")
            return
        
        if message.content.startswith("/send"):

            if not self.LXMF_global_cooldown.try_perform_action():
                message.author.send(f"Sorry, a global cooldown has been activated to prevent spam from reaching the meshtastic network. Current cooldown timer is {int(self.LXMF_global_cooldown.cooldown)} seconds")
                return

            if user.name == "UNK":
                message.author.send("Sorry, to prevent spam, we need your RNS identity first.\nYou can try announcing it, but it may take a while for it to propagate through the network...")
            else:
                msg = message.content.split("/send")[-1]
                if len(msg):
                    msg = f"{message.author.display_name}: {msg}"
                    self.mesh.interface.sendText(profanity.censor(msg), wantAck=True)
                    message.author.send("Your message has been sent!")
                else:
                    message.author.send("Use the send command as /send <your message here>")
            return
        

    def handle_LXMF_index(self, path:str, link:RNS.Link):
        """
        This function handles the 'index.mu' nomadnet page request.
        """
        try:
            return create_canvas(self.mesh.interface, self.router, self.routers).render().encode("utf-8")
        except Exception as e:
            print(traceback.format_exc())
            logger.warning(f"Could not serve page: {e}")
            return "Sorry, but an internal server error occurred...".encode("utf-8")

    def handle_meshtastic_message(self, user:MeshtasticNode, message:str, from_id:str):
        """
        This function handles meshtastic users sending messages to the bridge over the meshtastic network. 
        """
        if not message.startswith("/"):
            self.mesh.interface.sendText('Hi!\nThis is a bridge node for LXMF.\nType /info or /help for more information', from_id, wantAck=True)
            return

        if message.startswith("/info"):
            self.mesh.interface.sendText('This bot was made to allow meshtastic users to send LXMF messages; which is kind of like an email system for nerds.', from_id, wantAck=True)

        if message.startswith("/help"):
            self.mesh.interface.sendText('Commands:\n/register <base32 key>, load an existing identity\n/deregister, remove identity\n/send <LXMF id> <message>, send a message to a node', from_id, wantAck=True)

        if message.startswith("/register"):
            try:
                key = message.split("/register")[1]
                identity = RNS.Identity.from_bytes(base64.b32decode(key[:128]))
            except:
                self.mesh.interface.sendText('Sorry, your provided identity could not be loaded.', from_id, wantAck=True)
                return 
            
            user.lxmf_identity = key # type: ignore
            user.save()

            self.mesh.interface.sendText('Successfully loaded your identity!', from_id, wantAck=True)
            return

        if message.startswith("/deregister"):
            if user.lxmf_identity is None:
                self.mesh.interface.sendText('No identity to deregister!', from_id, wantAck=True)
                return
            
        if message.startswith("/send"):
            try:
                command, dst_node, to_send = message.split(" ")[0], message.split(" ")[1], " ".join(message.split(" ")[2:])
            except:
                self.mesh.interface.sendText('Invalid command structure, please see /help.', from_id, wantAck=True)
                return
            
            # Handle special edge case where the user tries sending a message to bridge via the bridge
            if dst_node == self.source.hash.hex(): # type: ignore
                self.mesh.interface.sendText('https://imgflip.com/i/7ogz7h', from_id, wantAck=True)
                return
            
            identity = self.meshtastic_user_to_identity(user)
            router = self.routers.get(str(user.node_id), None)
            if router is None:
                self.mesh.interface.sendText('Your router does not exist?', from_id, wantAck=True)
                return
                        
            destination = RNS.Destination(
                RNS.Identity.recall(bytes.fromhex(dst_node)),
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery"
            )

            # A low key hacky way to get the LXMF address from the reticulum router object
            source = list(router.delivery_destinations.values())[0]
            router.announce(source.hash)

            lxm = LXMF.LXMessage(
                destination,
                source,
                profanity.censor(to_send),
                desired_method=LXMF.LXMessage.OPPORTUNISTIC,
                include_ticket=True
            )
            router.handle_outbound(lxm)

            self.mesh.interface.sendText('Sent!', from_id, wantAck=True)

    def meshtastic_user_to_identity(self, user: MeshtasticNode):
        """
        Provides a repeatable way to convert a meshtastic node into a
        reticulum identity. This is later used to listen to incoming
        LXMF messages.
        """
        if user.node_id in self.routers:
            return self.routers[str(user.node_id)].identity

        if user.lxmf_identity is None:
            logger.info("Building user identity from public key")
            return self.meshtastic_public_to_identity(str(user.public_key))
        else:
            logger.info("Building user identity from custom identity")
            return RNS.Identity.from_bytes(base64.b32decode(str(user.lxmf_identity)))

    def create_keys(self, seed: bytes):
        """
        A hacky way to deterministically convert a 'seed' (32 bytes) into 
        a valid reticulum private key.
        """
        assert len(seed) == 32, f"Seed must be 32 bytes, got {len(seed)}"

        self.prv = X25519PrivateKey.from_private_bytes(seed)
        self.prv_bytes = self.prv.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption()
        )

        self.sig_prv = Ed25519PrivateKey.from_private_bytes(seed)
        self.sig_prv_bytes = self.sig_prv.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption()
        )

        return self.prv_bytes+self.sig_prv_bytes

    def meshtastic_public_to_identity(self, public_key:str):
        return RNS.Identity.from_bytes(
            self.create_keys(
                hashlib.sha256((public_key + str(SECRET)).encode("utf-8")).digest()
                )
            )

    def onReceive(self, packet, interface:meshtastic.tcp_interface.TCPInterface):
        """
        Handles meshtastic users sending messages to the bridge over the meshtastic network.
        """
        assert isinstance(interface.nodes, dict), "interface nodes not loaded?"
        raw_node = interface.nodes.get(packet["fromId"], None)
        if raw_node is None:
            return
        
        if not ('decoded' in packet and packet['decoded']['portnum'] == 'TEXT_MESSAGE_APP'):
            return
        
        # If we found ourself in the public channel
        out_node_info = interface.getMyNodeInfo()
        if not isinstance(out_node_info, dict):
            logger.warning("Node info was none, broken pipe?")
            return

        our_node_id = out_node_info.get("user", {}).get("id", None)

        if our_node_id is None or packet["fromId"] == our_node_id:
            return
        
        # Remember the meshtastic node that messages us. By default, they are 'hidden' from LXMF until
        # we receive their '/listen' command in order to best preserve their privacy.
        mesh_node:MeshtasticNode = MeshtasticNode.get_or_none(MeshtasticNode.node_id==raw_node["user"]["id"])
        if mesh_node is None:
            mesh_node = MeshtasticNode.create(
                node_id = raw_node["user"]["id"],
                long_name = raw_node["user"]["longName"],
                short_name = raw_node["user"]["shortName"],
                last_seen = int(time.time()),
                public_key = raw_node["user"]["publicKey"],
                lxmf_identity = None
            )
        else:
            # Update the names in the event that the node updated them
            mesh_node.long_name = raw_node["user"]["longName"]
            mesh_node.short_name = raw_node["user"]["shortName"]
            mesh_node.last_seen = int(time.time()) # type: ignore
            mesh_node.public_key = raw_node["user"]["publicKey"]
            mesh_node.save()

        message_bytes = packet['decoded']['payload']
        try:
            message_string:str = message_bytes.decode('utf-8')
        except:
            return
        
        logger.info(f'Received meshtastic message: "{message_string}"')
    
        MeshtasticMessage.create(
            author = mesh_node,
            content = message_string,
            received = int(time.time())
        )

        if not packet["toId"] == meshtastic.BROADCAST_ADDR:
            if packet["toId"] == our_node_id:
                self.handle_meshtastic_message(mesh_node, message_string, packet["fromId"])
            return
        
        # Edge case where a meshtastic user tries (?) to contact us via the public channel
        if "@brdg" in message_string.lower():
            interface.sendText('Hi! This is an automated response because you mentioned me.\nPlease DM me with "/info" if you want to know what I do.', packet["toId"], wantAck=True)
        
        count = LXMFUser.select().where(LXMFUser.is_subscribed==True).count()
        logger.info(f'Alerting {count} LXMF users of the incoming message...')

        assert isinstance(self.source, RNS.Destination), "source not loaded"

        for lxmf_user in LXMFUser.select():
            lxmf_user: LXMFUser

            if lxmf_user.is_subscribed:
                dest = Author(
                    base64.b64decode(str(lxmf_user.identity_hash)), 
                    self.router, 
                    self.source
                )

                dest.send(f"{raw_node['user']['longName']}: {profanity.censor(message_string)}")

        logger.info(f'Done')

if __name__ == "__main__":
    Bridge(app_name = config['bridge']['name'], storage_path="tmp").run()
