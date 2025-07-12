from LXMKit.mu import *
from db import MeshtasticNode
from log_f import logger
from config import config
import time
from meshtastic.stream_interface import StreamInterface

logo = r"""
    __  ___          __    ____       _     __         
   /  |/  /__  _____/ /_  / __ )_____(_)___/ /___ ____ 
  / /|_/ / _ \\/ ___/ __ \\/ __  / ___/ / __  / __  / _ \\
 / /  / /  __(__  ) / / / /_/ / /  / / /_/ / /_/ /  __/
/_/  /_/\\___/____/_/ /_/_____/_/  /_/\\__,_/\\__, /\\___/ 
                                          /____/       
"""


def format_string(text, target_length):
    text = ''.join([i if ord(i) < 128 else ' ' for i in text])
    if len(text) > target_length:
        return text[:target_length-3] + "..."
    return text.ljust(target_length)

def create_canvas(meshtastic_interface:StreamInterface, primary_router, routers=[]):
    
    nodes = meshtastic_interface.nodes
    assert isinstance(nodes, dict), "interface nodes not loaded?"

    # get nodes that were heard in the last hour
    active_node_ids = [i for i in nodes if nodes[i].get("lastHeard", 0) > time.time() - 60*60]
    num_active_nodes = len(active_node_ids)
    num_total_nodes = len(nodes)

    available = []
    for node_id, router in routers.items():
        node = MeshtasticNode.get_or_none(MeshtasticNode.node_id == node_id)

        if node is None:
            continue

        name = f"({format_string(node.short_name, 4)}) {format_string(node.long_name, 32)}"
        dst = str(list(router.delivery_destinations.values())[0].hash.hex())
        name = f"`[{name}`lxmf@{dst}]"

        online = Paragraph("\\[ONLINE ] ", [BOLD, FOREGROUND_GREEN])
        offline = Paragraph("\\[OFFLINE] ", [BOLD, FOREGROUND_RED])
        
        available.append(
            Span(
                [
                    online if node_id in active_node_ids else offline,
                    Paragraph(name, style=[ITALIC]),
                ],
                style = [CENTER]
            )
        )
    
    if len(available) == 0:
        available = [
            Paragraph("No nodes loaded...")
        ]
    else:
        available.append(Br())

    our_dest = str(list(primary_router.delivery_destinations.values())[0].hash.hex())

    custom_message = []
    if config["personal"]['custom_message']:
        custom_message = [
            Paragraph(config["personal"]['custom_message']),
            Br()
        ]

    develop_msg = []
    if config["advanced"]["developing"]:
        develop_msg = [
            Paragraph("THIS BRIDGE IS UNDERGOING ACTIVE MAINTENANCE", [BACKGROUND_RED, FOREGROUND_BLACK]),
            Paragraph("Please be patient...", [BACKGROUND_RED, FOREGROUND_BLACK, ITALIC])
        ]

    

    return Micron(
        subnodes=[
            Div(
                subnodes = [
                    Paragraph(logo, style=[FOREGROUND_LIGHT_GREY, CENTER]),
                    Br(),
                    Header(
                        content="What is this?",
                        subnodes=[
                            Paragraph(f"This is an experimental 'bridge' between the Meshtastic network in {config['bridge']['location']} and LXM. When running, LXM clients can send messages to the mesh and vise-versa. Message `[`lxmf@{our_dest}] with '/help' to see more details."),
                            Br(),
                            Paragraph("Please note that development is still underway, so bugs are expected.", style=[FOREGROUND_RED]),
                            Br(),
                        ] + develop_msg
                    ),
                    Br(),
                    Header(
                        content="More info",
                        subnodes=[
                            Paragraph("You can read the source code (and more) here: https://github.com/Aveygo/LXMBridge"),
                            Br(),
                            Paragraph(f"This bridge is run by {config['personal']['name']}."),
                            Br(),
                        ] + custom_message
                    ),
                    Br(),
                    Header(
                        content="Meshtastic Network Health",
                        subnodes=[
                            Paragraph(f"There are currently {num_active_nodes}/{num_total_nodes} active nodes on the network."),
                            Br(),
                        ]
                    ),
                    Br(),
                    Header(
                        content = "Available Nodes",
                        subnodes = [
                            Br(),
                            Paragraph("Below is a list of registered meshtastic nodes and their associated LXM addresses. By sending a message to to one of these addresses, the bridge will (hopefully) relay it to that node."),
                            Br(),
                            Paragraph("(Unicode characters have been removed...)", style=[ITALIC]),
                            Br(),
                            Hr(),
                            Div(
                                available
                            ),
                            Hr(),
                            Br(),
                            Paragraph(f"If you are in {config['bridge']['location']} and want to be added to this list, please direct message this bridge node with /listen over in the meshtastic network."),
                            Br(),
                            Br(),
                            Br(),   
                        ]
                    )

                ]
            )
        ]
    )

        