"""
The meshtastic devs, in their infinite wisdom, decided to put the meshtastic heartbeat on a separate thread.
This is fine and dandy until the connection drops and the heartbeat fails, which does raise an exception, but is never caught.

Here, we setup a communication channel that exposes an 'is_alive' method that can be used to reset the interface on error.
Very useful over unstable wifi connections.

If you are still having issues, you may need to switch to a serial (USB) connection to the meshtastic node.  
"""
from log_f import logger
import meshtastic
import threading, time
import meshtastic.mesh_interface
from meshtastic.protobuf import mesh_pb2
import meshtastic.tcp_interface

class Injector:
    def __init__(self, interface_generator):
        self.interface_generator = interface_generator
        self.inject_interface()

    def inject_interface(self):
        
        while True:
            try:
                self.interface:meshtastic.tcp_interface.TCPInterface = self.interface_generator()
                break
            except:
                logger.warning("Meshtastic interface creation failed, retrying...")
            
            time.sleep(10)

        self.interface.sendHeartbeat = self.customsendHeartbeat
        logger.info(f"Successfully injected custom heartbeat")

    def customsendHeartbeat(self):
        try:
            self.interface.socket = None
            p = mesh_pb2.ToRadio()
            p.heartbeat.CopyFrom(mesh_pb2.Heartbeat())
            self.interface._sendToRadio(p)  
        except Exception as e:
            del self.interface
            self.inject_interface()


if __name__ == "__main__":
    def generator():
        interface = meshtastic.tcp_interface.TCPInterface("192.168.2.169")
        return interface
    
    Injector(generator)

    while True:
        time.sleep(1)
