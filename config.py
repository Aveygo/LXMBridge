"""
You are probably looking for config.toml, not config.py
This python script loads data from that file.
"""

import toml, os

if os.path.exists("dev.toml"):
    path = "dev.toml" # Just for development; if you are reading this then stick to config.toml
else:
    path = "config.toml"    

with open(path, 'r') as f:
    config = toml.load(f)