#!/usr/bin/env python3
import subprocess
import datetime
import os
import mimetypes
import uuid
import http.client
import json
from urllib.parse import urlparse

# CONFIGURATION
RRD_FILE = "/var/log/rrd/collectd/localhost/interface-red0/if_octets.rrd"
OUTPUT_PNG = "/tmp/netother.png"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/XXXXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"      # Add Discord keys here

# TIME RANGE ( last 24H )
end_time = int(datetime.datetime.now().timestamp())
start_time = end_time - 86400

# BUILD RRDTOOL COMMAND
cmd = [
    "rrdtool", "graph", OUTPUT_PNG,
    "--start", str(start_time),
    "--end", str(end_time),
    "--title", "IPFire Net-Other Traffic (Last 24h)",
    "--width", "800",
    "--height", "200",
    "--vertical-label=Bytes/s",
    f"DEF:rx_bytes={RRD_FILE}:rx:AVERAGE",
    f"DEF:tx_bytes={RRD_FILE}:tx:AVERAGE",
    "LINE1:rx_bytes#00FF00:Inbound",
    "LINE1:tx_bytes#0000FF:Outbound"
]
subprocess.run(cmd, check=True)

# PREPARE MULTIPART BODY
u = urlparse(DISCORD_WEBHOOK_URL)
boundary = uuid.uuid4().hex
headers = {
    "Content-Type": f"multipart/form-data; boundary={boundary}"
}

# Payload JSON (message content)
payload = {
    "content": "📊 IPFire Net-Other Traffic Graph",
    "attachments": [
        {"id": 0, "filename": os.path.basename(OUTPUT_PNG)}
    ]
}
payload_part = (
    f"--{boundary}\r\n"
    'Content-Disposition: form-data; name="payload_json"\r\n\r\n'
    f"{json.dumps(payload)}\r\n"
).encode("utf-8")

# File part
with open(OUTPUT_PNG, "rb") as f:
    file_data = f.read()
file_mime = mimetypes.guess_type(OUTPUT_PNG)[0] or "application/octet-stream"
file_part = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="files[0]"; filename="{os.path.basename(OUTPUT_PNG)}"\r\n'
    f"Content-Type: {file_mime}\r\n\r\n"
).encode("utf-8") + file_data + b"\r\n"

# End boundary
end_part = f"--{boundary}--\r\n".encode("utf-8")

# Full body
body = payload_part + file_part + end_part

# SEND HTTP POST
conn = http.client.HTTPSConnection(u.netloc)
conn.request("POST", u.path, body=body, headers=headers)
resp = conn.getresponse()
print(resp.status, resp.reason, resp.read().decode())
