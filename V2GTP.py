import struct

class V2GTP:
    def __init__(self, protocol_ver, inv_protocol_ver, payload_type, payload):
        self.protocol_ver = protocol_ver
        self.inv_protocol_ver = inv_protocol_ver
        self.payload_type = payload_type
        self.payload = payload
        self.payload_len = len(payload)
        self.v2gtp_msg = struct.pack(
            ">BBHI",
            self.protocol_ver,
            self.inv_protocol_ver,
            self.payload_type,
            self.payload_len,
            ) + self.payload

