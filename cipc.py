import struct
from loguru import logger as l


class CIPC_Message():

    def __init__(self):
        self.message = []
        self.tlv_bytes = b''

    def __generate_header(self):
        self.header = struct.pack("<IHHIIIIBB",
                                  0x4353434f,             # ID Tag
                                  26,                     # Header Length
                                  len(self.tlv_bytes),    # Data Length
                                  0xffffffff,             # IPC response CB
                                  0x00000000,             # Message User Context
                                  0x00000002,             # Request Message ID
                                  0x00000000,             # Return IPC Object
                                  1,                      # Message Type
                                  2,                      # Message ID
                                  )
        l.debug("--- CIPC HEADER ---")
        l.debug(self.header)

    def __generate_tlv_bytes(self):
        for idx, m in enumerate(self.message):
            msg_value = m['value'].encode("utf-8") + b'\x00'
            tlv_header = struct.pack(">BBH",
                                     m['type'],
                                     m['index'],
                                     len(msg_value),
                                     )
            l.debug(f"------TLV: {idx+1}------")
            l.debug(f"---( HEADER {len(tlv_header)} bytes)----")
            l.debug(tlv_header)
            l.debug(f"---( MESSAGE {len(msg_value)} bytes)---")
            l.debug(msg_value)
            l.debug("-----------------")
            self.tlv_bytes += tlv_header + msg_value
        l.debug(f"tlv_bytes is now: {len(self.tlv_bytes)} bytes.")

    def append(self, msg_type: int, msg_index: int, msg_value: str):
        self.message.append({
            "type": msg_type,
            "index": msg_index,
            "value": msg_value
        })

    def as_bytes(self) -> bytes:
        self.__generate_tlv_bytes()
        self.__generate_header()
        return self.header + self.tlv_bytes
