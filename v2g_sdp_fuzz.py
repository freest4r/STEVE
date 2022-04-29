import socket, sys, os
from logs import *
from V2GTP import *
from globals import *

class V2GSDPFuzzer:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.udp_port = UDPPORT
        self.recv_data = None

    def generate_testcases(self):
        logger.info("Generate testcases ...")
        ######
        self.pro_ver = [0x01]
        self.inv_pro_ver = [0xfe]
        self.payload_type = [0x8001, 0x9000, 0x9001]
        self.payload = []
        #SECC discovery req msg payload (fig 15, table 16)
        for s in [b'\x00', b'\x01', b'\x0f', b'\x10', b'\x11', b'\xff']:
            for t in [b'\x00', b'\x01', b'\x0f', b'\x10', b'\x11', b'\xff']:
                self.payload.append((struct.pack(">I", 2),s+t))
        for i in range(100000):
            d = os.urandom(2)
            self.payload.append((struct.pack(">I", 2),d))
        #SECC Discovery req msg payload for PPD (fig 16, table 17)
        for s in [b'\x00', b'\x01']:  
            for t in [b'\x00', b'\x01']:
                self.payload.append((struct.pack(">I", 22),s+t+os.urandom(20)))
        for i in range(100000):
            d = os.urandom(22)
            self.payload.append((struct.pack(">I", 22),d))
        #random payload
        for i in [0x00, 0x01, 0xff, 0x0400]:
            for j in range(0,100000):
                self.payload.append((struct.pack(">I", i), os.urandom(i)))
        #random payload, wrong length
        self.payload.append((struct.pack(">I", 0), os.urandom(0x2400-8)))
        self.payload.append((struct.pack(">I", 0), os.urandom(0x2400-9)))
        self.payload.append((struct.pack(">I", 2), b'\x00'))
        self.payload.append((struct.pack(">I", 2), b'\xff'))
        self.payload.append((struct.pack(">I", 2), os.urandom(0x2400-8)))
        self.payload.append((struct.pack(">I", 2), os.urandom(0x2400-9)))
        self.payload.append((struct.pack(">I", 22), b'\x00'))
        self.payload.append((struct.pack(">I", 22), b'\xff'))
        self.payload.append((struct.pack(">I", 22), os.urandom(0x2400-8)))
        self.payload.append((struct.pack(">I", 22), os.urandom(0x2400-9)))
        self.payload.append((struct.pack(">I", 0xffffffff),b'\x00'))
        self.payload.append((struct.pack(">I", 0xffffffff),os.urandom(0x2400-8)))
        self.payload.append((struct.pack(">I", 0xffffffff),os.urandom(0x2400-9)))
 
        logger.info(f"{len(self.payload)*len(self.inv_pro_ver)*len(self.payload_type)} testcases are generated.")
 
    def connect(self):
        logger.info(f"Connect to {self.ip_addr}")
        try:
            self.sock_udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
            self.sock_udp.connect((self.ip_addr, UDPPORT, 0, 11))
        except Exception as e:
            logger.error("ERROR")
            logger.error(e)
            sys.exit(1)
        logger.info("Done.\n")

    def send(self, payload):
        try:
            self.sock_udp.send(payload)
        except Exception as e:
            logger.error("FAIL")
            logger.error(e)
            sys.exit(1)
        return 1
    #Check SECC is alive by transmitting valid SECCDiscoveryReq.
    def check_fail(self):
        payload = struct.pack(">BB", 0x01, 0x00)#0x01,0x00 -> TCP    
        v2gtp_msg = V2GTP(V2GTP_VERSION, V2GTP_INVERSE_VERSION, V2GTP_SDP_REQ_MSG, payload)
        try:
            self.sock_udp.send(v2gtp_msg.v2gtp_msg)
            ret = self.sock_udp.recv(1024)
            if len(ret) != 28:
                return "FAIL"
            port = int.from_bytes(ret[24:26], 'big')
        except Exception as e:
            logger.error(e)
            return "FAIL"

    def fuzz(self):
        i=0
        for pro_ver in self.pro_ver:
            for inv_pro_ver in self.inv_pro_ver:
                for payload_type in self.payload_type:
                    for payload in self.payload:
                        i+=1
                        if i%1000==0:
                            logger.info(f"{i}/{len(self.payload)*len(self.inv_pro_ver)*len(self.payload_type)}")
                        self.tc = struct.pack(">BBH",pro_ver,inv_pro_ver,payload_type)
                        self.tc += payload[0]
                        self.tc += payload[1]
                        ret = self.send(self.tc)
                        result = self.check_fail()
                        if result == 'FAIL':
                            sys.exit(1)
        logger.info(f"{i}/{len(self.payload)*len(self.inv_pro_ver)*len(self.payload_type)}")

if __name__ == "__main__":
    ip_addr = "fe80:0:0:0:1c56:8543:61aa:30c0"#sys.argv[1]
    f = V2GSDPFuzzer(ip_addr)
    f.connect()
    f.generate_testcases()
    f.fuzz()
