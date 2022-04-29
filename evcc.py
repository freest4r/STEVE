import socket, sys, subprocess, time, ssl
from turtle import end_fill
import xml.etree.ElementTree as ET
import sys, errno, base64, hashlib
from logs import *
from V2GTP import *
from globals import *

class EVCC:
    def __init__(self, ip_addr, iface):
        logging.info("Initialize EVCC.")
        self.ip_addr = ip_addr
        self.iface = iface
        self.udp_port = UDPPORT
        self.tcp_port = None
        self.tls_port = None
        self.tls = False
        self.genchallenge = None
        self.cert = CONTRACT_CERT
        self.recv_data = None
        self.sessionID = None
        self.charge_progress = None

    def UDPConnect(self):
        #logger.debug(f"UDP Connect to {self.ip_addr} {self.udp_port}")
        try:
            #macOSX(m1)
            self.sock_udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
            self.sock_udp.connect((self.ip_addr, self.udp_port, 0, 11))
            #Ubuntu
            #self.sock_udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
            #self.sock_udp.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)
            #self.sock_udp.connect((self.ip_addr, self.udp_port))#, 0, 11))
        except Exception as e:
            logger.error("UDPConnect ERROR")
            logger.error(e)
            sys.exit(1)

    def TCPConnect(self):
        logger.info(f"[TCPConnect] {self.ip_addr}:{self.tcp_port}")
        try:
            #macOSX(m1)
            self.sock_tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.sock_tcp.connect((self.ip_addr, self.tcp_port, 0, 11))
            self.sock_tcp.settimeout(5)
            #Ubuntu
            #self.sock_tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            #self.sock_tcp.setsockopt(socket.SOL_SOCKET, 25, INTERFACE)
            #self.sock_tcp.connect((self.ip_addr, self.tcp_port))#, 0, 11))
            return True
        except Exception as e:
            logger.error("TCPConnect ERROR")
            logger.error(e)
            return False
    
    def Disconnect(self):
        logger.info("TCP/UDP socket closed")
        self.sock_tcp.close()
        self.sock_udp.close()

    def send(self, payload, protocol):
        try:
            if protocol == "udp":
                #logger.debug(f"UDP -> {payload}")
                self.sock_udp.send(payload)
                self.recv_data = self.sock_udp.recv(4028)
                #logger.debug(f"UDP <- {self.recv_data}")
            elif protocol == "tcp":
                #logger.debug(f"TCP -> {payload}")
                self.sock_tcp.send(payload)
                self.recv_data = self.sock_tcp.recv(4028)
                #logger.debug(f"TCP <- {self.recv_data}")
            elif protocol == "tls":
                self.sock_tls.send(payload)
                self.recv_data = self.sock_tls.recv(4028)
            else:
                logger.error("Unsupported protocol")
                sys.exit(1)

            if self.recv_data == b'':
                raise Exception("empty data")
        except Exception as e:
            logger.error(e)
            return e
        return True

    def runCMD(self, cmd):
        ret=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (payload, err) = ret.communicate()
        return payload
    
    def XMLtoEXI(self, xmldata, gram, mode):
        if mode == "f":
            cmd = "java -jar "+EXI_XML_jar+" -e -f "+xmldata+" -g "+gram
        else:
            cmd = "java -jar "+EXI_XML_jar+" -e -i '"+xmldata+"' -g "+gram
        exidata = self.runCMD(cmd)
        return exidata

    def EXItoXML(self, exidata, gram, mode):
        if mode == "f":
            cmd = "java -jar "+EXI_XML_jar+" -d -f '"+exidata+"' -g "+gram
        else:
            cmd = "java -jar "+EXI_XML_jar+" -d -i '"+exidata+"' -g "+gram
        xmldata = self.runCMD(cmd)
        if "error" in xmldata.decode("utf-8"):
            logging.error("EXI decode error")
            logging.error(cmd)
            logging.error(xmldata.decode("utf-8"))
            sys.exit(1)
        return xmldata
    
    def getDefaultXML(self, reqName):
        return ET.parse(XMLPATH+reqName+".xml").getroot()

    def setSessionID(self, root):
        root.find("*/{*}SessionID").text = self.sessionID
        return root

    def sendV2Gmsg(self, root, gramfile):
        xmldata = ET.tostring(root).decode("utf-8")
        exidata = self.XMLtoEXI(xmldata, gramfile, 'stdout')
        v2gtp_msg = V2GTP(V2GTP_VERSION, V2GTP_INVERSE_VERSION, V2GTP_EXI_ENC_MSG, exidata).v2gtp_msg
        ret = self.send(v2gtp_msg, 'tcp')
        if ret == True:
            retxml = self.EXItoXML(self.recv_data[8:].hex(), gramfile, 'stdout')
            return retxml.decode("utf-8")
        return ret

    def SECCDiscoveryReq(self, tls=False):
        logger.info("[SECCDiscovery]")
        if tls:
            payload = struct.pack(">BB", 0x00, 0x00)#0x00,0x00 -> TLS
        else:
            payload = struct.pack(">BB", 0x01, 0x00)#0x01,0x00 -> TCP
            
        v2gtp_msg = V2GTP(V2GTP_VERSION, V2GTP_INVERSE_VERSION, V2GTP_SDP_REQ_MSG, payload)
        self.UDPConnect()
        ret = self.send(v2gtp_msg.v2gtp_msg, "udp")
        if ret == True:
            if tls and self.recv_data[26] == 0:
                self.tls_port = int.from_bytes(self.recv_data[24:26], 'big')
                self.tls = True
            elif not tls and self.recv_data[26] == 1:
                self.tcp_port = int.from_bytes(self.recv_data[24:26], 'big')
                self.tls = False
            else:
                logger.error("SECC Discovery exception")
                logger.error(self.recv_data)
                sys.exit(1)
            security = self.recv_data[26]
            if security == 0x10: # No transport layer security
                logger.error("No transport layer security")
            return True
        return False

    def SupportedAppProtocolReq(self):
        logger.info("[SupportedAppProtocolReq]")
        root = self.getDefaultXML("SupportedAppProtocolReq")
        retxml = self.sendV2Gmsg(root, V2G_CI_AppProtocol_XSD)
        if retxml == False:
            return -1
        root = ET.fromstring(retxml)
        responseCode = root.find("ResponseCode")
        if responseCode == None or "Failed" in responseCode.text:
            logger.error(responseCode.text)
            return -1
        return retxml

    def SessionSetupReq(self):
        logger.info("[SessionSetupReq]")
        root = self.getDefaultXML("SessionSetupReq")
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        root = ET.fromstring(retxml)#.decode("utf-8"))
        if "SessionID" in root[0][0].tag:
            self.sessionID = root[0][0].text
            logger.info("SessionID:"+self.sessionID)
        else:
            logger.error("Exception. Cannot find SessionID")
            logger.error(retxml)
            sys.exit(1)
        return retxml
    
    def ServiceDiscoveryReq(self):
        logger.info("[ServiceDiscoveryReq]")
        root = self.getDefaultXML("ServiceDiscoveryReq")
        root = self.setSessionID(root)
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        return retxml

    def PaymentServiceSelectionReq(self):
        logger.info("[PaymentServiceSelectionReq]")
        root = self.getDefaultXML("PaymentServiceSelectionReq")
        root = self.setSessionID(root)
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        return retxml

    def PaymentDetailsReq(self):
        logger.info("[PaymentDetailsReq]")
        root = self.getDefaultXML("PaymentDetailsReq")
        root = self.setSessionID(root)
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        root = ET.fromstring(retxml)
        self.genchallenge = root.find("*/*/{*}GenChallenge").text
        return retxml

    def AuthorizationReq(self):
        logger.info("[AuthorizationReq]")
        root = self.getDefaultXML("AuthorizationReq")
        root = self.setSessionID(root)
        if self.genchallenge != None:
            root.find("*/*/{*}GenChallenge").text = self.genchallenge

        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        return retxml

    def ChargeParameterDiscoveryReq(self):
        logger.info("[ChargeParameterDiscoveryReq]")
        root = self.getDefaultXML("ChargeParameterDiscoveryReq")
        root = self.setSessionID(root)
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        return retxml

    def PowerDeliveryReq(self, val):
        logger.info("[PowerDeliveryReq]")
        root = self.getDefaultXML("PowerDeliveryReq")
        root = self.setSessionID(root)
        root.find("*/*/{*}ChargeProgress").text = val
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        return retxml

    def ChargingStatusReq(self):
        logger.info("[ChargingStatusReq]")
        root = self.getDefaultXML("ChargingStatusReq")
        root = self.setSessionID(root)
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        root = ET.fromstring(retxml)
        TMeter = root.find("*/*/{*}MeterInfo/{*}TMeter").text
        logger.info(TMeter)
        return retxml

    def SessionStopReq(self):
        logger.info("[SessionStopReq]")#add session ID to stop session
        root = self.getDefaultXML("SessionStopReq")
        root = self.setSessionID(root)
        retxml = self.sendV2Gmsg(root, V2G_CI_MsgDef)
        if retxml == False:
            return -1
        self.Disconnect()
        return retxml
        
    def do_normal_process(self):
        logger.info("check fail"+"="*100)
        try:
            self.SECCDiscoveryReq(False)
            self.TCPConnect()
            if self.SupportedAppProtocolReq() == -1:
                raise Exception("SupportedAppProtocolReq failed")
            self.SessionSetupReq()
            self.SessionStopReq()
            return True
        except Exception as e:
            logger.error(e)
            return False    
        
if __name__ == "__main__":
    #ip_addr = "fe80:0:0:0:1c56:8543:61aa:30c0"#%en0
    ip_addr = "fe80:0:0:0:1c56:8543:61aa:30c0"
   
    evcc = EVCC(ip_addr)
    evcc.SECCDiscoveryReq(False)
    
    evcc.TCPConnect()
    evcc.SupportedAppProtocolReq()
    evcc.SessionSetupReq()
    evcc.ServiceDiscoveryReq()
    evcc.PaymentServiceSelectionReq()
    #evcc.PaymentDetailsReq()
    evcc.AuthorizationReq()
    evcc.ChargeParameterDiscoveryReq()
    evcc.PowerDeliveryReq("Start")
    for i in range(0, 1000):
        evcc.ChargingStatusReq()
    evcc.PowerDeliveryReq("Stop")
        
    evcc.SessionStopReq()
    
