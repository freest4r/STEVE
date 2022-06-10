import xml.etree.ElementTree as ET
import time, subprocess, re, argparse, sys
from scapy.all import *
from datetime import datetime
from evcc import *
from v2g_sdp_fuzz import *

class STEVE:
    def __init__(self, ip, iface):
        self.evcc=EVCC(ip, iface)

    def RESET_SECC(self):
        logger.info("RESET SECC")
        subprocess.Popen(["pkill","-f", "java -jar target/rise-v2g-secc-1.2.6.jar"])
        time.sleep(1)
        subprocess.Popen(["./runRISE_SECC.sh"])
        time.sleep(2)

    def checkFAIL(self, recvdata):
        if type(recvdata) != str:
            logger.error(recvdata)
            ret = self.evcc.do_normal_process()
            return (ret, str(recvdata))
        root = ET.fromstring(recvdata)
        responseCode = root.find("ResponseCode")
        if responseCode == None:
            responseCode = root.find("*/*/{*}ResponseCode")
        if responseCode != None:
            if "FAILED_SequenceError" in responseCode.text:
                logger.error(responseCode.text)
                ret = self.evcc.do_normal_process()
                return (ret, responseCode.text)
            else:
                return (True, responseCode.text)
        logger.error(responseCode)
        ret = self.evcc.do_normal_process()
        return (ret, 'No ResponseCode')

    def TEST_SupportedAppProtocolReq(self, fuzzdata, tags=[]):
        logging.info("=== TEST SupportedAppProtocolReq ===")
        if tags == []:
            tags = SupportedAppProtocolReqTags
        for tag in tags:
            for d in fuzzdata:
                logger.info(tag+": "+str(d)[:30]+"... "+"-"*30)
                self.evcc.SECCDiscoveryReq()
                self.evcc.TCPConnect()
                root = self.evcc.getDefaultXML("SupportedAppProtocolReq")
                root.find(tag).text = d
                retxml = self.evcc.sendV2Gmsg(root, V2G_CI_AppProtocol_XSD)
                (ret, rcode) = self.checkFAIL(retxml)
                if ret:
                    logger.debug("PASS")
                    logger.debug(rcode)
                    if "OK_SuccessfulNegotiation" in rcode:
                        self.evcc.SessionStopReq()
                else:
                    logger.error("FAIL")
                    logger.error(rcode)
                    sys.exit(1)
                    #self.RESET_SECC()

    def TEST_SessionSetupReq(self, fuzzdata, tags=[]):
        logging.info("=== TEST SessionSetupReq ===")
        if tags == []:
            tags = SessionSetupReqTags

        for tag in tags:
            for d in fuzzdata:
                logger.info(tag+": "+d[:20]+" "+"-"*30)

                self.evcc.SECCDiscoveryReq()
                self.evcc.TCPConnect()
                self.evcc.SupportedAppProtocolReq()

                root = self.evcc.getDefaultXML("SessionSetupReq")
                root.find(tag).text = d
                retxml = self.evcc.sendV2Gmsg(root, V2G_CI_MsgDef)
                (ret, rcode) = self.checkFAIL(retxml)
                if ret:
                    logger.debug("PASS")
                    logger.debug(rcode)
                    if "OK_NewSession" in rcode:
                        self.evcc.SessionStopReq()
                else:
                    logger.error("FAIL")
                    logger.error(rcode)
                    sys.exit(1)
                    #self.RESET_SECC()
    
    # NOT COMPLETED
    def TEST_ServiceDiscoveryReq(self, fuzzdata, tags=[]):#
        logging.info("=== TEST ServiceDiscoveryReq ===")
        if tags == []:
            tags =ServiceDiscoveryReqTags 

        for tag in tags:
            for d in fuzzdata:
                logger.info(tag+": "+d[:20]+" "+"-"*30)
                self.evcc.SECCDiscoveryReq()
                self.evcc.TCPConnect()
                self.evcc.SupportedAppProtocolReq()
                self.evcc.SessionSetupReq()

                root = self.evcc.getDefaultXML("ServiceDiscoveryReq")
                root = self.evcc.setSessionID(root)
                #root.find(tag).text = d
                retxml = self.evcc.sendV2Gmsg(root, V2G_CI_MsgDef)
                (ret, rcode) = self.checkFAIL(retxml)
                if ret:
                    logger.debug("PASS")
                    logger.debug(rcode)
                    self.evcc.SessionStopReq()
                else:
                    logger.error("FAIL")
                    logger.error(rcode)
                    sys.exit(1)
                    #self.RESET_SECC()

    def TEST_PaymentServiceSelectionReq(self, fuzzdata, tags=[]):
        logging.info("=== TEST PaymentServiceSelectionReq ===")
        if tags == []:
            tags = PaymentServiceSelectionReqTags 

        for tag in tags:
            for d in fuzzdata:
                logger.info(tag+": "+d[:20]+" "+"-"*30)
                self.evcc.SECCDiscoveryReq()
                self.evcc.TCPConnect()
                self.evcc.SupportedAppProtocolReq()
                self.evcc.SessionSetupReq()
                self.evcc.ServiceDiscoveryReq()

                root = self.evcc.getDefaultXML("PaymentServiceSelectionReq")
                root = self.evcc.setSessionID(root)
                root.find(tag).text = d
                retxml = self.evcc.sendV2Gmsg(root, V2G_CI_MsgDef)
                (ret, rcode) = self.checkFAIL(retxml)
                if ret:
                    logger.debug("PASS")
                    logger.debug(rcode)
                    self.evcc.SessionStopReq()
                else:
                    logger.error("FAIL")
                    logger.error(rcode)
                    sys.exit(1)
                    #self.RESET_SECC()

    def TEST_AuthorizationReq(self, fuzzdata, tags=[]):
        logging.info("=== TEST AuthorizationReq ===")
        tags = []

    def TEST_ChargeParameterDiscoveryReq(self, fuzzdata, tags=[]):
        logging.info("=== TEST ChargeParameterDiscoveryReq ===")
        if tags == []:
            root = self.evcc.getDefaultXML("ChargeParameterDiscoveryReq")
            if root.find(AC) != None:
                tags = AC_EVChargeParams
            elif root.find(DC) != None:
                tags = DC_EVChargeParams
            else:
                logger.error("Unknown ChargeParameterDiscoveryReq ERROR")
                sys.exit(1)
                
        for tag in tags:
            root = self.evcc.getDefaultXML("ChargeParameterDiscoveryReq")
            subtags = root.findall(tag)
            for tag2 in subtags:
                for d in fuzzdata:
                    logger.info(tag+" "+tag2.tag+": "+d[:20]+" "+"-"*30)
                    self.evcc.SECCDiscoveryReq()
                    self.evcc.TCPConnect()
                    self.evcc.SupportedAppProtocolReq()
                    self.evcc.SessionSetupReq()
                    self.evcc.ServiceDiscoveryReq()
                    self.evcc.PaymentServiceSelectionReq()
                    self.evcc.AuthorizationReq()
                    root = self.evcc.setSessionID(root)
                    old = tag2.text
                    tag2.text = d
                    retxml = self.evcc.sendV2Gmsg(root, V2G_CI_MsgDef)
                    tag2.text = old
                    (ret, rcode) = self.checkFAIL(retxml)
                    if ret:
                        logger.debug("PASS")
                        logger.debug(rcode)
                        self.evcc.SessionStopReq()
                    else:
                        logger.error("FAIL")
                        logger.error(rcode)
                        sys.exit(1)
                        #self.RESET_SECC()
    
    def TEST_PowerDeliveryReq(self, fuzzdata, tags=[]):
        logging.info("=== TEST PowerDeliveryReq ===")
        if tags == []:
            tags = PowerDeliveryReqTags
        
        for tag in tags:
            for d in fuzzdata:
                logger.info(tag+": "+d[:20]+" "+"-"*30)
                self.evcc.SECCDiscoveryReq()
                self.evcc.TCPConnect()
                self.evcc.SupportedAppProtocolReq()
                self.evcc.SessionSetupReq()
                self.evcc.ServiceDiscoveryReq()
                self.evcc.PaymentServiceSelectionReq()
                self.evcc.AuthorizationReq()
                self.evcc.ChargeParameterDiscoveryReq()

                root = self.evcc.getDefaultXML("PowerDeliveryReq")
                root = self.evcc.setSessionID(root)
                root.find(tag).text = d
                print(ET.tostring(root))
                retxml = self.evcc.sendV2Gmsg(root, V2G_CI_MsgDef)
                (ret, rcode) = self.checkFAIL(retxml)
                if ret:
                    logger.debug("PASS")
                    logger.debug(rcode)
                    self.evcc.SessionStopReq()
                else:
                    logger.error("FAIL")
                    logger.error(rcode)
                    sys.exit(1)
                    #self.RESET_SECC()

    def TEST_TLS(self):
        self.evcc.SECCDiscoveryReq(True)
        ip = self.evcc.ip_addr+"%"+self.evcc.iface
        port = self.evcc.tls_port
        port = 51238
        cmd = "openssl s_client -connect "+ip+":"+str(port)+"<<<'Q'"
        try:
            ret=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (result, err) = ret.communicate(timeout=5)
        except Exception as e:
            logger.error(e)
            logger.error("TLS is disabled.")
            return
        logger.debug("TLS is enabled.")

        ################################################
        #check tls version
        cmd = "openssl s_client -connect "+ip+":"+str(port)+" -tls1_2 <<< 'Q' "
        ret=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (result, err) = ret.communicate()
        result = result.decode("utf-8")
        try:
            v = re.search("Protocol  : (.*?)\n", result, re.DOTALL).group(1)
            if v == "TLSv1.0" or v == "TLSv_1.1":
                logger.error(f"TLS version: {v}")
                logger.error("TLSv1.2 or TLSv1.3 is required.")
            elif v != "TLSv1.2" or v != "TLSv_1.3":
                logger.debug(f"TLS version: {v}")
            else:
                logger.error(f"TLS version: {v}")
                logger.error("Unknown version")
        except Exception as e:
            logger.error("Exception occurred! Can't find TLS version")
            logger.error(e)
            logger.error(result)
            sys.exit(1)
            
        ################################################
        logger.info("=== Validate Certificate ===")
        #get certificate
        cmd = "openssl s_client -connect "+ip+":"+str(port)+" < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' > cert.pem"
        ret=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (result, err) = ret.communicate()
        
        #check validity of the certificate
        cmd = "openssl x509 -enddate -noout -in cert.pem"
        ret = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (result, err) = ret.communicate()
        result = result.decode("utf-8")
        if 'notAfter' not in result:
            logger.error("notAfter filed is not in response")
            logger.error(err.decode("utf-8"))
            sys.exit(1)
        
        #check expired time
        expired_time = re.search("notAfter=(.*?)\n", result).group(1)
        t1 = time.mktime( datetime.strptime(expired_time, "%b %d %H:%M:%S %Y GMT").timetuple() )
        t2 = time.time()

        logger.info(f"Expired time: {expired_time}")
        if t1>t2:
            logger.debug("Certificate is OK")
        else:
            logger.error("Expired Certificate")

        #delete downloaded certificate        
        cmd = "rm cert.pem"
        ret=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (result, err) = ret.communicate()


    def TEST_DOS_Attack(self):
        max_syn = 65535
        self.evcc.SECCDiscoveryReq(False)
        for i in range (0, max_syn):
            if i%1000==0:
                logger.info(f"{i}/{max_syn} packets transmitted" )
            ETHpkt = Ether(src=RandMAC(), dst="33:33:00:00:00:01")
            IPv6pkt = IPv6(src = self.evcc.ip_addr, dst = self.evcc.ip_addr)
            TCPpkt = TCP (sport = random.randint(10000,59999), dport = self.evcc.tcp_port, flags = "S")
            sendp(ETHpkt/IPv6pkt/TCPpkt, verbose=0)
        logger.info(f"{i}/{max_syn} packets transmitted" )
        ret = self.evcc.TCPConnect()
        if ret:
            logger.debug("TCP connection successful.")
            logger.debug("SECC is still alive.")
        else:
            logger.error("TCP connection failed.")
            logger.error("SECC is dead.")

    def TEST_V2G_SDP_Fuzz(self):
        f = V2GSDPFuzzer(self.evcc.ip_addr)
        f.connect()
        f.generate_testcases()
        f.fuzz()


def main():
    print("1. TLS Check")
    print("2. DoS Attack (Synflood)")
    print("3. Parameter validation")
    print("4. V2GTP/SDP fuzz")
    try:
        m = input("> ")
        m = int(m)
    except Exception as e:
        logger.error("Not supported menu")
        sys.exit(1)
    if m < 1 or m>4:
        logger.error("Not supported menu")
        sys.exit(1)
    return m

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='STEVE - Security Testing Framework for EV Charging Environments')
    parser.add_argument('--target', '-t', help='secc', required=True)
    parser.add_argument('--ip', help='target IP address', required=True)
    parser.add_argument('--iface', help='network interface', required=True)

    args = parser.parse_args()

    m = main()    
    seccTest = STEVE(args.ip, args.iface)
    if m == 1:
        seccTest.TEST_TLS()
    elif m == 2:
        seccTest.TEST_DOS_Attack()
    elif m == 3:
        fuzzdata = ["", "A"*1024, "0", "-1", "4294967296", "18446744073709551616", "<", ">", "</>", "<!--", "<!DOCTYPE", "<!ELEMENT", "<!ENTITY"]
        seccTest.TEST_SupportedAppProtocolReq(fuzzdata)
        seccTest.TEST_SessionSetupReq(fuzzdata)
        seccTest.TEST_ServiceDiscoveryReq(fuzzdata)
        seccTest.TEST_PaymentServiceSelectionReq(fuzzdata)
        seccTest.TEST_ChargeParameterDiscoveryReq(fuzzdata)
        seccTest.TEST_PowerDeliveryReq(fuzzdata)
    elif m == 4:
        seccTest.TEST_V2G_SDP_Fuzz()
    
   
