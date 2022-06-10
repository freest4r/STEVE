INTERFACE = b"en0"
UDPPORT = 15118
#CONTRACT_CERT = "./certs/contractCert.pem"
#CONTRACT_CERT = "./certs/v2gRootCACert.pem"
#CONTRACT_CERT = "./certs/cpsSubCA1Cert.pem"
#CONTRACT_CERT = "./certs/moRootCACert.pem"
CONTRACT_CERT = "./certs/oemRootCACert.pem"
CONTRACT_CERT = "./certs/seccCert.pem"
#
V2GTP_VERSION = 0x01
V2GTP_INVERSE_VERSION = 0xFE
#Table 10.
V2GTP_EXI_ENC_MSG = 0x8001
V2GTP_SDP_REQ_MSG = 0x9000
V2GTP_SDP_RES_MSG = 0x9001

EXI_XML_jar = "EXI/target/exi-xml.jar"

XMLPATH = "./XMLDATA/"
SupportedAppProtocolReq = "./XMLDATA/SupportedAppProtocolReq.xml"
SessionSetupReq = "./XMLDATA/SessionSetupReq.xml"
ServiceDiscoveryReq = "./XMLDATA/ServiceDiscoveryReq.xml"
ServiceDetailReq = "./XMLDATA/ServiceDetailReq.xml"
PaymentServiceSelectionReq = "./XMLDATA/PaymentServiceSelectionReq.xml"
CertificateInstallationReq = "./XMLDATA/CertificateInstallationReq.xml"
AuthorizationReq = "./XMLDATA/AuthorizationReq.xml"
ChargeParameterDiscoveryReq = "./XMLDATA/ChargeParameterDiscoveryReq.xml"
PowerDeliveryReq = "./XMLDATA/PowerDeliveryReq.xml"
ChargingStatusReq = "./XMLDATA/ChargingStatusReq.xml"
SessionStopReq = "./XMLDATA/SessionStopReq.xml"

V2G_CI_AppProtocol_XSD = "./xsd/V2G_CI_AppProtocol.xsd"
V2G_CI_MsgBody = "./xsd/V2G_CI_MsgBody.xsd"
V2G_CI_MsgDataTypes = "./xsd/V2G_CI_MsgDataTypes.xsd"
V2G_CI_MsgDef = "./xsd/V2G_CI_MsgDef.xsd"
V2G_CI_MsgHeader = "./xsd/V2G_CI_MsgHeader.xsd"
XMLDSIG = "./xsd/xmldsig-core-schema.xsd"


SupportedAppProtocolReqTags = [
    "AppProtocol/ProtocolNamespace", #ProtocolNamespace: string (max length: 100)
    "AppProtocol/VersionNumberMajor",#VersionNumberMajor: unsignedInt
    "AppProtocol/VersionNumberMinor",#VersionNumberMinor: unsignedInt
    "AppProtocol/SchemaID",#SchemaID: unsignedByte
    "AppProtocol/Priority"#Priority: unsignedByte(1-20)
    ]

SessionSetupReqTags = [
    "*/{*}SessionID", #hexBinary(max length: 8)
    "*/*/{*}EVCCID"     #hexBinary(max length: 6)
    ]

ServiceDiscoveryReqTags = [
    "*/*/{*}ServiceScope", #string (max length: 32)
    "*/*/{*}ServiceCategory" #enumeration
   ]

PaymentServiceSelectionReqTags = [
    "*/*/{*}SelectedPaymentOption", #ExternalPayment, Contract
    "*/*/*/*/{*}ServiceID", #unsignedshort
    "*/*/*/*/{*}ParameterSetID" #short
    ]

#ChargeParameterDiscoveryReq
AC = "*/*/{*}AC_EVChargeParameter/"
AC_EVChargeParams = [
    "*/*/{*}RequestedEnergyTransferMode",
    AC+"{*}DepartureTime",          
    AC+"*/{*}Multiplier", 
    AC+"*/{*}Unit", 
    AC+"*/{*}Value", 
]

DC = "*/*/{*}DC_EVChargeParameter"
DC_EVChargeParams = [
    "*/*/{*}RequestedEnergyTransferMode",
    DC+"{*}DepartureTime",          
    DC+"*/{*}Multiplier",
    DC+"*/{*}Unit",
    DC+"*/{*}Value",
]

PowerDeliveryReqTags = [
    "*/*/{*}ChargeProgress",
    "*/*/{*}SAScheduleTupleID",
    "*/*/*/*/{*}ChargingProfileEntryStart",
    "*/*/*/*/*/{*}Multiplier",
    "*/*/*/*/*/{*}Unit",
    "*/*/*/*/*/{*}Value",
    "*/*/*/*/{*}ChargingProfileEntryMaxNumberOfPhasesInUse"
]
