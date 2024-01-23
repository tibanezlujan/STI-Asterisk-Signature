import json,jwt
import calendar,time
import sys

################################################################################
#FUNCTIONS
################################################################################

def checkOriginAttestA(orig_tn):
    file="DDI/aNumbersSTI.txt" 
    f=open(file, "r")
    for line in f:
        if orig_tn in line:
            return(True)
    return(False)

def checkOriginAttestB(orig_tn):
    file="DDI/bNumbersSTI.txt"
    f=open(file, "r")
    for line in f:
        if orig_tn in line:
            return(True)
    return(False)

def attestation_level_call(orig_tn,dest_tn,cc):
        lenCC=len(cc)
        prefixA=orig_tn[1:lenCC]
        prefixB=dest_tn[1:lenCC]
        prefixCC=cc[1:]
        if prefixA==prefixB and prefixA==prefixCC:

                if checkOriginAttestA(orig_tn):
                    return("A")
                elif checkOriginAttestB(orig_tn):
                    return("B")
                else:
                    return("C")
        else:
                return("C")

def generate_payload_STI_json_Text(attest,dest_tn,orig_tn,ORIGID):
    dest_tn=dest_tn[1:]
    orig_tn=orig_tn[1:]
    epochSecs=calendar.timegm(time.gmtime())
    epochSecs=int(time.time())
    iat=str(epochSecs)
    payloadSTI = {
        "attest":attest,
        "dest":{"tn":dest_tn},
        "iat":str(iat),
        "orig":{"tn":orig_tn},
        "ORIGID":ORIGID,
    }
    return(json.dumps(payloadSTI, indent=4))

def generate_payload_STI_json_Object(attest,dest_tn,orig_tn,ORIGID):
    dest_tn=dest_tn[1:]
    orig_tn=orig_tn[1:]
    epochSecs=calendar.timegm(time.gmtime())
    epochSecs=int(time.time())
    iat=str(epochSecs)
    payloadSTI = {
        "attest":attest,
        "dest":{"tn":dest_tn},
        "iat":iat,
        "orig":{"tn":orig_tn},
        "ORIGID":ORIGID,
    }
    return(payloadSTI)

def generate_header_STI_json_Object(alg,urlCert):
    headerSTI = {
        "ppt":"shaken",
        "typ":"passport",
        "x5u":urlCert
    }
    return(headerSTI)

def encode_Identity_header(payload,private_key,algo,headerSTI):
    jwt_token=jwt.encode(payload, private_key, algorithm=algo, headers=headerSTI)
    return(jwt_token)

def encode_Identity_noheader(payload,private_key,algo):
    jwt_token=jwt.encode(payload, private_key, algorithm=algo)
    return(jwt_token)

def load_private_key(private_key_file_pem):
    with open(private_key_file_pem, 'r') as private_key_file:
        private_key = private_key_file.read()
        return(private_key)

def load_public_key(public_key_file_pem):
    with open(public_key_file_pem, 'r') as public_key_file:
        public_key = public_key_file.read()
        return(public_key)

def load_config():
    file="STIsigner.cfg"
    f=open(file, "r")
    for line in f:
        line=line.rstrip('\n')
        if "ALGOR" in line:
            global global_ALGOR
            global_ALGOR=line.split('=')
            global_ALGOR=global_ALGOR[1]
            #print(">>"+global_ALGOR)
        elif "BYPASS" in line:
            global global_BYPASS
            global_BYPASS=line.split('=')
            global_BYPASS=global_BYPASS[1]
            #print(">>"+str(global_BYPASS))
        elif "ORIGID" in line:
            global global_ORIGID
            global_ORIGID=line.split('=')
            global_ORIGID=global_ORIGID[1]
            #print(">>"+global_ORIGID)
        elif "PRI_KEY" in line:
            global global_PRI_KEY
            global_PRI_KEY=line.split('=')
            global_PRI_KEY=global_PRI_KEY[1]
            #print(">>"+global_PRI_KEY)
        elif "PUB_CERT" in line:
            global global_PUB_CERT
            global_PUB_CERT=line.split('=')
            global_PUB_CERT=global_PUB_CERT[1]
            #print(">>"+global_PUB_CERT)
        elif "URL_CERT" in line:
            global global_URL_CERT
            global_URL_CERT=line.split('=')
            global_URL_CERT=global_URL_CERT[1]
            #print(">>"+global_URL_CERT)
        else:
            return(False)

    return(True)


################################################################################
# MAIN BODY
################################################################################
#private_key_file_pem="PKI/priv_serverPKI.key"
#public_key_file_pem="PKI/pub_serverPKY.cert"
#url_cert="http://voice-test-tool-colt.net/sti-repo/pizzatelecom.crt"

#STEP 1: Intialize global variables
global global_ALGOR 
global_ALGOR=""
global global_BYPASS
global_BYPASS = ""
global global_ORIGID
global_ORIGID = ""
global global_PRI_KEY
global_PRI_KEY = ""
global global_PUB_CERT
global_PUB_CERT = ""
global global_URL_CERT
global_URL_CERT = ""


#STEP 2: Load configuration
config=load_config()

if config == False:
    print("Error: The configuration file has not been loaded")
    exit()
    


#STEP 3: Take arguments from CLI. If there are no arguments ask for them interactively:
try:

    if len(sys.argv) > 5:
        cc=sys.argv[1]
        orig_tn=sys.argv[2]
        dest_tn=sys.argv[3]
        private_key_file_pem=sys.argv[4]
        public_key_file_pem=sys.argv[5]
        url_cert=sys.argv[6]
        #print(sys.argv)
    elif len(sys.argv) < 5:
        cc=sys.argv[1]
        orig_tn=sys.argv[2]
        dest_tn=sys.argv[3]
        private_key_file_pem=global_PRI_KEY
        public_key_file_pem=global_PUB_CERT
        url_cert=global_URL_CERT

    else:
        if cc=="--help":
            print("HOW TO USE:")
            print("python3 STIsigner_v2.py +cc +orig_tn +dest_tn locationPrivateKeu LocationPublicKey urlCertificate")

        else:
            print("Error: Incorrect number of arguments")
            print("HOW TO USE:")
            print("python3 STIsigner_v2.py +cc +orig_tn +dest_tn locationPrivateKeu LocationPublicKey urlCertificate")

except Exception as err:
        if len(sys.argv) < 2 or cc=="--help":
            print("*******************************")
            print("*** STI signature generator ***")
            print("*******************************\n")
            print("The aim of this script is to get a signature using a private key and a public key for a call.")
            print("An Identity heder will be send.")
            print("This is how to call the script:")
            print("bash>python3 STIsigner_v2.py +cc +orig_tn +dest_tn locationPrivateKey LocationPublicKey http://certificate-website.net")
            print("")
            exit()
        else:
            #print("WARNING: Unexpected {err=}, {type(err)=}\n")
            print("P-Bypass-Identity: "+global_BYPASS)
            exit()

if cc!="" and dest_tn!="" and orig_tn!="" and private_key_file_pem!="" and  public_key_file_pem!="" and url_cert!="":

    #STEP 4: Load private and public key
    private_key=load_private_key(private_key_file_pem)
    public_key=load_public_key(public_key_file_pem)

    #STEP 5: Set the attestation level for this call
    attest = attestation_level_call(orig_tn,dest_tn,cc)

    #STEP 7: Generate JSON to sign
    payloadSTItxt = generate_payload_STI_json_Text(attest,dest_tn,orig_tn,global_ORIGID)
    payloadSTIob = generate_payload_STI_json_Object(attest,dest_tn,orig_tn,global_ORIGID)
    headerSTI=generate_header_STI_json_Object(global_ALGOR,url_cert)

    #STEP 8: Encode the JSON
    #sti_token = encode_Identity_noheader(payloadSTIob,private_key,global_ALGOR)
    sti_token = encode_Identity_header(payloadSTIob,private_key,global_ALGOR,headerSTI)
    print("Identity: "+sti_token+";info=<"+url_cert+">;alg="+global_ALGOR+";ppt=shaken")
