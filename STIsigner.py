import json,jwt
import calendar,time
import sys


################################################################################
# DOCUMENTATION
################################################################################
#
# https://github.com/jpadilla/pyjwt/ 
#


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

        #Check if is national call
        #print(prefixA+" "+prefixB+" "+prefixCC)
        if prefixA==prefixB and prefixA==prefixCC:

                if checkOriginAttestA(orig_tn):
                    return("A")
                elif checkOriginAttestB(orig_tn):
                    return("B")
                else:
                    return("C")

        else:
                return("C")

def generate_payload_STI_json_Text(attest,dest_tn,orig_tn,origid):
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
        "origid":origid,
    }
    return(json.dumps(payloadSTI, indent=4))

def generate_payload_STI_json_Object(attest,dest_tn,orig_tn,origid):
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
        "origid":origid,
    }
    return(payloadSTI)

def generate_header_STI_json_Object(algo,urlCert):
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

################################################################################
# MAIN BODY
################################################################################
#private_key_file_pem="PKI/priv_serverPKI.key"
#public_key_file_pem="PKI/pub_serverPKY.cert"
#url_cert="http://voice-test-tool-colt.net/sti-repo/pizzatelecom.crt"

#STEP 1: Define the Alg
#algo="ES256"
algo="RS256"
BY_PASS="OPE00-999999-99999-9999"

#STEP 2: Take generate origid
origid="123e4567-e89b-12d3-a456-426655440000"


#STEP 3: Take arguments from CLI. If there are no arguments ask for them interactively:
try:
        cc=sys.argv[1]
        orig_tn=sys.argv[2]
        dest_tn=sys.argv[3]
        private_key_file_pem=sys.argv[4]
        public_key_file_pem=sys.argv[5]
        url_cert=sys.argv[6]
        #print(sys.argv)

        if cc=="--help":
            print("Usage:")
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
            print("P-Bypass-Identity: "+BY_PASS)
            exit()

if cc!="" and dest_tn!="" and orig_tn!="" and private_key_file_pem!="" and  public_key_file_pem!="" and url_cert!="":

    #STEP 4: Load private and public key
    private_key=load_private_key(private_key_file_pem)
    public_key=load_public_key(public_key_file_pem)

    #STEP 5: Set the attestation level for this call
    attest = attestation_level_call(orig_tn,dest_tn,cc)

    #STEP 7: Generate JSON to sign
    payloadSTItxt = generate_payload_STI_json_Text(attest,dest_tn,orig_tn,origid)
    payloadSTIob = generate_payload_STI_json_Object(attest,dest_tn,orig_tn,origid)
    headerSTI=generate_header_STI_json_Object(algo,url_cert)

    #STEP 8: Encode the JSON
    #sti_token = encode_Identity_noheader(payloadSTIob,private_key,algo)
    sti_token = encode_Identity_header(payloadSTIob,private_key,algo,headerSTI)
    print("Identity: "+sti_token+";info=<"+url_cert+">;alg="+algo+";ppt=shaken")
