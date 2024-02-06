# STI signature generator

In order to mitigate robocalls, STIR/SHAKEN has started to be implemented in different countries like United States or France. This suite of protocols is used for avoiding robocalls and callerId spoofing via PSTN. STIR (Secure Telephone Identity Revisited) SHAKEN (Signature-based Handling of Asserted information using toKENs), as explained in Wikipedia, is a uite of protocols and procedures intended to combat caller ID spoofing on public telephone networks. Caller ID spoofing is used by robocallers to mask their identity or to make it appear the call is from a legitimate source.

Some old PBX/SBC are not ready for the usage of STIR/SHAKEN. Others can only use a limited number of certificates to sign calls. In order to start signing calls and send them to PSTN (or transit carrier), this script has been deployed and implemented. This can be easily implemented in old Asterisk boxes.

The level of assertation of the call (A, B or C) will be decided taking into account if the orig_tn is defined in the DDI files named as xNumbersSTI.txt. This means that if for a call orig_tn is contained in the aNumbersSTI.txt, the call will be signed with attestation level "A". On the other hand, if that orig_tn is in bNumbersSTI.txt. Finally, if that orig_tn is contained in cNumbersSTI.txt or is not contained, then the call will be signed with "C".

STIsigner.cfg is the file that contains the values per default of all the most relevant value. It permits to sign calls just executing the comand with CC, orig_tn and dest_tn.

	ALGOR=RS256
	BYPASS=OPE00-999999-99999-9999
	ORIGID=123e4567-e89b-12d3-a456-426655440000
	PRI_KEY=PKI/priv_serverPKI.key
	PUB_CERT=PKI/pub_serverPKY.cert
	URL_CERT=http://certificate_repository.net/sti-repo/pub_cert.crt



## USAGE:

	bash> python3 STIsigner.py +cc +orig_tn +dest_tn pathToPrivateKey pathToPublicKey http://certificate-website.net

		+cc 				= Country  Code where the call is placed
		+orig_tn 			= Origin of call (Calling number)
		+dest_tn			= Destination of call (Called number)
		pathToPrivateKey		= Location where the private key is stored in the PBX server
		pathToPublicKey			= Location where the public certificate/key is stored in the PBX server
		http://certificate-website.net	= URL where is available the certificate for verifying the calls from the other end


## FILES/FOLDER STRUCTURE

	script-folder/
	|
	|-STIsigner.cfg
	|
	|-PKI
	|    |-priv_serverPKI.key (Default Private Key)
	|    |-pub_serverPKI.cert  (Default Public Key)
	|
	|-DDI
	     |-aNumbersSTI.txt (List of A numbers)
	     |-bNumbersSTI.txt (List of B numbers)
	     |-cNumbersSTI.txt (List of C numbers)


## MODULES

	- json
	- jwt
	- calendar
	- time
	- sys


## RELATED PROJECTS

	https://github.com/jpadilla/pyjwt/


## LIMITATIONS

	- TODO: Private keys should not use password, otherwise cannot be processed.

	- TODO: Set a private and public default key for signature

	- If there is a missing value in the script, or they key is not valid file, the call is not signed and "P-Bypass-Identity: OPE00-999999-99999-9999" is returned.

	- If the origin and destination are in different country (international gateway) the call is signed as C always.

	- If the country is different to orig_tn or dest_tn the call is signed as C.

	- No diversion scenario is considered.
