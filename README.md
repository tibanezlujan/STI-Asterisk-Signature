
*STI signature generator*

In order to mitigate robocalls, STIR/SHAKEN has started to be implemented in different countries like United States or France. This suite of protocols is used for avoiding robocalls and callerId spoofing via PSTN. 

STIR   - 
SHAKEN - 


Some old PBX/SBC are not able to use this protocol. Other new PBX/SBC can only use a limited number of certificates to sign calls. In order to start signing calls and send them to PSTN, I have deployed an small script that taking a public key and a private key sign that call.

USAGE:

	bash> python3 STIsigner.py +cc +orig_tn +dest_tn pathToPrivateKey pathToPublicKey http://certificate-website.net

	+cc 			= Country  Code where the call is placed
	+orig_tn 		= Origin of call (Calling number)
	+dest_tn		= Destination of call (Called number)
	pathToPrivateKey	= Location where the private key is stored in the PBX server
	pathToPublicKey		= Location where the public certificate/key is stored in the PBX server


LIMITATIONS:

	- TODO: The calls are only signed as B number in case that is national call or C in case is international.
       		Need to deploy checkOriginFullAttest() function to look for this orig_tn as trusted number.
		The idea is to generate a file with the valid numbers can be presented. 
		If using asterisk, this can be extracted from extensions.conf using the extensions parstedto a SIP  callerId field adding the provisioned number 
 	
	- TODO: Private keys should not use password, otherwise cannot be processed.
	- If there is a missing value in the script, the call is not signed and "P-Bypass-Identity: OPE00-999999-99999-9999" is returned.
	- If the origin and destination are in different country (international gateway) the call is signed as C always.
	- If the country is different to orig_tn or dest_tn the call is signed as C.
	- No diversion scenario is considered.
