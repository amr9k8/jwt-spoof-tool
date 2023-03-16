
# jwt-spoof-tool

### Tool Description  :
I made this tool for learning purpose and automating jwt token hijacking without depending on  using burpsuite 
the code is well documented and easy to follow
Based on (CVE-2018-0114)
The Vulnerabilty happend because in backend the server check jwk object embeded inside jwt header, it contain n and e which are 2 paramters used to form the public key 
### How to exploit :
<br> 1) An attacker generate new RSA KEY PAIRS,
<br> 2) Get n and e and inject them inside the jwk object in jwt headers
<br> 3) Change any values in jwt body section then sign it with his private key 
<br> 4) The server uses the attacker public key to verify the signature .
<br> 5) i made a verify function to make sure the jwt is exploited successfulyy or not by trying to decode it using attacker public key  (n and e)

### How to run it :
<br> 1) overwrite value of variable "jwt_orginal at line 125" by the new  vulnerable jwt 
<br> 2) add any attributes you wanna change inside the dictionary object "dict_values at line  126"
<br> 3) Enjoy
