# Rogue (Forensics Challenge)
HTB Business CTF 2022
Writeup by: @godylockz

## Challenge Description
Category: Forensics
Difficulty: Easy
Points: 350
SecCorp has reached us about a recent cyber security incident. They are confident that a malicious entity has managed to access a shared folder that stores confidential files. Our threat intel informed us about an active dark web forum where disgruntled employees offer to give access to their employer's internal network for a financial reward. In this forum, one of SecCorp's employees offers to provide access to a low-privileged domain-joined user for 10K in cryptocurrency. Your task is to find out how they managed to gain access to the folder and what corporate secrets did they steal.

## Strategy
The premise revolving around this challenge was decryption of SMBv3 traffic given the known user password or NTLM hash.

```sh
$ python3 calc_hash.py --verbose --user athomson --ntlmpassword 88d84bad705f61fcdea0d771301c3a7d --domain CORP --ntproofstr d047ccdffaeafb22f222e15e719a34d4 --sessionkey 032c9ca4f6908be613b240062936e2d2 --sessionid 0000a00000000015
USER+DOMAIN: ATHOMSONCORP
PASS HASH: 88d84bad705f61fcdea0d771301c3a7d
RESP NT: 6bc1c5e3a6a4aba16139faad9a3cce6e
NT PROOF: d047ccdffaeafb22f222e15e719a34d4
KeyExKey: 4765b4b66d2d5de5b323708a33d33318
Session ID: 1500000000a00000
Random SK: 9ae0af5c19ba0de2ddbe70881d4263ac
Decrypt #2:
1500000000a00000 9ae0af5c19ba0de2ddbe70881d4263ac
HTB{n0th1ng_c4n_st4y_un3ncrypt3d_f0r3v3r}
```


```python
#!/usr/bin/env python3
"""
This function calculates the random secret key for SMB decryption.
This uses the NTLM hash or plaintext password of the user given a pre-existing packet capture.
"""

# Imports
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD4
import hashlib
import hmac
import argparse
from binascii import hexlify, unhexlify

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    cipher_encrypt = cipher.encrypt
    sessionKey = cipher_encrypt(exportedSessionKey)
    return sessionKey

def swap_bytes(x):
    x = bytearray(unhexlify(x));
    x.reverse();
    return hexlify(x)

# Arguments
parser = argparse.ArgumentParser(
    description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
parser.add_argument("-p", "--password", required=False,
                    help="Password of User")
parser.add_argument("-ph", "--ntlmpassword", required=False,
                    help="NTLM Password Hash of User")
parser.add_argument("-n", "--ntproofstr", required=True,
                    help="NTProofStr (hex). This can be found in PCAP via ntlmssp.ntlmv2_response.ntproofstr")
parser.add_argument("-k", "--sessionkey", required=True,
                    help="Encrypted Session Key (hex). This can be found in PCAP.")
parser.add_argument("-i", "--sessionid", required=True,
                    help="Session ID (hex). This can be found in PCAP.")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")
args = parser.parse_args()

# Upper CaseUsername and Domain
Username = str(args.user).upper().encode('utf-16le')
Domain = str(args.domain).upper().encode('utf-16le')

# Create 'NTLM' Hash of password
if args.ntlmpassword:
    NTLMPassword = unhexlify(args.ntlmpassword)
elif args.password:
    Password = args.password.encode('utf-16le')
    hash1 = MD4.new(Password)
    NTLMPassword = hash1.hexdigest()
    NTLMPassword = unhexlify(NTLMPassword)
else:
    exit("Requires password or NTLM hash")

# Calculate the ResponseNTKey
h = hmac.new(NTLMPassword, digestmod=hashlib.md5)
h.update(Username+Domain)
ResponseNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Exchange Key
NTProofStr = unhexlify(args.ntproofstr)
h = hmac.new(ResponseNTKey, digestmod=hashlib.md5)
h.update(NTProofStr)
KeyExchKey = h.digest()

# Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(
    KeyExchKey, unhexlify(args.sessionkey))

if args.verbose:
    print("USER+DOMAIN: " + Username.decode() + "" + Domain.decode())
    print("PASS HASH: " + hexlify(NTLMPassword).decode())
    print("RESP NT:   " + hexlify(ResponseNTKey).decode())
    print("NT PROOF:  " + hexlify(NTProofStr).decode())
    print("KeyExKey:  " + hexlify(KeyExchKey).decode())
print("Session ID: " + swap_bytes(args.sessionid).decode())
print('Random SK:', hexlify(RsessKey).decode())
```