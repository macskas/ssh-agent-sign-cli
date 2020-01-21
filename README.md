# ssh-agent-sign-cli
SSH agent sign cli (POC)

## usage
I use it to avoid writing in username/password for internal HTTP api calls from CLI.

### flow with HTTP
#### case A 
-> request encrypt string from HTTP (you have to include timestamp and verify it)
<- send back the encrypt string (timestamp etc)
call ssh-sign.pl -m "encrypt string"
-> send back the encrypted strings (md5fingerprintofpubkey:signedhex)
<- verify, then respond with an access token/refresh token etc. 
now you can use the api with the refresh token
#### case B (less secure, more resources, no extra calls needed)
* build your own encrypt string from the request_method, url, timestamp
* send signed strings along with the original string in http header(s)
server will check the signature with the public keys, check timestamp if its still valid and let you continue the api call.

#### example php included for verify, bigint support needed. phpseclib for example


### help
```
# perl ssh-sign.pl -h
ssh-sign.pl -m <message> | -l
   -q                 - quiet mode
   -m <message>       - message to sign
   -c <comment>       - filter by ssh-key *comment*
   -f <hash>          - filter by ssh-key =fingerprint
   -x <comment>       - exclude by ssh-key *comment*
   -l                 - list keys
```

### cli sample output
```
# perl ssh-sign.pl -l # list keys
542eac4bb60e9502a167803a02c2aa61:/test/k1
bf2b4508482c99becadb1c789399640c:/test/k2

# perl ssh-sign.pl -m test # encrypt the string "test"
542eac4bb60e9502a167803a02c2aa61:2156acafa7a23395cd69549e8806bbda9c0d687073742a0c09fced7749e3cf6012ceed9733b39afc3fc57ece03806ccc921121c9d8a27140d3aab0b93ae1bf48d9949a8705be5fe05b6fb8e8044dd05ea97b099e717e0d1390ba687b22726f21c68cd5268c005c2aa5f542d453c4cc1ed11c0506a7d7a51214ee8ae874e58f5562364371cafd2371706bc3f1d36c525e67b0a074bceaaa0924e99bcad5030065c181c58c36d5ac2ab88d25c77646020254eeb14fdfbc9562e959969c9ff1a36992d70bfb312aee15c34e3019cddfa47afc65e8dfeaad4b408388361f4afad9c084909653d1f2fad487b04dc214e44bde6f4192328e846f5a3600e97352c4969c
bf2b4508482c99becadb1c789399640c:0e8d68b9eff4c266cd562014dbe67d1a6591219212c8149da1e405b9c018e8a475bc92114ff520cd3af785036b7335026e7e50c04313deb13147ab6c042294feb2b6cab767a44cd98eae82e3402126dde1e26f1718339063910f649c7e62fedb586e77c4e71a0eb38cb5043e3bb21ac3b55e8e3a9917e40aab0b98c4e7ac7b27080d717750ef1d3532703e20432d31a36056862ecb9a90d19eadb17c5605c770a0e1cafaf7415500817e24e376bab43f0dcc1bde58387dc258673e3aed1cc9fc8ada2b33e87770234e5e9a709ecb5ab1ee111f4623e68d613a0f77241c1fea67442fd29ac8a42ae3c464a84057a2b7145396de215c6ada29b8b213e23def6ead

```
