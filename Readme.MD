## Overview

Experimenting with JWKS with x5c - Using nodejs utilities for faster setup. 

## Step 1: Setup NPM & Install node-jose

```shell
sudo apt update
sudo apt install -y curl

curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -

#Install nodejs
sudo apt install -y nodejs

#verify
node -v
npm -v

#Create a project directory
mkdir jwk-x5c-generator && cd jwk-x5c-generator

#Intialize node-jose
npm init -y
npm install node-jose
```
This will:
	• Create a project folder
	• Set up package.json
Install the node-jose CLI tool for PEM → JWK conversion

## Step 2: Generating Private Key and Certificate with openssl 
I'm using a demo self-signed certificate here. For real-world applications, you might want to generate a CSR and get it signed with a trusted certificate authority.

```shell
# Generate 2048-bit RSA private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate a self-signed certificate
openssl req -x509 -new -key private_key.pem -out cert.pem -days 365 -subj "/CN=horikita.jwkdemo.local"

#Verify Certificate Parms
openssl x509 -in cert.pem -noout -text

#Convert certificate into DER and then base64 encode
openssl x509 -in cert.pem -outform DER | base64 -w 0 > cert.b64

```

## Generating JWK with x5c from your private key and cert
```shell
#Install minimst to support CLI args
npm install minimist

#Create Output Directory
mkdir out 

#Or if you already have one, cleanup output directory
rm -r ./out/*

# Generate new JWK - Generates jwk_full_private.json and jwk_public.json
# Both contain x5c 
node rsa_to_jwk.js --key rsa/private_key.pem --cert rsa/cert.pem --out-full out/jwk_full_private.json --out-public out/jwk_public.json

# Print and see
cat jwk_full_private.json
#Outputs following
'{
  "kty": "RSA",
  "kid": "aCu1pJ8E1xxmim4V_lJU_ocjHCOlD0lcrNcL9tYrqkU",
  "n": "1U47CSC_U7EoBHnDCoN8N1qI0IABCJojuz7jKo7Kl4uKlHLYYbgXULH9n9zyFq7_dTkucuOOr-RkQ7tAbwYUpiss_1Vq_qHepH4zzxCPtyYDXCGN_QX9prMytCiwpnEYbhGb0lH5bB8dmlFLma6DtScrCXBqTIbAdQ4hSUSMgDOB26VtmaDuEvk_ZRjs12McjXofILt72ZY1USfUOeq-5wDGxbDmpUje1Yj54WvkwqE8pJyAVw5iLldepC32VR_Pt_5yt9clYJViUlrNAx5KscZAz637YfikgoD81SOORP60s1ajjHyJv_oJmze7kk4jhjyXlkL9MDXSEPUb3iewrQ",
  "e": "AQAB",
  "d": "KE11eJpMJDVNHRlfiYlB61iLELAa4ePz2-F8PRKJQ1x9hOJ1MXN9zkSvKekugawzftPcy57k2yWRbz2-ZSvWM3ZldGIQiweNIHHq-pUDvoRrbpk1cYkT_c8Ohb1JcU1doxBnK3RLJwtzBbEWEnXHk28Q4eHwZ8CvNP7EOcp-rIsWkALzLnXMNgtGY8aYG1Ojp4HeTQiFIqO7K4Jn6I9D_VOfmwPp-GqzXn_ULTxfe6kljVZQ5Bs_JYQLwl_VNYGNbCmuaMYPVH-EuhvRq-A8XXRn7hzp60L4hTvvHxzLYBsYyHK7nBBAQs1mgSEA9qV72niMAndM3JYUAqWgV1s2IQ",
  "p": "6MwTaOZwtmkFqLxi0c52_lGgIB0m-1DSQJM8pAxigghExaC7KjWP7ez908u1g1exkLBFpaV-K0zNaPWg-RjwD8Mx-FBIUdy5IGTOj3mEcu1Cb-lOmZ1cn1nqrJqXS7vBMdSANt9rXp1bJie4EVib8GnB5O1ry7uVldKOHf_oACE",
  "q": "6pDRfQzE1WN0J-RsUqOVgqDlFiUcmaZWS46ZhdH-qtUuQqLw80sB1ihIRnwUDK9ZRQo9qIuiWbtYU4W9DzwuXbwzpQpNvMcZq4B4pBDXYQM_3k55Y5gR3F__11uPisnQ20bBNj2bQ3pI-2QWC44ah9V7YBfBRFKnnSniwvKlzw0",
  "dp": "5a2qnL12iNGXDsJGsP8Fsaaw195LPnqf5awekS_S5L3ptB3_awaLaU9_or2B6QLVIo53OJXNpETTCHIHDpyHBNYtb_MtVu7xCz_J-A4JGiZxfN5veOmjn2hkO0UObl7gnhwtH3ZQhXm0mzFmzl5hA9IjxYxk5Q2-6KFjK7_2kmE",
  "dq": "CO77C4gw9u-SvPI2Le-NAiyejPlc3X04TChiMHaO_HKiEGekRZ_VshJWrliLavBCth5tur2WsVQxSP0O9kWUfn1sehyqWUY79AwwjA8YJNm61PyoIuLnyzzcwZb7II4PJkrLkQVHpIpDvU9Sh54h5Ip86Gv_MFr1h0bRHBuhtQE",
  "qi": "m8JW6xqRdL5xAzosYyF-VkduqolRZ7g7e-Ty7648HmwGlBxcT5lv2B5-7a4oRAbtm2MIBeIbH4PrdtO9Tb4giL4kFHRMG9EOvLrWOs2uELAlMEUCKzAlidGwRFEaX1zS-1leKQ8DxsctFOhsCVLXWDFshnhnuAi9DKcu2NmBj1M",
  "x5c": [
    "MIIDIzCCAgugAwIBAgIUQWgOz6oG5UT6R+LC6bDfh0Bj0zAwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWaG9yaWtpdGEuandrZGVtby5sb2NhbDAeFw0yNTA0MTIxNTU1NDlaFw0yNjA0MTIxNTU1NDlaMCExHzAdBgNVBAMMFmhvcmlraXRhLmp3a2RlbW8ubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVTjsJIL9TsSgEecMKg3w3WojQgAEImiO7PuMqjsqXi4qUcthhuBdQsf2f3PIWrv91OS5y446v5GRDu0BvBhSmKyz/VWr+od6kfjPPEI+3JgNcIY39Bf2mszK0KLCmcRhuEZvSUflsHx2aUUuZroO1JysJcGpMhsB1DiFJRIyAM4HbpW2ZoO4S+T9lGOzXYxyNeh8gu3vZljVRJ9Q56r7nAMbFsOalSN7ViPnha+TCoTyknIBXDmIuV16kLfZVH8+3/nK31yVglWJSWs0DHkqxxkDPrfth+KSCgPzVI45E/rSzVqOMfIm/+gmbN7uSTiOGPJeWQv0wNdIQ9RveJ7CtAgMBAAGjUzBRMB0GA1UdDgQWBBQI/i/gyh2lPWSTxlpf0TQAnYwfrDAfBgNVHSMEGDAWgBQI/i/gyh2lPWSTxlpf0TQAnYwfrDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBHmEEIywoL6NeSXXwjK8XKj/RF/1dzBD+XfsGDsPF8Rzy+zHzKulnW8fIpJ7Ftdo6EOutx6J3qCl8228MAkhxQ2UOCysB4Wbu9gzlRXtbSlzaAh99wThjmME80lEs9dhQ2diWaknXSz6o2/HZ5auXIX13E3ZU3elSl1ov0D/IStQVKR1nqKvSLAATy2GjppB7vpWB1jKfzH2pYoS9wzI/D+THhG1FGs9oMKofrvw4HBcxzHGXXzAd4S1SgY3uncKkXplqkNbjjEEu19xdhA9Mit+C3EypjUV9TJQfFxurchhA2GVMhK8RTLdRf2OW7SXwbytsnxLTomAwg2WoMDVuX"
  ]
}'

cat jwk_public.json
#Outputs following
'{
  "kty": "RSA",
  "kid": "aCu1pJ8E1xxmim4V_lJU_ocjHCOlD0lcrNcL9tYrqkU",
  "n": "1U47CSC_U7EoBHnDCoN8N1qI0IABCJojuz7jKo7Kl4uKlHLYYbgXULH9n9zyFq7_dTkucuOOr-RkQ7tAbwYUpiss_1Vq_qHepH4zzxCPtyYDXCGN_QX9prMytCiwpnEYbhGb0lH5bB8dmlFLma6DtScrCXBqTIbAdQ4hSUSMgDOB26VtmaDuEvk_ZRjs12McjXofILt72ZY1USfUOeq-5wDGxbDmpUje1Yj54WvkwqE8pJyAVw5iLldepC32VR_Pt_5yt9clYJViUlrNAx5KscZAz637YfikgoD81SOORP60s1ajjHyJv_oJmze7kk4jhjyXlkL9MDXSEPUb3iewrQ",
  "e": "AQAB",
  "x5c": [
    "MIIDIzCCAgugAwIBAgIUQWgOz6oG5UT6R+LC6bDfh0Bj0zAwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWaG9yaWtpdGEuandrZGVtby5sb2NhbDAeFw0yNTA0MTIxNTU1NDlaFw0yNjA0MTIxNTU1NDlaMCExHzAdBgNVBAMMFmhvcmlraXRhLmp3a2RlbW8ubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVTjsJIL9TsSgEecMKg3w3WojQgAEImiO7PuMqjsqXi4qUcthhuBdQsf2f3PIWrv91OS5y446v5GRDu0BvBhSmKyz/VWr+od6kfjPPEI+3JgNcIY39Bf2mszK0KLCmcRhuEZvSUflsHx2aUUuZroO1JysJcGpMhsB1DiFJRIyAM4HbpW2ZoO4S+T9lGOzXYxyNeh8gu3vZljVRJ9Q56r7nAMbFsOalSN7ViPnha+TCoTyknIBXDmIuV16kLfZVH8+3/nK31yVglWJSWs0DHkqxxkDPrfth+KSCgPzVI45E/rSzVqOMfIm/+gmbN7uSTiOGPJeWQv0wNdIQ9RveJ7CtAgMBAAGjUzBRMB0GA1UdDgQWBBQI/i/gyh2lPWSTxlpf0TQAnYwfrDAfBgNVHSMEGDAWgBQI/i/gyh2lPWSTxlpf0TQAnYwfrDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBHmEEIywoL6NeSXXwjK8XKj/RF/1dzBD+XfsGDsPF8Rzy+zHzKulnW8fIpJ7Ftdo6EOutx6J3qCl8228MAkhxQ2UOCysB4Wbu9gzlRXtbSlzaAh99wThjmME80lEs9dhQ2diWaknXSz6o2/HZ5auXIX13E3ZU3elSl1ov0D/IStQVKR1nqKvSLAATy2GjppB7vpWB1jKfzH2pYoS9wzI/D+THhG1FGs9oMKofrvw4HBcxzHGXXzAd4S1SgY3uncKkXplqkNbjjEEu19xdhA9Mit+C3EypjUV9TJQfFxurchhA2GVMhK8RTLdRf2OW7SXwbytsnxLTomAwg2WoMDVuX"
  ]
}'
```


## JWT Creation With Private JWK
```shell
npm install jose

npm list jose

node sign_jwt.js --jwk out/jwk_full_private.json
```

This will output a JWT something like this:
```shell
SUCCESS: Signed JWT:
eyJhbGciOiJSUzI1NiIsImtpZCI6ImFDdTFwSjhFMXh4bWltNFZfbEpVX29jakhDT2xEMGxjck5jTDl0WXJxa1UifQ.eyJzdWIiOiJzdXp1bmUuaG9yaWtpdGEiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NDQ0ODExMDksImlhdCI6MTc0NDQ4MDUwOX0.WcpsBNL-EuQbWsVQzy47zQt-dDpPEqCeO1HhohWVceWEF1X6h9vq8s0g7Tj4I3RtjlfVUg7a6vNFrSe8qiPBBnH5q-asoprYNVxYt_tWii8LgD6aWPT_eWIM0l381YJYxsEn-qc6KgXkpp53rt_ZwqrDlDYGpy2mXxanElzOVL9SB8SPn8i09HOgxuyluTo0ZoaFVaEorlzws4gaekJBvsklavRvFNI_Rvg9CfVVXqi7WodKiI4W_GB44D5FlJMdRsj1GbbTMheh6UZnkWSo2otjncA2hW3wF8LbXggg4D9Suj1i8RB87VG4-itzWb_MuTfMWY7CNw1JI2xPmbBafw
```

You can base64 decode and verify the header and body.
```shell
#Verify Header
echo eyJhbGciOiJSUzI1NiIsImtpZCI6ImFDdTFwSjhFMXh4bWltNFZfbEpVX29jakhDT2xEMGxjck5jTDl0WXJxa1UifQ | base64 -d 

# Or use follwing if base64 decoding complains about invalid input due to padding and _
echo 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImFDdTFwSjhFMXh4bWltNFZfbEpVX29jakhDT2xEMGxjck5jTDl0WXJxa1UifQ' \
| sed 's/-/\//g; s/_/+/' \
| awk '{ l=length($0)%4; if(l==2) print $0"=="; else if(l==3) print $0"="; else print $0 }' \
| base64 -d

#This outputs following
{"alg":"RS256","kid":"aCu1pJ8E1xxmim4V_lJU_ocjHCOlD0lcrNcL9tYrqkU"} 

#Body
echo eyJzdWIiOiJzdXp1bmUuaG9yaWtpdGEiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NDQ0ODExMDksImlhdCI6MTc0NDQ4MDUwOX0 | base64 -d

#This outputs following
{"sub":"suzune.horikita","role":"admin","exp":1744481109,"iat":1744480509}
```

## JWT Validation With Public JWK
```shell
export token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImFDdTFwSjhFMXh4bWltNFZfbEpVX29jakhDT2xEMGxjck5jTDl0WXJxa1UifQ.eyJzdWIiOiJzdXp1bmUuaG9yaWtpdGEiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NDQ0ODExMDksImlhdCI6MTc0NDQ4MDUwOX0.WcpsBNL-EuQbWsVQzy47zQt-dDpPEqCeO1HhohWVceWEF1X6h9vq8s0g7Tj4I3RtjlfVUg7a6vNFrSe8qiPBBnH5q-asoprYNVxYt_tWii8LgD6aWPT_eWIM0l381YJYxsEn-qc6KgXkpp53rt_ZwqrDlDYGpy2mXxanElzOVL9SB8SPn8i09HOgxuyluTo0ZoaFVaEorlzws4gaekJBvsklavRvFNI_Rvg9CfVVXqi7WodKiI4W_GB44D5FlJMdRsj1GbbTMheh6UZnkWSo2otjncA2hW3wF8LbXggg4D9Suj1i8RB87VG4-itzWb_MuTfMWY7CNw1JI2xPmbBafw

node verify_jwt.js --jwt ${token} --jwk out/jwk_public.json

#Output
SUCCESS: JWT is valid!
JWT Header: { alg: 'RS256', kid: 'aCu1pJ8E1xxmim4V_lJU_ocjHCOlD0lcrNcL9tYrqkU' }
JWT Payload: {
  sub: 'suzune.horikita',
  role: 'admin',
  exp: 1744481109,
  iat: 1744480509
}
```

## What Your Real-World Flow would look like with managed JWKs
Read more on why I created this demo here - https://medium.com/@horikitas/designing-trust-managing-jwks-with-x5c-cert-rotation-and-real-world-lifecycles-c0052c4117d3
![img.png](img.png)
