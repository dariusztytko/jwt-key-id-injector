# JWT Key ID Injector
Simple python script to check against hypothetical JWT vulnerability.

Let's say there is an application that uses JWT tokens signed HS256 algorithm. An example token looks like the follow:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.zbgd5BNF1cqQ_prCEqIvBTjSxMS8bDLnJAE_wE-0Cxg
```
Above token can be decoded to the following data:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```
To calculate signature the following secret is used:
```
supersecret
```

The following pseudo code is used to calculate signature:
```
$alg = "sha256";
$data = "...";
$key = "supersecret";

hmac($alg, $data, $key);
```
But what if unexpected **"kid":0** field will be injected into the header?
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": 0
}
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```
**kid** field is a standard way to choose a key.
My assumption is that, if **kid** field is not expected, there may be vulnerable implementation that will treat the string $key value as an array:
```
hmac($alg, $data, $key[kid]);
```
As results "s" ($key[0]) value will be used as an HMAC secret.

## Usage
injector.py script takes original JWT token,
injects "kid":0 field into the header
and generates tokens signed with the one-letter secrets
(ASCII codes: 32 - 126 [{space}, !, ", #, ..., x, y, z, {, |, }, ~]):
```
python3 injector.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.zbgd5BNF1cqQ_prCEqIvBTjSxMS8bDLnJAE_wE-0Cxg
```
As results two files are created - tokens.txt and tokens_meta.txt.
tokens.txt contains generated tokens and can be used as a list of payloads for the Burp Intruder.
If any token is valid (what means that application is vulnerable),
tokens_meta.txt file can be used to check what algorithm and secret were used to generate the given token.
tokens_meta.txt file contains the following data:
```
token1:algorithm:secret
...
token{n}:algorithm:secret
```

## Changes
Please see the [CHANGELOG](CHANGELOG)
