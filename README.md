# spnego
This provides a Common Lisp implementation of SPNEGO authentication. Essentially this is a wrapper around NTLM and Kerberos,
with an initial negotiation phase between client and server to decide which method can be used. 

## 1. Introduction
The SPNEGO authentication system provides a pseduo-authentication system which resolves to either NTLM or Kerberos as 
dictated by an initial negotiation phase between client and server. As a result, it can require multiple exhanges 
before authentication completes.

## 2. Usage
Use the various generic functions from [glass](https://github.com/fjames86/glass).

### 2.1 Client
The client calls are implemented and have been shown to work. 

```
;; get a credential handle
(glass:acquire-credentials :spnego "service/host@DOMAIN.COM")

;; generate the initial buffer
(glass:initialize-security-context *creds*)

;; possibly feed the buffer back into the initial context (if several negotiation steps required)
(glass:initialize-security-context context :buffer buffer)
```

### 2.2 Server 
The equivalent to the client calls, but with ACCEPT-SECURITY-CONTEXT.

```
;; get a credential handle
(glass:acquire-credentials :spnego nil)

;; accept an input buffer
(glass:accept-security-context creds buffer)

;; possibly generate another buffer if multiple steps required (mutual authentication)
(glass:accept-security-context context buffer)
```

## 3. Notes
The underlying NTLM and Kerberos implementations are [ntlm](https://github.com/fjames86/ntlm) and [cerberus](https://github.com/fjames86/cerberus).

## 4. License
Licensed under the terms of the MIT license.

Frank James 
June 2015.


