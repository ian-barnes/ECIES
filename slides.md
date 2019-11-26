---
title: ECIES
theme: moon
revealOptions:
    transition: 'none'
css: slides.css
---

## ECIES

### Elliptic Curve Integrated Encryption

---

## Outline

1. How ECIES works
2. How to use ECIES in Java
3. How (not) to mess it up

---

## Hybrid encryption

- Use a combination of symmetric and asymmetric cryptography
- Speed / security of symmetric
- Key distribution / agreement of asymmetric

---

## Typical simple hybrid scheme

1. Alice generates a unique symmetric key and encrypts the message with it.
2. Alice uses asymmetric encryption to wrap the symmetric key with Bob's public
   key
3. Alice sends both the encrypted message and wrapped key to Bob.

Bob uses his private key to unwrap the symmetric key, and then uses that to
decrypt the message.

TLS and OpenPGP both work like this.

---

## ECIES hybrid scheme

A bit different:

- Don't wrap the symmetric key
- Instead use elliptic curve Diffie-Helman (ECDH) key agreement to enable both
  Alice and Bob to derive it.

ECIES is used by Google Pay and Ethereum.

---

## Other interesting feature of ECIES

- Instead of using her private key, Alice creates a single-use "ephemeral" key
  pair for her end of the key agreement.

  - This ensures that the symmetric key is different for every message sent.

- Use a  KDF to generate the symmetric key from the ECDH shared secret.

- Use a MAC so Bob can verify that the message has not been tampered with.

  - The MAC key is also derived from the shared secret using the KDF.

---

## ECIES in detail

Three phases:

1. Preparation

2. Alice sends a message to Bob

3. Bob checks and decrypts the message

---

## Preparation

1. Alice and Bob agree on a choice of elliptic curve, KDF, symmetric encryption
   algorithm and MAC algorithm

2. Bob generates an EC public/private key pair and sends Alice his public key,
   for example by publishing it in an X509 certificate

---

## Alice sends Bob a message

1. Alice generates an ephemeral EC public/private key pair

2. Uses ECDH with the ephemeral private key and Bob's public key to generate a
   shared secret

3. Destroys the ephemeral private key

4. Uses the KDF to derive symmetric MAC keys from the shared secret

5. Encrypts the message using the derived symmetric key

6. Computes a MAC of the ciphertext using the derived MAC key

7. Sends Bob the ephemeral public key, the MAC and the ciphertext

---

## Bob authenticates and decrypts

1. Bob uses ECDH with his private key and Alice's ephemeral public key to derive
   the shared secret

2. Uses the KDF to derive the symmetric key and the MAC key

3. Verifies the integrity of the ciphertext by computing the MAC and comparing
   it to the received value

4. Decrypts the ciphertext using the derived symmetric key

---

## Variations on ECIES

- Use authenticated encryption (e.g. AES/GCM) instead of separate symmetric
  encryption and MAC operations.

- Streaming mode: don't use a symmetric cipher, instead use the KDF to generate
  key material the same length as the plaintext message, and generates the
  ciphertext by XORing the plaintext and the key material bit streams.

---

## ECIES in Java

Two options:

- BouncyCastle
  - via standard JCE API with a `Cipher` object with algorithm `ECIES`

- Tink
  - built on top of the existing Java cryptography providers
  - does not use the standard JCE API
  - uses trusted implementations of ECDH key agreement on chosen curves and
    authenticated encryption with 128-bit AES/GCM

---

### BouncyCastle

```java
Security.addProvider(new BouncyCastleProvider());

// Generate Bob's key pair
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH");
keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair keyPair =  keyPairGenerator.generateKeyPair();
PublicKey publicKey = keyPair.getPublic();
PrivateKey privateKey = keyPair.getPrivate();

// Message
byte[] message = "hello".getBytes();
System.out.println("message = " + Hex.toHexString(message));

// Alice encrypts the message
Cipher cipher = Cipher.getInstance("ECIESWithAES-CBC");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
byte[] ciphertext = cipher.doFinal(message);
System.out.println("ciphertext = " + Hex.toHexString(ciphertext));

// Bob decrypts the message
AlgorithmParameters params = cipher.getParameters();
cipher.init(Cipher.DECRYPT_MODE, privateKey, params);
byte[] plaintext = cipher.doFinal(ciphertext);
System.out.println("plaintext = " + Hex.toHexString(plaintext));
```

---

And here's the output:

```txt
message = 68656c6c6f
ciphertext = 0448c28c1c293228b31d06227b61be0ec09510d9f6e629dcdef0f93b9128a3813ee
573412108f3157b23deaf71036f268d39c28d511e2ed4ee80af42e66aa311b19ac904518220c4220
75d72e15f1b640337526bf93159d4c719635f0ca54ffec77872d89b
plaintext = 68656c6c6f
```

The ciphertext is much longer than the plaintext message because it contains the
ephemeral public key and the MAC output as well as the actual encrypted message.

---

### Tink

```java
TinkConfig.register();

// Generate Bob's key pair
KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(
    HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
);
KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

// Message
byte[] message = "hello".getBytes();
System.out.println("message = " + Hex.encode(message));

// Alice encrypts the message
HybridEncrypt hybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt.class);
byte[] ciphertext = hybridEncrypt.encrypt(message, null);
System.out.println("ciphertext = " + Hex.encode(ciphertext));

// Bob decrypts the message
HybridDecrypt hybridDecrypt = privateKeysetHandle.getPrimitive(HybridDecrypt.class);
byte[] plaintext = hybridDecrypt.decrypt(ciphertext, null);
System.out.println("plaintext = " + Hex.encode(plaintext));
```

---

And again, here's the output:

```txt
message = 68656c6c6f
ciphertext = 01743b2309040f3f72d9be18ba7a1ead7f9e125ef10e089dd43b53b99f1d33c7313
2c9575b07ac24ea7d0c604d3a6a072366556a9acfe7e7c2c4919cf2088b096533cb42ad17f45f8e7
f18f38dc631081d51bca62573e5354241e7f0fb422ae42985cac9d4f235
plaintext = 68656c6c6f
```

---

## How not to screw up ECIES

Four categories of potential weaknesses:

- those inherent to the design of ECIES

- incorrect implementation of the scheme

- weaknesses in elliptic curve crypto

- weaknesses in the other cryptographic primitives used to implement the scheme

---

## Inherent limitations

- Bob has no guarantee that a message really came from Alice

- No forward security: if Bob's private key is compromised, all past, present
  and future messages can be decrypted

---

## Incorrect implementation of the scheme

**Example:** Alice uses her long-term key pair instead of generating a new
ephemeral key pair for each message.

**Consequence:** The same symmetric key gets used for all messages from Alice to
Bob.

That's a problem for two reasons:

- it gives an attacker a better chance of obtaining the key
- that key would decrypt all past, present and future messages between Alice and
  Bob

Old BouncyCastle versions made this easy, and the test code made no distinction
between long-term and ephemeral keys.

---

## Elliptic curve cryptographic weaknesses

Weaknesses in the ECDH key agreement step (and in EC crypto generally) basically
come down to the choice of curve.

- Curves with keys that are less than 256 bits are now generally considered to
  be too short

- Even if the keys are long enough, some curves are known to have weaknesses
  that make cryptanalysis easier than their length would suggest.

Choose a well-studied standard curve with keys at least 256 bits in length.

---

## Safe curves?

Both examples use the NIST P-256 curve. However some people think the NSA might
have influenced NIST's choice of curves. Schneier:

> I no longer trust the constants. I believe the NSA has manipulated them
> through their relationships with industry.

In that case maybe use a non-NIST alternative like Curve25519 instead.

And see the Safe Curves project: <https://safecurves.cr.yp.to/>

---

## Weaknesses in the components

Even if the ECIES steps are followed correctly, if the cryptographic primitives
it uses are weak, then the result will be weak also.

This applies to:

- the KDF
- the symmetric encryption algorithm
- the MAC

If you use BouncyCastle library through its own API rather than the standard JCE
API, then you have the freedom to make your own (bad) choices.

---

## BouncyCastle ECIES CVEs

Older versions of BouncyCastle used weak symmetric encryption:

- ECB mode (CVE-2016-1000352)

- a version of CBC mode that was vulnerable to a padding oracle attack
  (CVE-2016-1000345)

These bugs were fixed in version 1.56 (December 2016)

---
