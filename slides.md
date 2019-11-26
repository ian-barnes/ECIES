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
2. Alice uses asymmetric encryption to wrap the symmetric key with Bob's public key
3. Alice sends both the encrypted message and wrapped key to Bob.

Bob uses his private key to unwrap the symmetric key, and then uses that to decrypt the message.

Examples: [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security) (TLS) and [OpenPGP](https://tools.ietf.org/html/rfc4880#section-2).

---

## ECIES

- Don't wrap the symmetric key
- Instead use elliptic curve Diffie-Helman (ECDH) key agreement to enable both Alice and Bob to derive it.

ECIES is used by Google Pay and Ethereum.

---

## Other interesting feature of ECIES

- Instead of using her private key, Alice creates a single-use "ephemeral" key pair for her end of the key agreement.
  - This ensures that the symmetric key is different for every message sent.

- Use a  KDF to generate the symmetric key from the ECDH shared secret.

- Use a MAC so Bob can verify that the message has not been tampered with.
  - The MAC key is also derived from the shared secret using the KDF.

---

## ECIES in detail

1. Preparation
2. Alice sends a message to Bob
3. Bob checks and decrypts the message

---

## Preparation

1. Alice and Bob agree on a choice of elliptic curve, KDF, symmetric encryption algorithm and MAC algorithm.
2. Bob generates an EC public/private key pair and sends Alice his public key, for example by publishing it in an X509 certificate.

---

## Alice sends Bob a message

1. Alice generates an ephemeral EC public/private key pair, to be used for this message only.
2. Alice uses ECDH with the ephemeral private key and Bob's public key to generate a shared secret.
3. Alice destroys the ephemeral private key.
4. Alice uses the KDF to derive a symmetric key and MAC key from the shared secret.
5. Alice encrypts her message using the symmetric algorithm and the derived symmetric key.
6. Alice computes a MAC of the encrypted message using the derived MAC key.
7. Alice sends the ephemeral public key, the MAC output and the ciphertext to Bob.

---

## Bob authenticates and decrypts the message

1. Bob uses ECDH with his private key and Alice's ephemeral public key to derive the shared secret.
2. Bob uses the KDF to derive the symmetric key and the MAC key.
3. Bob verifies the integrity of the ciphertext by computing the MAC and comparing it to the received value.
4. Bob decrypts the ciphertext using the derived symmetric key.

---

## Variations on ECIES

- Use authenticated encryption (e.g. AES/GCM) instead of separate symmetric encryption and MAC operations.

- Streaming mode: don't use a symmetric cipher, instead use the KDF to generate key material the same length as the plaintext message, and generates the ciphertext by XORing the plaintext and the key material bit streams.

---

## ECIES in Java

Two options:

- BouncyCastle
  - via standard JCE API with a `Cipher` object with algorithm `ECIES`

- Tink
  - built on top of the existing Java cryptography providers
  - does not use the standard JCE API
  - uses trusted implementations of ECDH key agreement on chosen curves and authenticated encryption with 128-bit AES/GCM

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
ciphertext = 0448c28c1c293228b31d06227b61be0ec09510d9f6e629dcdef0f93b9128a3813ee573412108f3157b23dea
f71036f268d39c28d511e2ed4ee80af42e66aa311b19ac904518220c422075d72e15f1b640337526bf93159d4c719635f0ca
54ffec77872d89b
plaintext = 68656c6c6f
```

The `ciphertext` byte array is much longer than the plaintext message because it contains the ephemeral public key and the MAC output as well as the actual encrypted message.

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
ciphertext = 01743b2309040f3f72d9be18ba7a1ead7f9e125ef10e089dd43b53b99f1d33c73132c9575b07ac24ea7d0c6
04d3a6a072366556a9acfe7e7c2c4919cf2088b096533cb42ad17f45f8e7f18f38dc631081d51bca62573e5354241e7f0fb4
22ae42985cac9d4f235
plaintext = 68656c6c6f
```

---

## How not to screw up ECIES

Four categories of potential weaknesses:

- those inherent to the design of ECIES,
- incorrect implementation of the scheme,
- weaknesses in elliptic curve crypto, and
- weaknesses in the other cryptographic primitives used to implement the scheme.

---

## Inherent limitations

Even if correctly implemented and used, ECIES isn't going to be the right choice for all applications. In particular there are some aspects of the design that may make it unsuitable for you:

- With ECIES, Bob has no guarantee that a message really came from Alice.
- ECIES also doesn't offer forward security: if Bob's private key is compromised, all past, present and future messages can be decrypted.

There's not much you can do about this sort of thing. If either of these is a problem for you, don't use ECIES.

---

## Incorrect implementation of the scheme

If your implementation of ECIES doesn't follow the steps correctly, then you're not really doing ECIES, and that could lead to vulnerabilities.

An example of this might be if Alice used her long-term key pair for the ECDH key agreement instead of generating a new ephemeral key pair for each message. This would mean that the same symmetric key would end up being used for all messages from Alice to Bob. And that's a problem for two reasons:

- because it gives an attacker a better chance of obtaining those keys, and
- because instead of only letting the attacker decrypt one message, that key would decrypt all past, present and future messages between Alice and Bob.

This sort of problem can be prevented by using one of the standard implementations as shown above. In the case of BouncyCastle, make sure to use a recent version. Older versions required the application programmer to create the ephemeral key pair as a separate step, making it too easy to mess this up.

---

## Elliptic curve cryptographic weaknesses

Weaknesses in the ECDH key agreement step basically come down to the choice of curve.

- Curves with keys that are less than 256 bits are now generally considered to be too short.
- Even if the keys are long enough, some curves are known to have weaknesses that make cryptanalysis easier than their length would suggest.

These problems can be avoided by choosing a well-known standard curve with keys at least 256 bits in length. Both the examples above use the NIST P-256 curve, which many people think is a reasonable choice. If you're worried that the [NSA might have influenced NIST's choice of curves](https://www.schneier.com/blog/archives/2013/09/the_nsa_is_brea.html#c1675929), maybe use a non-NIST alternative like [Curve25519](https://en.wikipedia.org/wiki/Curve25519) instead.

---

## Weaknesses in the components

Even if the ECIES steps are followed correctly, if the cryptographic primitives it uses are weak, then the result will be weak also. This applies to:

- the KDF
- the symmetric encryption algorithm
- the MAC

The library implementations above make sound choices. If you use the BouncyCastle library through their own API rather than the standard JCE API, then you have the freedom to make your own (bad) choices. We don't recommend that.

Older versions of the BouncyCastle provider had weaknesses in the symmetric encryption: use of ECB mode (see CVE-2016-1000352) and a version of CBC mode that was vulnerable to a padding oracle attack (see CVE-2016-1000345). These bugs were fixed in version 1.56, released in December 2016. Anyone using an older version of the BouncyCastle provider should upgrade as soon as possible.