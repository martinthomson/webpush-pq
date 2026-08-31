---
title: "WebPush Encryption using HPKE"
category: std

docname: draft-thomson-webpush-hpke-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
obsoletes: 8291
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Web-Based Push Notifications"
keyword:
 - spam
 - transdimensional annoyance
venue:
  group: "Web-Based Push Notifications"
  type: "Working Group"
  mail: "webpush@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/webpush/"
  github: "martinthomson/webpush-hpke"
  latest: "https://martinthomson.github.io/webpush-hpke/draft-thomson-webpush-hpke.html"

author:
 -
    fullname: "Martin Thomson"
    organization: Mozilla
    email: "mt@lowentropy.net"

normative:

informative:
  WEBPUSH-SYM:
    title: WebPush Encryption using Symmetric Ciphers
    author:
      - name: Martin Thomson
    seriesinfo:
      Internet-Draft: draft-thomson-webpush-sym-latest
    date: draft-thomson-webpush-sym-date

  CDJZ:
    title: >
      Automated Analysis of Protocols that use Authenticated Encryption:
      How Subtle AEAD Differences can impact Protocol Security
    date: 2023-08
    author:
      - name: Cas Cremers
      - name: Alexander Dax
      - name: Charlie Jacomme
      - name: Mang Zhao
    seriesinfo:
      USENIX: 2023

...

--- abstract

This document defines how to use Hybrid Public Key Encryption (HPKE)
with Web Push.

This document obsoletes RFC 8291.


--- middle

# Introduction

Message Encryption for Web Push {{?RFC8291}}
defines a hybrid encryption system
that depends on elliptic curve cryptography.
This system is known to be vulnerable to compromise
in the event that a cryptographically-relevant quantum computer (CRQC)
is created.
The risk of this resulting in the compromise of Web Push encryption
will be increasingly likely as time passes {{?PQC-GUIDE=RFC9958}}.

This document defines a message encryption design
that can integrate a post-quantum KEM.
This design is a generic use
of Hybrid Public Key Encryption (HPKE) {{!HPKE=I-D.ietf-hpke-hpke}}
that can use any defined set of algorithms.

At the same time, the use of HPKE addresses a minor, but inconsequential,
vulnerability in the design of {{?RFC8291}}
that would allow an application to construct a single ciphertext
that two parties would successfully authenticate
and decrypt to different plaintexts.
This attack is described in {{proteus}}.

This document obsoletes RFC 8291 {{?RFC8291}}.

This document is one of a pair.
Its companion, {{WEBPUSH-SYM}} is an alternative to this approach.
{{WEBPUSH-SYM}} describes how to encode messages
using symmetric cryptography.

Of the two options, this is the most conservative.
It retains the same properties as {{?RFC8291}} with respect to key compromise.
However, it is also grossly less efficient
due to the massive overhead of current PQ KEMs.
If it is feasible to rotate client keys more frequently,
the design in {{WEBPUSH-SYM}} is likely a better choice
as it is simpler and more efficient.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Using HPKE in Web Push

Web Push {{!WEBPUSH=RFC8030}} provides a messaging capability
that allows applications to send small messages
to user agents via a push service.
The push service enables efficient message delivery,
even when user agents have constrained connectivity.

Typical interactions for Web Push are shown in {{f-overview}}.

~~~ aasvg

    +-------+           +--------------+       +-------------+
    |  UA   |           | Push Service |       | Application |
    +-------+           +--------------+       +-------------+
        |                      |                      |
        |        Setup         |                      |
        |<====================>|                      |
        |                      |                      |
        |           Provide Subscription              |
        |-------------------------------------------->|
        |                      |                      |
    ~~~~~~~~~~~~~~~~~~~~~~~ (Later) ~~~~~~~~~~~~~~~~~~~~~~~
        |                      |                      |
        |                      |     Push Message     |
        |    Push Message      |<---------------------|
        |<---------------------|                      |
        |                      |                      |
~~~
{: #f-overview title="Web Push Overview"}

Encryption of push messages ensures that the push service
is unable to read or alter the messages it handles.

Web Push uses a hybrid encryption mode that combines
a key-encapsulation mechanism (KEM)
and pre-shared key (PSK)
with authenticated encryption with additional data (AEAD) encryption.
This document describes how this can be provided by {{!HPKE}}.

The overall encryption design is composed from two parts:

1. A user agent key configuration,
   where the user agent provides the information
   necessary to construct a message it will accept.
   This is provided by the user agent to the application
   during the establishment of a Web Push subscription.
   Details of the format of this key configuration
   are provided in {{config}}.

2. A message protection format,
   used to encode push messages.
   This format is defined in {{message}}.


# User Agent Key Configuration {#config}

In order for an application server to send a push message using HPKE,
it requires knowledge of:

* the HPKE algorithms that the user agent accepts,
* the PSK the user agent has chosen, and
* the KEM public key (or keys) the user agent holds secret keys for.

This information is formatted into a key configuration,
similar in shape to that used in
the Encrypted Client Hello (ECH) `HpkeKeyConfig` ({{Section 4 of ?ECH=RFC9849}})
or the Oblivious HTTP key configuration ({{Section 3 of ?OHTTP=RFC9458}}).

{{f-config}} shows the format of the key configuration,
using the format described in {{Section 1.3 of ?QUIC=RFC9000}}.

~~~ artwork
Key Config {
  Key Config Item With Length (..) ...,
}

Key Config Item With Length {
  Key Config Item Length (16),
  Key Config Item (..),
}

Key Config Item {
  Key Identifier (8),
  PSK (128),
  HPKE KEM ID (16),
  HPKE Public Key (Npk * 8),
  HPKE Symmetric Algorithms Length (16) = 4..65532,
  HPKE Symmetric Algorithms (32) ...,
}

HPKE Symmetric Algorithms {
  HPKE KDF ID (16),
  HPKE AEAD ID (16),
}
~~~
{: #f-config title="Configuration Format"}

The format consists of one or more Key Config Items,
each prefixed with a 16 bit length, in network byte order.

Each Key Config Item contains:

Key Identifier:

: An 8 bit value that will be used in protected messages
  to identify the user agent's PSK and KEM secret key.

PSK:

: A 16 byte sequence of bytes of the pre-shared key.

HPKE KEM ID:

: A 16 bit value that identifies the Key Encapsulation Method (KEM)
  used for the identified key
  as defined in {{Section 7.1 of HPKE}}
  or [the HPKE KDF IANA registry](https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kem-ids).

HPKE Public Key:

: The public key used by the user agent.
  The length of the public key is `Npk`,
  which is determined by the choice of HPKE KEM
  as defined in {{Section 4 of HPKE}}.
  (As a result, knowledge of the KEM is necessary
  to process subsequent fields.)

HPKE Symmetric Algorithms Length:

: A 16 bit integer in network byte order that encodes the length, in bytes,
  of the HPKE Symmetric Algorithms field that follows.

HPKE Symmetric Algorithms:

: One or more pairs of identifiers for the different combinations
  of HPKE KDF and AEAD
  that the user agent supports:
  <dl>
  <dt>HPKE KDF ID:</dt>
  <dd markdown="1">
  A 16 bit HPKE KDF identifier as defined in {{Section 7.2 of HPKE}}
  or [the HPKE KDF IANA registry](https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kdf-ids).
  </dd>
  <dt>HPKE AEAD ID:</dt>
  <dd markdown="1">
  A 16 bit HPKE AEAD identifier as defined in {{Section 7.3 of HPKE}}
  or [the HPKE AEAD IANA registry](https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-aead-ids).
  </dd>
  </dl>


# HPKE-Encrypted Push Message Format {#message}

The format of push messages when using HPKE is illustrated in {{f-message}}.

~~~ artwork
HPKE-Protected Push Message {
  Key Identifier (8),
  HPKE KEM ID (16),
  HPKE KDF ID (16),
  HPKE AEAD ID (16),
  Encapsulated KEM Shared Secret (8 * Nenc),
  HPKE-Protected Message Contents (..),
}
~~~
{: #f-message title="HPKE-Protected Push Message Format"}

This format is identical to that in {{Section 4.1 of OHTTP}}
and it uses a similar construction
following the guidance of {{Section 4.6 of OHTTP}},
differing only in that it includes a pre-shared key.
Processes for the application server that sends messages
are included in {{encrypt}};
processes for the user agent that receives messages
are included in {{decrypt}}.


## Push Message Application Server Processing {#encrypt}

Applications encapsulate a push message, `msg`,
using values from the key configuration:

* the key identifier from the configuration, `key_id`,
  with the corresponding KEM identified by `kem_id`,

* the pre-shared key from the configuration, `psk`,

* the public key from the configuration, `pkR`, and

* a combination of KDF, identified by `kdf_id`,
  and AEAD, identified by `aead_id`,
  that the application selects from those in the key configuration.

The application then constructs an encrypted push message, `push_message`,
from the plaintext of the message, `msg`, as follows:

1. Construct a message header, `hdr`, by concatenating the values of `key_id`,
   `kem_id`, `kdf_id`, and `aead_id`, as one 8-bit integer and three 16-bit
   integers, respectively, each in network byte order.

2. Build `info` by concatenating the ASCII-encoded string "webpush message",
   a zero byte,
   and the header.

3. Create a sending HPKE context by invoking `SetupPSKS()`
   ({{Section 5.1.2 of HPKE}})
   with the public key of the receiver `pkR`,
   `info` as constructed,
   the pre-shared key `psk`,
   a single byte pre-shared key identifier containing a single `key_id`.
   This yields the context `sctxt` and an encapsulation key `enc`.

4. Encrypt `msg` by invoking the `Seal()` method on `sctxt`
   ({{Section 5.2 of HPKE}})
   with empty associated data `aad`,
   yielding ciphertext `ct`.

5. Concatenate the values of `hdr`, `enc`, and `ct`,
   yielding an encrypted push message `push_message`.

Note that `enc` is of fixed-length, so there is no ambiguity in parsing this
structure.

In pseudocode, this procedure is as follows:

~~~ pseudocode
hdr = concat(encode(1, key_id),
             encode(2, kem_id),
             encode(2, kdf_id),
             encode(2, aead_id))
info = concat(encode_str("webpush message"),
              encode(1, 0),
              hdr)
enc, sctxt = SetupPSKS(pkR, info, psk, [key_id])
ct = sctxt.Seal("", msg)
push_message = concat(hdr, enc, ct)
~~~


## Push Message Receiver Processing {#decrypt}

An user agent decrypts a push message by reversing this process.
To decapsulate the encrypted push message, `push_message`:

1. Parses `push_message`
   into `key_id`, `kem_id`, `kdf_id`, `aead_id`, `enc`, and `ct`
   (indicated using the function `parse()` in pseudocode).
   The user agent is then able to find
   the HPKE private key, `skR`,
   and pre-shared key, `psk`.

   a. If `key_id` does not identify a key matching the type of `kem_id`,
      the user agent discards the message.

   b. If `kdf_id` and `aead_id` identify a combination of KDF and AEAD
      that the user agent is unwilling to use with `skR`,
      the user agent discards the message.

2. Build `info` by concatenating the ASCII-encoded string "message/bhttp
   request", a zero byte, `key_id` as an 8-bit integer, plus `kem_id`, `kdf_id`,
   and `aead_id` as three 16-bit integers.

3. Create a receiving HPKE context, `rctxt`, by invoking `SetupPSKR()`
   ({{Section 5.1.2 of HPKE}})
   with `enc`, `skR`, `info`, `psk`,
   and a one byte pre-shared key ID containing `key_id`.

4. Decrypt `ct` by invoking the `Open()` method on `rctxt`
   ({{Section 5.2 of HPKE}}),
   with an empty associated data `aad`,
   yielding `msg` or an error on failure.
   If an error is returned, the user agent discards the message.

In pseudocode, this procedure is as follows:

~~~ pseudocode
key_id, kem_id, kdf_id, aead_id, enc, ct = parse(enc_request)
info = concat(encode_str("message/bhttp request"),
              encode(1, 0),
              encode(1, key_id),
              encode(2, kem_id),
              encode(2, kdf_id),
              encode(2, aead_id))
rctxt = SetupBaseR(enc, skR, info, psk, [key_id])
msg, error = rctxt.Open("", ct)
~~~


# Mandatory Algorithms {#algorithms}

All implementations of this specification MUST implement
the following algorithms:

* the MLKEM768-X25519 KEM (0x647a) {{Section 8.2 of !HPKE-PQ=I-D.ietf-hpke-pq}}
* the TurboSHAKE128 KDF (0x0012) {{Section 5 of !HPKE-PQ}}
* the AES-GCM AEAD (0x0001) {{Section 7.3 of !HPKE}}


# Upgrading from RFC 8291

The encryption scheme in {{?RFC8291}} identifies itself
through the use of the encrypted "aes128gcm" content coding {{!RFC8188}}.
Though it is possible to use this message encryption system
and the "aes128gcm" content coding at the same time,
this is not generally necessary.
A user agent can therefore use the absence of the encrypted content coding
to indicate the use of this scheme.

This document defines a media type
for HPKE-protected push messages; see {{iana}}.
This media type MAY be omitted if the "aes128gcm" content coding is not present.

Unlike RFC 8291, no native padding facility is provided by this encryption format;
see {{security}} for details.


# Security Considerations {#security}

A Web Push user agent relies to some degree on two values
remaining confidential to protect it from unwanted messages:

* the URL at which push messages are delivered,
  knowledge of which is necessary
  for messages to reach the user agent at all, and

* the pre-shared key that is used to authenticate the sender,
  which is the primary defense.

Knowledge of these values,
along with the other parameters in the key configuration,
allows an attacker to send any message it chooses
to the user agent.

Like the design in RFC 8291 (see {{Section 7 of ?RFC8291}}),
this mechanism cannot obscure the presence, timing, and size of messages
from the push service.
Though communication with the push service is protected by TLS,
without additional traffic analysis protection,
network observers might also be able to observe these attributes of messages.

Padding of the payload of messages can be used
to obscure the precise size of the message,
but no facility is provided in this document for padding messages.
This differs from the RFC 8291 design,
which was able to use the padding provided by the {{?RFC8188}} encoding.

This document exercises the options described in {{?RFC8192}}
for replacing the encryption scheme.
Any replacement of this encryption scheme can use those same techniques.


## Handling Denial of Service {#dos}

A user agent that receives multiple unwanted messages,
including messages that are discarded,
might be the target of a denial of service attack.
Such an attack might seek to drain batteries
by activating the device radio
or by creating messages that cannot be decrypted.

A user agent can disable the associated subscription
if they receive too many unwanted or invalid messages.


## Multi-Target Ciphertexts in RFC 8291 {#proteus}

RFC 8291 {{?RFC8192}} is vulnerable to an attack
where a malicious application can construct a single ciphertext
that will be decrypted successfully
(that is, the AEAD tag is accepted)
by multiple recipients,
each of whom can receive a different plaintext.

This format is also vulnerable to this attack.It is possible to apply the techniques from {{CDJZ}}
to achieve this outcome with only modest amounts of computation.

This attack has no practical consequence,
as it requires that the attacker have information
that would allow it to send any message
without any need to a share a ciphertext.


## Media Type Security {#sec-media}

Push messages contain arbitrary content chosen by an application server.
Though the format does not provide explicit signaling for the encapsulated media type,
applications can include arbitrary data.
How data is handled is determined by the application,
which both sends and receives the data.


# IANA Considerations {#iana}

This document registers the "application/webpush-message" content type
to identify a push message that is protected with this scheme,
as defined in {{message}}.

Type name:

: application

Subtype name:

: webpush-message

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{sec-media}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: This type identifies an encrypted web push message.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

TODO
