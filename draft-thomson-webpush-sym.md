---
title: "WebPush Encryption using Symmetric Ciphers"
category: std

docname: draft-thomson-webpush-sym-latest
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
 - perfect forward secrecy
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
  HPKE: I-D.ietf-hpke-hpke

informative:
  WEBPUSH-HPKE:
    title: WebPush Encryption using HPKE
    author:
      - name: Martin Thomson
    seriesinfo:
      Internet-Draft: draft-thomson-webpush-hpke-latest
    date: draft-thomson-webpush-hpke-date

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

This document defines how to use purely symmetric cryptography
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
that uses purely symmetric algorithms,
relying on a pre-shared symmetric key.
This relies on building a system for signaling
updates to the pre-shared key.
That system is not described in this document.

This document obsoletes RFC 8291 {{?RFC8291}}.

This document is one of a pair.
Its companion, {{WEBPUSH-HPKE}} is an alternative to this approach.
{{WEBPUSH-HPKE}} describes how to encode messages
using Hybrid Public Key Encryption (HPKE).

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
This document describes how this can be performed using purely symmetric ciphers.

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

In order for an application server to send a push message using these keys,
it requires knowledge of the PSK the user agent has chosen
and the corresponding cipher.

This information is formatted into a key configuration.

{{f-config}} shows the format of the key configuration,
using the format described in {{Section 1.3 of ?QUIC=RFC9000}}.

~~~ artwork
Key Config {
  Symmetric Algorithms (32) ...,
}

Symmetric Key {
  Key Identifier (8),
  HPKE AEAD ID (16),
  Key Length (16),
  Key (Nk * 8),
}
~~~
{: #f-config title="Configuration Format"}

The format consists of one or more Symmetric Key items,
each of which contains:

Key Identifier:

: An 8 bit value that will be used in protected messages
  to identify the user agent's PSK and KEM secret key.

HPKE AEAD ID:

: A 16 bit HPKE AEAD identifier as defined in {{Section 7.3 of HPKE}}
  or [the HPKE AEAD IANA registry](https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-aead-ids).

Key Length:

: A 16 bit integer in network byte order that encodes the length, in bytes,
  of the Key field that follows.

Key:

: A key for the identified AEAD,
  with a length determined by the
  If the encoded length of the key is not identical to the size of the key (Nk)
  in the definition of the AEAD,
  the entry MUST be discarded.


# HPKE-Encrypted Push Message Format {#message}

The format of push messages is illustrated in {{f-message}}.

~~~ artwork
HPKE-Protected Push Message {
  Key Identifier (8),
  Nonce (Nn),
  Encrypted Message Contents (..),
}
~~~
{: #f-message title="HPKE-Protected Push Message Format"}

Processes for the application server that sends messages
are included in {{encrypt}};
processes for the user agent that receives messages
are included in {{decrypt}}.


## Push Message Application Server Processing {#encrypt}

Applications encapsulate a push message, `msg`,
using values from the key configuration:

* the key identifier from the configuration, `key_id`,
  with the corresponding AEAD identified by `aead_id`, and

* the pre-shared key from the configuration, `key`,

The application then constructs an encrypted push message, `push_message`,
from the plaintext of the message, `msg`, as follows:

1. Generate a unique value for `nonce`.
   This value needs to be unique across all uses
   of the same pre-shared key.

2. Encrypt `msg` by invoking the `Seal()` method on the selected AEAD
   passing `key` and an empty associated data `aad`,
   yielding ciphertext `ct`.

3. Concatenate the values of `key_id`, `nonce`, and `ct`,
   yielding an encrypted push message `push_message`.

Ideally, senders maintain a counter and use that for nonces.
However, coordinating a counter across multiple hosts
can be challenging.
For this reason, the value of `nonce` can be drawn at random,
in which case the number of messages that can be protected
with a single key MUST be significantly less than
two to the power of half the number of bits in the `nonce` value.
Setting a limit of 2<sup>Nn/2 - margin</sup> messages,
where `margin` is at least 20,
provides a very low chance of collision.

Note that `nonce` is of fixed-length, so there is no ambiguity in parsing this
structure.

In pseudocode, this procedure is as follows:

~~~ pseudocode
aead = find_aead(aead_id)
nonce = random_bits(aead.Nn)
ct = aead.Seal(key, nonce, "", msg)
push_message = concat(key_id, nonce, ct)
~~~


## Push Message Receiver Processing {#decrypt}

An user agent decrypts a push message by reversing this process.
To decapsulate the encrypted push message, `push_message`:

1. Parses `push_message`
   into `key_id`, `nonce`, and `ct`
   (indicated using the function `parse()` in pseudocode).
   The user agent is then able to find
   the pre-shared key, `key`.

   a. If `key_id` does not identify a key known to the user agent
      the user agent discards the message.

   b. Optionally, if `nonce` matches a value that has been used with this key,
      the user agent destroys the corresponding key
      and discards the message.

2. Decrypt `ct` by invoking the `Open()` method on the AEAD
   associated with the `key`,
   passing `key`, `nonce, and an empty associated data,
   yielding `msg` or an error on failure.
   If an error is returned, the user agent discards the message.

In pseudocode, this procedure is as follows:

~~~ pseudocode
key_id, nonce, ct = parse(enc_request)
key, aead = find_key(key_id)
if not key: abort
if previously_seen(key_id, nonce):
  delete(key)
  abort
msg, error = aead.Open(key, "", nonce, ct)
if error: abort
~~~


# Mandatory Algorithms {#algorithms}

All implementations of this specification MUST implement
AES-128-GCM, identified as 0x0001 in {{Section 7.3 of HPKE}}.


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

The use of post-quantum cryptography can increase the size of messages considerably.
{{Section 4 of RFC8291}} recommends that push services support ciphertext
of 4096 bytes.
This can reduce the available space for plaintext considerably.
For example, using MLKEM768-X25519 means 1143 bytes of cryptographic overhead,
compared to the 103-byte overhead in RFC 8291.

Ideally, to allow for a smooth transition to PQ cryptography,
push services would allow an additional 1kB for ciphertext.

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


## Post-Compromise Security {#pcs}

This message encryption scheme does not provide confidentiality
of messages that are sent after a key becomes compromised.
A key compromise leads to loss of confidentiality
for all messages sent under the same key,
in the past or future.
Knowledge of the key also grants the ability to forge arbitrary new messages.


## Nonce Collisions {#collision}

Protection of two different messages with an identical nonce
leads to a key compromise in many AEAD functions.
Applications MUST ensure that nonces used with the same key are unique.

This document does not require that user agents track
which nonces have been used,
as that require significant state retention and computation.
However, where a user agent detects nonce reuse
it MUST discard the associated key.
Messages that are merely replayed MUST NOT trigger this response.
The user agent is encouraged to make all affected entities aware
of the (potential) compromise of both previous and subsequent communications.

This document does not require the use of a nonce-reuse resistant AEAD,
but one might be defined based on something like {{?AES-GCM-SIV=RFC8452}}.


## AEAD Overuse {#overuse}

Overuse of an AEAD key can give an attacker additional advantages
that might lead to loss of confidentiality
or the ability to forge messages.
The guidance in {{!AEAD-LIMITS=I-D.irtf-cfrg-aead-limits}}
MUST be followed with a target AEA advantage of 2<sup>-40</sup>,
assuming that all messages are 4096 bytes.
Application servers MUST refuse to send messages beyond the corresponding limits;
user agents MUST discard keys after receiving that many messages.


## Handling Denial of Service {#dos}

A user agent that receives multiple unwanted messages,
including messages that are discarded,
might be the target of a denial of service attack.
Such an attack might seek to drain batteries
by activating the device radio
or by creating messages that cannot be decrypted.

A user agent can disable the associated subscription
if they receive too many unwanted or invalid messages.


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

David Benjamin insisted that we attempt to use symmetric keys.
This is because introducing a scheme that provides post-compromise security,
such as the one in {{WEBPUSH-HPKE}} is somewhat more inefficient than this scheme.
