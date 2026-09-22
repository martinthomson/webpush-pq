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

  PUSH-API:
    title: Push API
    author:
      - name: Marcos Caçeres
      - name: Kagami Rosylight
    date: 2025-12-01
    seriesinfo:
      W3C: Working Draft

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

This process uses a ratcheting key derivation process
to protect the confidentiality of old messages
in the event of key compromise (namely, forward secrecy or FS).
Critically, it does not protect messages that might be sent after
any such compromise (that is, post-compromise security or PCS).

This document obsoletes RFC 8291 {{?RFC8291}}.

This document is one of a pair.
Its companion,  is an alternative to this approach.
{{WEBPUSH-HPKE}} describes how to encode messages
using Hybrid Public Key Encryption (HPKE).


## Comparison with Predecessor

The security properties of this mechanism differ
from the system that it replaces {{?RFC8291}}.

RFC 8291 encryption had application servers generate ephemeral asymmetric keys
for every message.
That guaranteed that only a compromise of the secret key held by a client --
or a break in the underlying cryptography --
would compromise future messages.

The need to safeguard against the potential creation of a CRQC
leads to one of two conclusions:
upgrade the cryptographic algorithms used
or switch to purely symmetric ciphers.
{{WEBPUSH-HPKE}} explores the former option,
which comes at a very high cost in added bytes.

Post-quantum key encapsulation would add overheads to every message
that exceed typical message sizes,
which are exchanged over a medium that is highly constrained.

Though push messaging is highly sensitive to added bytes,
it is less needful of protection than other protocols
as it uses TLS to protect every communication step.
Push message encryption provides an additional layer of end-to-end protection.

Using purely symmetric encryption creates new vulnerabilities over RFC 8291.
An RFC 8291 application server did not hold secrets;
every message they created was encrypted with an ephemeral key.
This symmetric design means that a compromise of an application server
will result in both:

* any message sent by the application server being readable to an attacker

* the attacker being able to forge messages that the user agent will accept
  as being from the compromised application server

This risk can be managed by requesting fresh secrets from the user agent
more often.



## Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terminology introduced in {{?WEBPUSH=RFC8030}}.


# Encryption in Web Push

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


## Ratchet Design

The push message encryption design in this document
uses a very simple ratchet.

Each message that is sent by an application server
takes the shared secret
and uses a key-derivation function (KDF)
to produce three new values:

1. A per-message encryption key
2. A per-message nonce
3. A fresh secret for the next message

The key and nonce are used with
an Authenticated Encryption with Associated Data (AEAD) function {{?AEAD=RFC5116}}
to encipher the message.

The sequence number is then incremented by one
and the old secret destroyed.

This process is illustrated in {{f-ratchet}}.

~~~ aasvg
+------------+         .-----.         +------------+
|  secret n  +--------+ KDF s +------->| secret n+1 +--->...
+---+---+----+         `-----'         +---+---+----+
    |   |                                  |   |
    |   |      .-----.                     |   |
    |    `----+ KDF n +--------------.     |  ...
    |          `-----'                |
    |          .-----.                |
     `--------+ KDF k +----------.    |
               `-----'        key |   | nonce
                                  v   v
                                +-------.
+------------+                  |        \
| message    +----------------->|  AEAD   +--------.
+------------+                  |        /          |
                                +-------'           |
                                                    v
                               +-------+--------+---------------+
                               | keyid |   n    | ciphertext    |
                               +-------+--------+---------------+
~~~
{: #f-ratchet title="Message Encryption Ratchet"}


## Cryptographic Primitives and Agility {#crypto}

This document uses a fixed profile of cryptographic primitives.

This document uses HMAC-based Extract-and-Expand Key Derivation Function (HKDF) {{!HKDF=RFC5869}}
with SHA-256 {{!SHA=DOI.10.6028/NIST.FIPS.180-4}} as the underlying hash function.
It also uses the 128-bit variant of AES in the GCM mode (AEAD_AES_128_GCM)
as defined in {{Section 5.1 of !AEAD=RFC5116}}.

Cryptographic agility is addressed by defining a replacement scheme;
see {{upgrade}}.
Any replacement push message encryption scheme
defines new parameters in the Web API {{PUSH-API}}.
This is the same process that allows this scheme to be deployed
as a replacement for the scheme in RFC 8291.


## This Document

This document describes the push message encryption design
in three parts:

1. A user agent shared secret configuration,
   where the user agent provides the information
   necessary to construct a message it will accept.
   This is provided by the user agent to the application
   during the establishment of a Web Push subscription.
   This depends only on the format of the shared secret,
   which are provided in {{config}}.

2. The process used to encrypt push messages.
   This includes the format ({{message}})
   and the process for producing that format ({{encrypt}}).

3. The process used to decrypt push messages ({{decrypt}}).
   This is somewhat more involved than encryption
   as it has to account for the potential for reordered and dropped messages.


# User Agent Configuration {#config}

In order for an application server to send a push message using these keys,
it requires knowledge of the shared secret the user agent has chosen
and the corresponding cipher.

This information is formatted into a 36 byte shared secret format.
{{f-secret}} shows the structure of this information,
using the format described in {{Section 1.3 of ?QUIC=RFC9000}}.

~~~ artwork
Shared Secret {
  Key Identifier (8),
  Sequence Number (24),
  Secret (256),
}
~~~
{: #f-secret title="Shared Secret Format"}

This comprises the following items:

Key Identifier:

: An 8 bit value that will be used in protected messages
  to identify the shared state at the user agent's.

Sequence Number:

: A 24 bit integer in network byte order.

Secret:

: A 256 bit shared secret.


# Encrypted Push Message Format {#message}

The format of push messages is illustrated in {{f-message}}.

~~~ artwork
Encrypted Push Message {
  Key Identifier (8),
  Sequence Number (24),
  Encrypted Message Contents (..),
}
~~~
{: #f-message title="Encrypted Push Message Format"}

Processes for the application server that sends messages
are included in {{encrypt}};
processes for the user agent that receives messages
are included in {{decrypt}}.


# Push Message Encryption {#encrypt}

Applications encapsulate a push message, `msg`,
using values from the key configuration:

* the key identifier from the configuration, `key_id`,

* the sequence number, `seq`, and

* the shared secret from the configuration, `secret`,

The application then constructs an encrypted push message, `push_message`,
from the plaintext of the message, `msg`, as follows:

1. Invoke HKDF-Expand (see {{Section 2.3 of !HKDF=RFC5869}})
   with SHA-256 {{!SHA}} as the underlying hash function
   three times,
   each time with `secret` as the `PRK` input,
   as follows:

   {: type="a"}
   1. An `info` input of the ASCII-encoded ({{!ASCII=RFC20}}) string "secret"
      (that is, six bytes with no length prefix or null termination)
      and a length (`L`) input of 32 bytes;
      the output (`OKM`) is assigned to a variable `next_secret`.

   2. An `info` input of the ASCII-encoded string "key"
      and a length (`L`) input of 16 bytes
      (corresponding to K_LEN for AEAD_AES_128_GCM);
      the output (`OKM`) is assigned to a variable `key`.

   3. An `info` input of the ASCII-encoded string "nonce"
      and a length (`L`) input of 12 bytes
      (corresponding to `N_MIN` for AEAD_AES_128_GCM);
      the output (`OKM`) is assigned to a variable `nonce`.

2. Invoke the encryption method (see {{Section 2.1 of AEAD}})
   of the AEAD_AES_128_GCM AEAD (see {{Section 5.1 of AEAD}})
   passing `msg` as P, `key` as K, `nonce` as N, and an empty associated data as A,
   yielding ciphertext `ct` as C.

3. Concatenate the values of `key_id`, `seq`, and `ct`,
   yielding an encrypted push message `push_message`.

4. Overwrite the value of `secret` with the value of `next_secret`
   and the value of `seq` with the value `(seq + 1) mod (1 << 24)`
   (that is, the next 24-bit sequence number, modulo 2<sup>24</sup>).

A pseudocode version of this procedure is shown in {{f-encrypt}}.

~~~ pseudocode
next_secret = hkdf.expand(secret, "secret", 32)
key = hkdf.expand(secret, "key", 16)
nonce = hkdf.expand(secret, "nonce", 12)
ct = aes128gcm.seal(key, nonce, "", msg)
push_message = concat(key_id, seq, ct)
secret = next_secret
seq = (seq + 1) & 0xff_ffff
~~~
{: #f-encrypt title="Encryption pseudocode"}


# Push Message Receiver Processing {#decrypt}

An user agent decrypts a push message by reversing this process.
However, a user agent needs additional processing
to deal with the potential for gaps in the sequence of messages it receives.

A user agent decrypts messages from multiple applications servers.
To that end, it needs to store multiple secrets,
which are indexed by application server identity and key identifier.
This is described in {{ua-state}}.

Importantly user agents need to deal with messages that arrive out of order
relative to when they were sent
and gaps in the sequence of messages.
User agents therefore need to maintain access
to the secrets for the messages it could receive
either by generating and storing multiple secrets
or by retaining an older secret and computing secrets as needed.

To avoid receiving the same message twice,
a user agent therefore needs to track which messages it has already received.
This is covered in more detail in {{ua-dup}}.

The algorithm in {{decrypt-algo}} is an example of a possible decryption routine.
Implementations are free to use other implementations
provided that they reject duplicate messages
and can accept some number of messages out of order.


## User Agent State {#ua-state}

The protocol the user agent shares with the push service
identifies the application server that any given message is from
(carried in the `app_server` variable).
The key identifier, `key_id`, is carried in the message.

The user agent can recover the necessary state
from the application server identity and key identifier:
the shared secret, `secret`,
the sequence number, `seq`,
and the duplicate message record, `dup_record`.

After successfully decrypting a message,
the user agent updates the values it stores.
This ensures that it is able to
receive messages with higher sequence numbers
and detect duplication messages.


## User Agent Duplicate Detection {#ua-dup}

Each sequence number and shared secret produce the same AEAD key and nonce.
Using the same key and nonce for different messages
with AEAD_AES_128_GCM enables recovery of the key
used to protect those messages.
Due to the use of a KDF, this does not compromise other messages,
but it is a serious risk to confidentiality and integrity.

User agents therefore MUST maintain a record of which sequence numbers
they have already received and successfully decrypted.
If a duplicate sequence number is detected
the user agent MUST destroy all secrets it holds for that session.
Destroying secrets means that all future messages
from that application server
will be discarded.

This record of used sequence numbers does not need to be unbounded in size;
it can be limited to a finite window.
Any message with a sequence number outside of that window
MUST be discarded without attempting to decrypt it.

To avoid false positives on duplicate detection
the push service needs to ensure that it cannot deliver the same message
more than once.
Any duplicate message that arrives is then the result of an application server bug
or an attack (such as a compromise of the secret).
The push service MUST NOT parse and validate the sequence number
from messages to remove duplicates as this could hide bugs and attacks.


## Simple Decryption Algorithm {#decrypt-algo}

The algorithm in this section is a simplified version of the logic
that a user agent might use to decrypt incoming push messages.
{{decrypt-notes}} contains a discussion of its limitations
and some additional considerations for user agent implementations.

This algorithm uses a configured value for
the number of messages that can be accepted out of order called `window`.
The duplicate message record is an array of booleans (a bitfield)
of size `window`.
This record initialized to contain all false values.

This algorithm ensures that push messages are either
passed to the AEAD for an attempt at decryption and subsequently tracked,
or they are rejected based on sequence number alone
as required by {{ua-dup}}.

To decapsulate the encrypted push message, `push_message`:

1. Parse `push_message`
   into `key_id`, `mseq`, and `ct`
   (indicated using the function `parse()` in pseudocode below).

2. The user agent is then able to use `key_id` and `app_server` to find
   the corresponding secret, `secret`, sequence number, `seq`,
   and duplicate message record, `dup_record`
   (indicated with the function `lookup()` in the pseudocode below).
   If `key_id` does not identify a secret known to the user agent,
   the user agent discards the message and aborts.

3. Assign a variable `offset` to `mseq` minus `seq`, modulo 2<sup>24</sup>.
   If `offset` is greater than or equal to `window`,
   the user agent discards the message and aborts.
   (Note that the modulo operation guarantees that offset will be very large
   if `mseq` is less than `seq`,
   which means that old messages are discarded.)

4. If `dup_record` at an offset of `offset` is true,
   the user agent destroys the state associated with
   this application server and key identifier,
   purging them from any store the user agent maintains,
   and then discards the message and aborts.

5. Assign a variable `msecret` to `secret`,
   then invoke HKDF on that value `offset` times.
   Each time HKDF-Expand (see {{Section 2.3 of !HKDF=RFC5869}}) is invoked
   with `msecret` as the `PRK` input,
   an `info` of "secret", and a length (`L`) of 32,
   assigning the output (`OKM`) back to `msecret`.

6. Then, invoke HKDF-Expand twice more,
   each time with `msecret` as the `PRK` input,
   as follows:

   {: type="a"}
   1. An `info` input of the ASCII-encoded string "key"
      and a length (`L`) input of 16 bytes
      (corresponding to K_LEN for AEAD_AES_128_GCM);
      the output (`OKM`) is assigned to a variable `key`.

   1. An `info` input of the ASCII-encoded string "nonce"
      and a length (`L`) input of 12 bytes
      (corresponding to `N_MIN` for AEAD_AES_128_GCM);
      the output (`OKM`) is assigned to a variable `nonce`.

7. Invoke the decryption method (see {{Section 2.2 of AEAD}})
   of the AEAD_AES_128_GCM AEAD (see {{Section 5.1 of AEAD}})
   passing `ct` as C, `key` as K, `nonce` as N, and an empty associated data as A,
   yielding either `msg` as P or an error (FAIL).
   If an error is returned,
   the user agent discards the message and aborts.

8. Set the value at an offset of `offset` in `dup_record` to true.

9. Assign a variable, `advance` to the greater of the following two values:

   {: type="a"}
   1. The number of contiguous true values from the start of `dup_record`.

   1. The value of `offset` less half of `window`
      (rounded in any direction, if necessary).

10. Drop the `advance` items from the start of `dup_record`,
    and add `advance` false values to the end.

11. Invoke HKDF `advance` times, as in step 5,
    but with `secret` in place of `msecret`.

12. Add `advance` to `seq`.

13. Return `msg` as the plaintext of the push message.

A pseudocode version of this procedure is shown in {{f-decrypt}}.

~~~ pseudocode
# Parse and validate
key_id, mseq, ct = parse(enc_request)
secret, seq, dup_record = lookup(app_server, key_id)
if not secret: abort
offset = (mseq + 0x100_0000 - seq) & 0xff_ffff
if offset >= window: abort
if dup_record[offset] == true:
  destroy_state(app_server, key_id)
  abort

# Get secret
msecret = secret
for i in 0..offset:
  msecret = hkdf.expand(msecret, "secret", 32)

# Decrypt
key = hkdf.expand(msecret, "key", 16)
nonce = hkdf.expand(msecret, "nonce", 12)
msg, error = aes128gcm.open(key, "", nonce, ct)
if error: abort

# Update state
dup_record[offset] = true
advance = max(
  dup_record.count_true_from_start(),
  offset - (window / 2)
)
dup_record = dup_record[advance..] + [false] * advance
for i in 0..advance:
  secret = hkdf.expand(secret, "secret", 32)
seq = seq + advance

return msg
~~~
{: #f-decrypt title="Sample decryption pseudocode"}

An important property of this algorithm is that
it does not alter user agent state unless decryption is successful.
All cases where the process aborts occur before state is modified.
Once successful, state is always updated;
in particular, the duplicate message record is updated immediately.


## Implementation Notes {#decrypt-notes}

The algorithm in {{decrypt-algo}} has some obvious inefficiencies.
This is deliberate, as the goal is to describe an interoperable routine,
not describe a performant one.

In particular, an implementation can retain the secrets it computes,
rather than recompute them each time.
Otherwise, a malicious sender could use sequence number gaps
to have the user agent waste effort.

The potential for wasted effort also motivates having as small a value for `window`
as typical usage permits.
However, too small a value will result in all messages being discarded.
Implementations will therefore need to learn what value is safe to deploy.

Aside from updates to the duplicate message record,
the final steps of the exemplary algorithm,
which update the state held by the user agent,
can be deferred and run less often.
Push messages can arrive in batches,
so running those steps at the end of handling a batch
rather than after every decryption
could be more efficient.

Concurrent decryption for the same application server and key identifier
cannot occur between steps 4 and 8 of the above algorithm, inclusive.
Otherwise, concurrency might cause duplicate push messages to be accepted.

Alternative algorithms are also possible.
The approach here tracks a window
that is roughly centered on the last sequence number that has been received
if there are gaps in the sequence number space.

The algorithm in {{decrypt-algo}} also does not consider time.
An implementation could choose to limit the time that secrets are retained
after a message with a higher sequence number has been received.


# Rekeying {#rekey}

A user agent MUST supply fresh secrets to an application server
on request.

Propagating secrets to application server instances can take time,
during which messages could be protected with older secrets.
For this reason, user agents MUST retain old secrets
until newer secrets are  used.
That is, a message is successfully decrypting using a newer secret.

Once a newer secret is used,
a user agent MUST destroy old secrets after a configured period.
This document does not specify how long to retain secrets,
but any period needs to account for typical message delivery delays
that might lead to reordering
and the degree to which message loss can be tolerated.
Longer periods are more tolerant,
but carry greater risk
if the old secret has been or will be compromised
before it is destroyed.

This ties removal of old secrets to the use of a replacement
rather than a request.
Use of the secret proves that the application successfully received the updated secret,
which avoids the destruction of functioning secrets
when an application fails to save newer secrets.

Until newer secrets are used,
the user agent MAY offer the same newer secrets to applications
when secrets requested,
which can reduce the amount of state they need to retain.


# Upgrading from RFC 8291 {#upgrade}

The encryption scheme in {{?RFC8291}} identifies itself
through the use of the encrypted "aes128gcm" content coding {{!RFC8188}}.
An application MUST NOT use this message encryption scheme
and the "aes128gcm" content coding at the same time,
even though that is theoretically possible.

A user agent can therefore use the absence of the encrypted content coding
to indicate the use of this scheme.

This document defines a media type
for push messages protected with this scheme; see {{iana}}.
This allows this message type to be positively identified
and to distinguish this encryption scheme from any future scheme.

{{Section 4 of RFC8291}} recommends that push services support ciphertext
of 4096 bytes.
This capacity includes cryptographic overheads,
which in RFC 8291 were 103 bytes.
The use of this symmetric encryption scheme reduces those overheads to 20 bytes:
4 for the header and 16 for the AEAD tag.

No provision is made for padding in this scheme.
Padding of plaintext is therefore necessary
to provide resistance against traffic analysis;
see {{security}} for details.


# Security Considerations {#security}

A user agent relies to some degree on two values
remaining confidential to protect it from unwanted messages:

* the URL at which push messages are delivered,
  knowledge of which is necessary
  for messages to reach the user agent at all, and

* the secrets that are used to authenticate the sender,
  which is the primary defense.

Knowledge of these values
allows an attacker to send any message it chooses
to the user agent.

This document exercises the options described in {{?RFC8192}}
for replacing the encryption scheme.
Any replacement of this encryption scheme can use those same techniques.


## Traffic Analysis {#traffic-analysis}

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


## Key Compromise Security {#compromise}

This message encryption scheme does not provide confidentiality
of messages that are sent after a key becomes compromised.
A key compromise leads to loss of confidentiality
for all messages sent under the same key,
in the past or future.
Knowledge of the key also grants the ability to forge arbitrary new messages.

Forward secrecy is provided with respect to compromise of application servers,
but the need to handle gaps and reordering at a user agent
means that there is only limited forward secrecy.
The simple algorithm in {{decrypt-algo}} provides forward secrecy
when messages arrive in order.
However, when there is a gap in the arriving sequence of messages,
the secrets for half of the configured window are retained.
{{decrypt-notes}} describes how user agent implementation could use a timer
to supplement this safeguard.

The best way to manage these risks is more frequent key rotation.
Whether it is possible to reliably rotate keys
will determine whether this design is feasiable
relative to one that uses a PQ KEM, like {{WEBPUSH-HPKE}}.
See {{rekey}} for details.


## Key and Nonce Collisions {#collision}

Protection of two different messages with an identical nonce
leads to a key compromise in many AEAD functions.
Application servers MUST ensure that each sequence number is used at most once.

User agents MUST track which nonces have been used
for any sequence numbers that they might accept.
If a user agent detects nonce reuse
it MUST discard the corresponding state
for that application server and key identifier.
This adds a requirement on the protocols used to deliver push messages
such that they provide duplicate detection and removal.

The probably that two messages use the same key and nonce
is negligible.
The two values are 224 bits when combined,
which produce a collision with at most 2<sup>n-112</sup> probability
in any sample of 2<sup>n</sup> messages.


## Secret and Key Usage {#key-usage}

The lack of post-compromise security in this design
means that using the same sequence of shared secrets
for an extended period of time increases the impact of a compromise.
All push messages from the point of compromise onward are compromised,
giving the attacker the ability to read, modify, or forge every message.

An application server SHOULD request fresh secrets as often as they are able;
see {{rekey}}.

Overuse of an AEAD key can give an attacker additional advantages
that might lead to loss of confidentiality
or the ability to forge messages.
The guidance in {{?AEAD-LIMITS=I-D.irtf-cfrg-aead-limits}}
does not apply as each secret is used for a single, small message.
Any requirement to renew secrets is therefore driven
by the need to manage the risk of compromise.


## Handling Denial of Service {#dos}

A user agent that receives multiple unwanted messages,
including messages that are discarded,
might be the target of a denial of service attack.
Such an attack might seek to drain batteries
by activating the device radio
or by creating messages that cannot be decrypted.

This design also creates additional load from push messages
with sequence numbers that are large
relative to the window that the window that the user agent will accept.
Such messages do not need to be decryptable to cause the user agent to waste effort.
A user agent can track any abnormal effort induced from each application
and act to protect itself.

If repeated abuse is detected,
options for protection include
limiting the rate of messages that are accepted from an application server
or destroying push subscriptions.


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

: push messaging applications;
  this identifies an encrypted web push message

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

{{{David Benjamin}}} and {{{Sebastian Poreba}}} suggested
that symmetric keys might be preferable
to an asymmetric PQ approach (such as {{WEBPUSH-HPKE}})
due to the significant overheads of the PQ KEM.
Both {{{David Benjamin}}} and {{{Dennis Jackson}}} independently
suggested variations on a racheting design.
