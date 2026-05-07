# Test vectors

The Partial MLS test vectors exercise the deterministic behavior added by this
document. They assume an implementation that already verifies the MLS test
vectors for message encoding, message protection, the key schedule, transcript
hashes, Welcome processing, and ordinary TreeKEM processing.

The goal is to test Partial MLS in pieces, grouped by the information available
to a partial client:

~~~
    Membership proofs
            |
            v
    Sender-authenticated messages       AnnotatedWelcome
            |                                  |
            v                                  v
    Partial UpdatePath --------------> AnnotatedCommit
            |                                  |
            v                                  v
                    Passive partial client
~~~

The message syntax vectors verify the TLS encoding of the new structures,
independent of semantics.

### Representation

  * Test vectors are JSON serialized.
  * Each test vector file is an array of objects in the form described here.
  * `optional<T>` is serialized as the value itself or `null` if not present.
  * MLS and Partial MLS structs are binary encoded according to the relevant
    TLS presentation syntax and represented as hex-encoded strings in JSON.
  * HPKE and Signature public keys are encoded in the formats specified for
    `HPKEPublicKey` and `SignaturePublicKey` in RFC 9420, but as raw binary
    data, without the length prefix used in the encoding of those structs.
  * HPKE and Signature private keys are encoded as binary objects in the same
    formats used by the MLS test vectors.
  * Files ending in `-spec.json` contain the MTI-ciphersuite subset included in
    the draft appendix. The corresponding non-`-spec.json` files contain the
    full vector set.

## Partial Message Syntax

Parameters:

  * Ciphersuite

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "copath_hash": /* serialized CopathHash */,
  "membership_proof": /* serialized MembershipProof */,
  "sender_authenticated_welcome":
    /* serialized SenderAuthenticatedMessage<Welcome> */,
  "sender_authenticated_group_info":
    /* serialized SenderAuthenticatedMessage<GroupInfo> */,
  "sender_authenticated_public_message":
    /* serialized SenderAuthenticatedMessage<PublicMessage> */,
  "sender_authenticated_private_message":
    /* serialized SenderAuthenticatedMessage<PrivateMessage> */,
  "annotated_welcome": /* serialized AnnotatedWelcome */,
  "annotated_commit": /* serialized AnnotatedCommit */
}
~~~

Verification:

  * Given each encoded object, the client decodes it as the named Partial MLS
    structure and re-encodes the same bytes.

## Membership Proofs

Parameters:

  * Ciphersuite
  * Tree shape
  * Proven leaf indices

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "tree_hash": /* hex-encoded binary data */,
  "proofs": [
    /* serialized MembershipProof */,
    ...
  ]
}
~~~

Verification:

  * Given `membership_proof` and `tree_hash`, the client reconstructs the same
    tree hash.

If multiple proofs are present, the client also verifies whether each proof
references the same tree as the previous proof.

## Sender-Authenticated Messages

Parameters:

  * Ciphersuite
  * Message type

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "message_type": /* string */,
  "sender_authenticated_message":
    /* serialized SenderAuthenticatedMessage<PublicMessage> */
}
~~~

Verification:

  * Given `sender_authenticated_message` and the current partial client state,
    the client verifies the sender proof and authenticates the message with the
    signature key from the proven leaf.

## Annotated Welcome

Parameters:

  * Ciphersuite
  * Joiner key package
  * Welcome sender leaf index
  * Joiner leaf index
  * External PSKs, if any

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "key_package": /* serialized MLSMessage(KeyPackage) */,
  "signature_priv": /* signature private key */,
  "encryption_priv": /* HPKE private key for the joiner leaf */,
  "init_priv": /* HPKE private key for the KeyPackage init key */,
  "external_psks": [
    {
      "psk_id": /* hex-encoded binary data */,
      "psk": /* hex-encoded binary data */
    },
    ...
  ],

  "annotated_welcome": /* serialized AnnotatedWelcome */,

  /* Expected outputs */
  "joiner_leaf_index": /* uint32 */,
  "epoch_authenticator": /* hex-encoded binary data */
}
~~~

Verification:

  * Given `annotated_welcome`, the joiner's private keys, and any
    `external_psks`, the client joins the group as a partial client at index
    `joiner_leaf_index` and produces an epoch with the given
    `epoch_authenticator`.

## Partial Client UpdatePath Handling

Parameters:

  * Ciphersuite
  * Sender leaf index
  * Receiver leaf index
  * Receiver path state

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "update_path": /* serialized UpdatePath */,
  "tree_hash_after": /* hex-encoded binary data */,
  "resolution_index": /* uint32 */,
  "sender_membership_proof_after": /* serialized MembershipProof */,
  "receiver_membership_proof_after": /* serialized MembershipProof */,
  "receiver_path_state": /* retained direct-path private state */,

  /* Expected outputs */
  "commit_secret": /* hex-encoded binary data */
}
~~~

Verification:

  * Given `update_path`, `tree_hash_after`, `resolution_index`, the sender's
    post-commit membership proof, the receiver's post-commit membership proof,
    and the receiver's retained direct-path private keys, the client selects the
    correct encrypted path secret, decrypts it, derives the remaining path
    secrets, and produces the expected `commit_secret`.

## Annotated Commit

Parameters:

  * Ciphersuite
  * Commit sender type
  * Commit wire format
  * Proposal mix
  * Receiver leaf index

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "state_before": /* partial client state */,
  "proposals": [
    /* serialized MLSMessage(PublicMessage or PrivateMessage) */
  ],
  "annotated_commit": /* serialized AnnotatedCommit */,

  /* Expected outputs */
  "tree_hash_after": /* hex-encoded binary data */,
  "commit_secret": /* hex-encoded binary data */,
  "epoch_authenticator_after": /* hex-encoded binary data */,
  "state_after": /* partial client state */
}
~~~

Verification:

  * Given an `AnnotatedCommit` for a member commit, the client verifies the
    pre-commit sender proof and authenticates the commit with the signature key
    from the proven sender leaf.
  * Given an `AnnotatedCommit` for a `new_member_commit`, the client rejects a
    sender proof and authenticates the commit using the MLS `new_member_commit`
    rules.
  * Given an `AnnotatedCommit` and `state_before`, the client advances to the
    expected next epoch state without constructing the full ratchet tree.
  * Given a commit containing non-tree-changing proposals, the client applies
    the proposal effects to its partial state.

The client also verifies the post-commit sender and receiver proofs against
`tree_hash_after`. If the embedded commit contains an `UpdatePath`, the client
uses the Partial UpdatePath vector behavior to derive `commit_secret`.

## Passive Partial Client

Parameters:

  * Ciphersuite
  * Sequence of group operations

Format:

~~~text
{
  "cipher_suite": /* uint16 */,

  "annotated_welcome": /* serialized AnnotatedWelcome */,
  "key_package": /* serialized MLSMessage(KeyPackage) */,
  "signature_priv": /* signature private key */,
  "encryption_priv": /* HPKE private key for the leaf */,
  "init_priv": /* HPKE private key for the KeyPackage init key */,
  "external_psks": [
    {
      "psk_id": /* hex-encoded binary data */,
      "psk": /* hex-encoded binary data */
    },
    ...
  ],
  "initial_epoch_authenticator": /* hex-encoded binary data */,

  "epochs": [
    {
      "proposals": [
        /* serialized MLSMessage(PublicMessage or PrivateMessage) */
      ],
      "annotated_commit": /* serialized AnnotatedCommit */,
      "application_messages": [
        /* serialized SenderAuthenticatedMessage<PrivateMessage> */
      ],
      "epoch_authenticator": /* hex-encoded binary data */
    },
    ...
  ]
}
~~~

Verification:

  * Given a sequence of `AnnotatedWelcome`, `AnnotatedCommit`, and
    sender-authenticated application messages, the client follows the group
    across epochs as a passive partial client.
