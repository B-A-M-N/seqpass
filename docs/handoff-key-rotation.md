# SeqPass sealed handoff key rotation

This procedure rotates the issuer-signing, recipient-encryption, and recipient-receipt keys without overwriting recipient trust. It uses a new destination ID for each key generation because recipient trust files are create-only and receipts are checked against the destination revision that authorized the capsule.

## Key roles

- **Issuer signing key:** SeqPass signs each capsule. The broker has the private seed; recipients receive the public key through a separately trusted channel. The broker is configured with one active issuer key ID at a time.
- **Recipient HPKE key:** the recipient decrypts capsules. Only the recipient service identity holds its private key; SeqPass stores the public key.
- **Receipt signing key:** the recipient signs completion receipts. Only the recipient service identity holds its private key; SeqPass stores the public key.

Never reuse one key for two roles. Never overwrite a private key or recipient trust registration in place. The registered `source_revision` means the operator-approved source-binding revision; it does not attest to the live generation of the resolved secret.

The current AegisKeys resolve protocol returns binding identity and credential
material but no credential-generation identifier. SeqPass therefore binds only
the approved source reference and source-binding revision into a capsule; it
does not claim that `source_revision` identifies the secret bytes' rotation
generation. A future backend generation field must be authenticated by
AegisKeys and copied into a distinct capsule field before it can support that
claim.

For the FI Gateway Unix socket, recipient trust may pin the expected gateway
service UID with `--fi-gateway-peer-uid`. Use this only when the gateway socket
is deliberately accessible to the recipient account. SeqPass still requires
the socket inode to be recipient-owned and owner-only; this pin does not relax
the socket or parent-directory checks. Arrange the service's bind path and
socket ownership explicitly in deployment configuration. The pin verifies
the peer's kernel-reported UID; it does not authenticate one executable or
prove the service process is uncompromised. Omitting the option keeps the
same-UID deployment behavior.

## Rotation procedure

1. **Record the current generation.** Save the old destination ID, destination revision, three key IDs, public-key fingerprints, current broker issuer-key ID, and all operations that are `authorized`, `dispatching`, or `uncertain`. Do not begin a new generation while the old destination has operations whose outcome still needs reconciliation.

2. **Drain the old generation.** Stop creating approvals for the old destination. Complete or reconcile issued operations. For an uncertain recipient-pull operation, use the recipient journal and the existing dispatch record; do not issue a second ticket just to make the state look complete. For a sealed capsule, retrieve only the already-issued ciphertext. Wait until every outstanding capsule has expired before retiring the old recipient decryption key.

The broker retains the exact encrypted capsule only until its operation expires
or reaches a final state. Cleanup clears the capsule BLOB and checkpoints the
SQLite WAL while preserving the dispatch digest, byte count, destination, and
handoff ID needed to validate a late signed receipt. A pending cleanup marker
causes later maintenance passes to retry a checkpoint blocked by a concurrent
reader. This policy applies to the active broker database and WAL; separately
copied database backups remain governed by the operator's backup retention.

3. **Create fresh keys under the owning identities.** On the recipient host, create a new HPKE key and receipt-signing key at new, private paths:

   ```bash
   seqpass recipient keys generate \
     --private-key /var/lib/seqpass-recipient/hpke-r2.json \
     --public-key /var/lib/seqpass-recipient/hpke-r2.pub \
     --receipt-private-key /var/lib/seqpass-recipient/receipt-r2.seed \
     --receipt-public-key /var/lib/seqpass-recipient/receipt-r2.pub
   ```

   On the broker host, create a new issuer key pair at new paths:

   ```bash
   seqpass admin handoff-issuer-keygen \
     --private-seed /var/lib/seqpass/issuer-r2.seed \
     --public-key /var/lib/seqpass/issuer-r2.pub
   ```

   Use new key IDs as well as new file paths. Transfer public keys only over the operator-controlled enrollment channel.

4. **Create a versioned destination.** Register a new destination ID, such as `opencode-primary-r2`, with the new recipient HPKE public key, receipt public key, issuer public key, and the approved application target. Keep the old destination record unchanged so receipts for its revision can still be verified.

   ```bash
   seqpass admin add-dest --name opencode-primary-r2 --type sealed-capsule \
     --handoff-mode sealed-capsule --expect-uid 3002 \
     --recipient-key-id opencode-r2 --recipient-public-key /etc/seqpass-recipient/hpke-r2.pub \
     --receipt-key-id opencode-receipt-r2 --receipt-public-key /etc/seqpass-recipient/receipt-r2.pub \
     --issuer-key-id seqpass-issuer-r2 --issuer-public-key /var/lib/seqpass/issuer-r2.pub \
     --app opencode --account openrouter --slot api_key \
     --update-method opencode-auth-import-v2 \
     --source-ref openrouter/main --source-revision 4
   ```

5. **Create recipient-local trust.** As the recipient service identity, register the new destination ID and new private-key paths. The command creates a separate trust file; it does not replace the old registration.

   ```bash
   seqpass recipient capsule register \
     --destination-id opencode-primary-r2 --destination-revision 1 \
     --recipient-key-id opencode-r2 \
     --recipient-private-key /var/lib/seqpass-recipient/hpke-r2.json \
     --receipt-key-id opencode-receipt-r2 \
     --receipt-private-key /var/lib/seqpass-recipient/receipt-r2.seed \
     --issuer-key-id seqpass-issuer-r2 \
     --issuer-public-key /etc/seqpass-recipient/issuer-r2.pub \
     --target-id opencode:openrouter:api_key --app opencode \
     --account openrouter --slot api_key --update-method opencode-auth-import-v2 \
     --source-ref openrouter/main --source-revision 4 \
     --opencode-command /home/seqpass-recipient/.opencode/bin/opencode
   ```

6. **Switch authorization and issuer configuration.** Configure the broker to use the new issuer key ID and private seed. Create a policy scoped to the new destination. Disable the old dedicated policy only after the old generation is drained; disabling a policy bumps the authorization epoch and revokes outstanding approvals. Avoid a shared wildcard policy that continues authorizing both generations.

7. **Qualify the new generation.** Use a synthetic credential first. Confirm the recipient decrypts the capsule, the registered adapter applies it, the recipient receipt verifies against the new receipt key and destination revision, and SeqPass records the expected operation outcome. Keep routing and upstream-provider verification separate from local storage acceptance.

8. **Retire old private keys only after reconciliation.** Keep the old recipient HPKE private key until all old capsules have expired. Keep the old receipt private key until every possibly-applied old operation has either produced a verified receipt or has been explicitly closed under the incident procedure. Retain the old issuer public key and destination metadata for audit and receipt verification. Never import a capsule by replacing recipient trust automatically.

## Recovery rules

- A lost issuer response is recovered by retrieving the exact stored capsule. Do not issue a new capsule with a later expiry for the same operation.
- A capsule past its expiry is not revived. Start a new authorization cycle if delivery is still required.
- A receipt for an old destination revision is verified against that unchanged old destination record. Do not edit the old destination in place to install the new keys.
- If any key is suspected compromised, stop new issuance immediately, disable the affected dedicated policy, preserve metadata and receipts, and create a new destination/key generation. Treat outstanding capsules as exposed until their original expiry; do not silently extend or reissue them.
