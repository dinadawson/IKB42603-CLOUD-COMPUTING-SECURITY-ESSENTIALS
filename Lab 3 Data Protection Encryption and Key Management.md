# Lab 3: Data Protection — Encryption & Key Management

**Course:** IKB42603 Cloud Computing Security Essentials
**Name:** _(fill in your full name as printed in Lab 2)_
**Lecturer:** _(confirm — Lab 2 used "MADAM ADNI"; lab manual header shows "Prof. Dr. Shahrulniza Musa")_
**Section:** B03, Group S
**Date:** _(submission date)_

## Objectives

This lab demonstrates data protection across four security dimensions:

1. **Encryption fundamentals** — symmetric (AES) and asymmetric (RSA) cryptography, and digital signatures.
2. **Encryption in transit** — TLS with a self-signed certificate.
3. **Cloud key management** — a KMS master key and envelope encryption.
4. **Cryptographic erasure** — provable, unrecoverable deletion via key destruction, plus tamper-evidence via hashing.

**Environment note:** This lab was completed on macOS (zsh), differing from the Linux/Git Bash environment used in earlier labs. Two environment-specific issues were encountered and resolved, documented under Task 3 and Task 5 below.

## Task 1 — Symmetric Encryption (AES, Data at Rest)

### Procedure
```bash
echo "Patient: Ahmad, Diagnosis: confidential" > record.txt
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc
cat record.enc
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo MATCH
```

<img width="904" height="292" alt="Pasted Graphic" src="https://github.com/user-attachments/assets/d0f0a4a3-a98a-4df7-ace5-a2faba61d79e" />



**Observed result:** `record.enc` was unreadable ciphertext; decryption using the same passphrase reproduced the original file exactly, confirmed by `MATCH`.

**Security interpretation:** AES-256-CBC with PBKDF2 key derivation uses a single shared key for both encryption and decryption. This is fast and efficient, but the entire security of the scheme depends on that one key never being exposed in transit or storage — the **key-distribution problem**. In a cloud setting, this matters because any party who needs to decrypt the data must be given the same key, and every additional copy of that key is another point of potential compromise.

## Task 2 — Asymmetric Encryption & Digital Signatures

### Procedure
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

<img width="831" height="331" alt="einasawss" src="https://github.com/user-attachments/assets/9fa88797-72e7-47b3-88fb-2ab92c985229" />


**Observed result:** Data encrypted with the public key was successfully decrypted with the private key; the signature verification returned `Verified OK`.

**Security interpretation:** Asymmetric cryptography uses two mathematically linked keys instead of one. Encryption uses the **public** key (which can be freely distributed), while only the matching **private** key can decrypt — solving the key-distribution problem that symmetric encryption has. Signing reverses these roles: the sender signs with their private key, and anyone can verify authenticity and integrity using the corresponding public key. This asymmetry (encrypt-with-public / sign-with-private) is the basis of PKI and TLS. The trade-off is speed — RSA operations are computationally heavier than AES, which is why in practice systems combine both (see Task 5, envelope encryption).

## Task 3 — Encryption in Transit (TLS)

### Procedure
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7 -nodes -subj "/CN=localhost"
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
  -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
  -v $(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf \
  nginx
curl -k https://localhost:8443/record.txt
```

Where `nginx.conf` was:
```nginx
server {
    listen 443 ssl;
    server_name localhost;
    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;
    location / {
        root /usr/share/nginx/html;
    }
}
```

<img width="495" height="32" alt="dinadawson@mac-dee Lab3 curl -k httpslocalhost8443record txt" src="https://github.com/user-attachments/assets/454617f6-ca16-4013-829f-8556070f4f07" />


**Observed result:** `curl -k https://localhost:8443/record.txt` returned the plaintext content of `record.txt` over an HTTPS connection secured by the self-signed certificate.

**Security interpretation:** TLS wraps the data in an encrypted channel end-to-end, so an on-path attacker capturing traffic sees only ciphertext rather than the plaintext record. This is distinct from Task 1's at-rest encryption — TLS protects data specifically while it is moving between two endpoints.

**macOS-specific issue and fix:** The default `nginx` image only exposes port 443 without an SSL configuration — a plain `docker run` with the certificate mounted was not sufficient, and the first attempt returned `curl: (35) Recv failure: Connection reset by peer`. This was resolved by supplying an explicit `nginx.conf` (above) that binds `listen 443 ssl` to the mounted certificate and key, mounted into `/etc/nginx/conf.d/default.conf`. A second, unrelated environment issue was a stale/zombie Docker Desktop process from a previous session blocking the daemon from restarting; this was cleared with `pkill -9 -f "com.docker"` before Docker Desktop would launch again.

## Session B — Cloud Key Management (LocalStack KMS)

LocalStack was run pinned to version `3.0` (newer versions require a paid auth token):
```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0
curl http://localhost:4566/_localstack/health
EP='--endpoint-url=http://localhost:4566'
```

## Task 4 — KMS Master Key

### Procedure
```bash
aws $EP kms create-key --description "CCSE tenant-A master key"
KEY_A=ae39f76c-5cf4-45cf-b48a-b96f2c40017f
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" --query CiphertextBlob --output text
```

[secretetcess-ley. test.tiff](https://github.com/user-attachments/files/32107817/secretetcess-ley.test.tiff)


**Observed result:** A customer master key (CMK) was created with `KeyId: ae39f76c-5cf4-45cf-b48a-b96f2c40017f`, and a small plaintext value was successfully encrypted directly by KMS.

**Security interpretation:** A KMS master key acts as the root of trust for all encryption operations under it — the cloud provider (or LocalStack, simulating one) manages the key's lifecycle and never exposes the raw key material to the caller.

## Task 5 — Envelope Encryption

### Procedure
```bash
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text
# Column 1 saved as datakey.b64 (plaintext), column 2 as datakey.enc (wrapped)
base64 -d -i datakey.b64 -o datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin
rm datakey.bin datakey.b64
```

<img width="802" height="182" alt="Screenshot 2026-09-09 at 3 00 18 AM" src="https://github.com/user-attachments/assets/70fc104a-def2-40dd-9e57-3fd20157e14c" />


**Observed result:** A one-time AES-256 data key was generated by KMS in two forms (plaintext and KMS-wrapped). The plaintext form was used locally to encrypt `record.txt`, then immediately deleted, leaving only the wrapped `datakey.enc` and the encrypted `record.env.enc` on disk.

**Security interpretation:** Encrypting large data directly with a master key is inefficient and increases exposure of that key. Envelope encryption instead uses a disposable data key for the bulk encryption, and only the small data key itself needs to be protected by the master key. Since the plaintext data key never touches persistent storage for longer than necessary, the master key — the only long-lived secret — is the sole component that needs hardware-grade protection (e.g. an HSM in production KMS).

**macOS-specific issue and fix:** The manual's `base64 -d datakey.b64 > datakey.bin` failed on macOS with `base64: invalid argument`, because macOS ships the BSD `base64` utility, which uses `-i`/`-o` flags rather than GNU `base64`'s stdin/stdout redirection syntax. The command was adapted to `base64 -d -i datakey.b64 -o datakey.bin`.

## Task 6 — Per-Tenant Keys & Cryptographic Erasure

### Procedure
```bash
aws $EP kms create-key --description "CCSE tenant-B master key"
KEY_B=4d91cb4e-7c38-4897-828e-ae0fed2b6bc2
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

<img width="814" height="339" alt="LIs3 X KEY 8-40910046-7636-4897-8286-260168204842" src="https://github.com/user-attachments/assets/d2c482da-5fa2-4bb5-a09e-2ff8c769b1f7" />


**Observed result:** Tenant A's key transitioned to `PendingDeletion` state. A subsequent attempt to unwrap tenant A's data key (`datakey.enc`) failed with `NotFoundException: Invalid keyId`.

**Security interpretation:** Once a tenant's master key is scheduled for deletion (or disabled), every ciphertext wrapped by that key — including data keys from envelope encryption — becomes permanently unreadable, even though the encrypted bytes still physically exist on disk. This is **cryptographic erasure**: instead of needing to locate and overwrite every physical copy of the data (which is often impossible in the cloud due to replication, snapshots, and wear-levelled storage), destroying the single key that protects it renders all copies computationally unrecoverable. Per-tenant keys (`KEY_A`, `KEY_B`) ensure this deletion is scoped — deleting tenant A's key has no effect on tenant B's data.

**Note:** LocalStack's `schedule-key-deletion` already transitions the key to a non-usable `PendingDeletion` state, so a subsequent `disable-key` call correctly fails with `KMSInvalidStateException` (the key is already locked). The failed `decrypt` call is the direct evidence that erasure was achieved.

## Task 7 — Integrity & Tamper-Evidence

### Procedure
```bash
shasum -a 256 record.txt
cp record.txt tampered.txt
echo "x" >> tampered.txt
shasum -a 256 record.txt tampered.txt

PREV=0
for line in "login ok" "file read" "export data"; do
  PREV=$(echo -n "$PREV$line" | shasum -a 256 | cut -d' ' -f1)
  echo "$line | $PREV"
done
```

[dinadawson@mac-dee Lab3  shasum -a 256 record. txi.tiff](https://github.com/user-attachments/files/32107892/dinadawson%40mac-dee.Lab3.shasum.-a.256.record.txi.tiff)



**Observed result:** `record.txt` and `tampered.txt` produced completely different SHA-256 hashes despite differing by a single appended character. The hash chain produced three entries, each incorporating the hash of the entry before it.

**Security interpretation:** A cryptographic hash is a fixed-length fingerprint of data — any change, however small, produces a completely different hash (the avalanche effect), which is why hashing detects tampering rather than preventing it. Chaining hashes together (each entry's hash depends on the previous entry) makes a log **tamper-evident**: modifying any historical entry breaks the chain of hashes for every entry after it, making retroactive tampering detectable.

**macOS-specific note:** macOS does not ship `sha256sum`; the equivalent BSD tool is `shasum -a 256`, used throughout this task.

## Verification

```bash
aws $EP kms list-keys
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

`[SCREENSHOT: verification commands output]`

## Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

Symmetric encryption (e.g. AES) uses one shared key for both encryption and decryption, making it computationally fast and well suited to encrypting large volumes of data. Its weakness is key distribution — the same key must reach every party who needs to decrypt, and each transfer or copy of that key is a potential point of compromise. Asymmetric encryption (e.g. RSA) uses a mathematically linked public/private key pair: the public key can be shared freely since only the private key can decrypt, eliminating the distribution problem. The trade-off is that asymmetric operations are significantly slower and less efficient for large payloads. In practice, systems combine both — asymmetric encryption to securely exchange or wrap a symmetric key, and symmetric encryption for the bulk data (demonstrated in Task 5's envelope encryption).

### Q2. Why is key management described as the weakest link, not the algorithm?

Modern algorithms like AES-256 and RSA-2048 are computationally infeasible to break directly. In practice, breaches occur not because the math failed, but because a key was exposed, reused, stored in plaintext, or improperly rotated. Task 1 illustrated this directly: the AES passphrase, once known, unlocks the data regardless of how strong the underlying cipher is. A KMS (Tasks 4–6) exists precisely to address this — it centralizes key lifecycle management, avoids exposing plaintext key material, and allows keys to be rotated, disabled, or destroyed independently of the algorithm itself.

### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.

Envelope encryption uses a two-tier key structure: a disposable data key encrypts the actual data locally (fast, symmetric), while the data key itself is "wrapped" (encrypted) by a master key held in the KMS. As demonstrated in Task 5, the plaintext data key exists only briefly on disk and is deleted immediately after use, leaving only its wrapped form. Because the master key never leaves the KMS and is used only to wrap/unwrap small data keys rather than bulk data, it is the single long-lived secret in the system — making it the only component that justifies the cost of hardware-grade protection (e.g. an HSM), while data keys can be generated, used, and discarded cheaply and frequently.

### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?

In a traditional on-premises system, secure deletion means physically overwriting the storage sectors that held the data. In the cloud, this is often impossible: data is replicated across multiple disks and regions, held in snapshots, or stored on SSDs with wear-levelling that abstracts away the true physical location of the bytes — a tenant has no way to guarantee every copy was reached. Cryptographic erasure sidesteps this entirely: instead of destroying the data, it destroys the **key** that protects it. Task 6 demonstrated this — scheduling deletion of tenant A's master key immediately rendered its wrapped data key, and by extension all data encrypted under it, permanently unreadable, even though the ciphertext bytes (`record.env.enc`, `datakey.enc`) still exist on disk. This is provable and instantaneous regardless of how many physical copies of the ciphertext exist.

### Q5. How does a hash chain make a log tamper-evident?

Each entry in a hash chain incorporates the hash of the previous entry as part of its own input (`PREV = hash(PREV + line)`), so every entry is cryptographically linked to the entire history before it. Task 7 demonstrated this with three chained log lines. If an attacker tries to alter or delete an earlier entry, that entry's hash changes, which in turn changes every hash computed after it — the tampering becomes immediately visible because the chain no longer matches. This is the same principle underlying tamper-evident audit logs and, at a larger scale, blockchains.

## Security Best-Practices Checklist

- [x] Data encrypted at rest (AES) and decryption verified.
- [x] Asymmetric keys used correctly (encrypt with public, sign with private).
- [x] Data protected in transit with TLS.
- [x] Envelope encryption used; plaintext data key not left on disk.
- [x] Per-tenant keys used; cryptographic erasure demonstrated.
- [x] Integrity verified with hashing / hash chain.

## Cleanup

```bash
docker stop tls
docker stop localstack
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt nginx.conf
```

## Conclusion

This lab demonstrated the full lifecycle of protecting data at rest, in transit, and under key-based access control. Symmetric and asymmetric encryption (Tasks 1–2) showed the trade-off between speed and key distribution, while TLS (Task 3) extended protection to data in motion. Moving to a simulated cloud KMS (Tasks 4–6), envelope encryption showed how a disposable data key limits exposure of the long-lived master key, and scheduling that master key's deletion rendered all data wrapped under it permanently unreadable — cryptographic erasure achieving provable deletion in a way that physical overwriting cannot guarantee in a replicated cloud environment. Finally, SHA-256 hashing and a hash chain (Task 7) demonstrated that integrity — detecting tampering — is a separate concern from confidentiality, and requires its own mechanism.
