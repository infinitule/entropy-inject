# entropy-inject

Every document you create is a confession.

The PDF you export carries your name, your employer, the exact version of the software you used, and the precise timestamp of every edit. None of this is visible in the text. All of it is visible to anyone with `exiftool` and thirty seconds. Legal teams harvest it in discovery. Investigators use it to establish chains of custody and break anonymity. Intelligence analysts use it to fingerprint authoring infrastructure. Stalkers use it. It travels silently with the document to every inbox it reaches, every leak site it surfaces on, every archive that caches it.

The digital world has produced an enormous volume of sophisticated tooling for protecting content in transit — encryption, signing, secure channels. It has produced almost nothing for protecting the identity of content at rest, as it moves between hands in its final form. A document either arrives scrubbed of all provenance, which destroys accountability for the owner, or it arrives intact, which exposes the owner to anyone who inspects it. There has been no clean middle ground.

**entropy-inject is that middle ground.**

It strips every identifying field from a PDF — author, title, producer, creator, timestamps, keywords, subject, and the hidden XMP stream that duplicates all of them — and replaces the entire identity surface with a single 256-bit random token bound cryptographically to the file's content hash. To anyone inspecting the sanitized file, the token is meaningless noise. To the owner, it is a key: the local encrypted ledger maps every token back to the full original provenance record, stored under Argon2id-derived XChaCha20-Poly1305 encryption that cannot be read without the passphrase.

The ledger lives on the owner's device and nowhere else. Nothing is sent. Nothing is logged. The passphrase is never stored.

---

## What it solves

**Provenance without exposure.** You can distribute a document without broadcasting who made it, when, or with what tools — while retaining the ability to look up the full history yourself.

**Tamper evidence.** The token is bound to the input file's SHA-256 hash. Any modification to the file body after sanitization breaks the binding. `verify` will flag it. You have cryptographic proof of the moment the file left your hands unchanged.

**Attested ownership without revealing identity.** With `--sign`, an Ed25519 signature is embedded in the PDF itself. A third party who holds your public key can confirm that you authorized this specific injection at this specific moment — without the ledger, without a server, and without learning anything else about you. The signature covers the token, the input hash, and the timestamp. It cannot be forged or transferred to another document.

**Body-level fingerprint reduction.** With `--deep-clean`, the pass extends below the metadata layer: authoring-tool artifacts in the document catalog are removed, per-page thumbnail images are stripped, and font subsetting prefixes — the six-character identifiers like `ABCDEF+Arial` that reveal which subsetter your tool used — are replaced with token-derived alternatives that are stable but meaningless.

**Portable encrypted provenance.** The `export` command re-encrypts your entire ledger under a separate passphrase into a self-contained bundle, transferable to another device. `import` decrypts it and merges it into the target ledger under the destination passphrase. Your provenance record follows you; your main passphrase does not leave your machine.

---

## What it proves

That the association between a document's identity and its provenance is not inherent — it is a default, and defaults can be changed without destroying the underlying record.

That a single local file, properly encrypted and backed by deterministic cryptographic bindings, is sufficient infrastructure for document provenance at the individual scale. No server. No trusted third party. No blockchain. A SQLite database and a 32-byte salt.

That tamper evidence and anonymization are not in tension. You can have both.

---

## What it is the foundation of

A document leaves your hands. It is sanitized. It carries a token. Somewhere, an encrypted ledger holds what that token means.

From here, the natural extensions are:

- **Recoverable tokens** — derive the token via HKDF from the file and your key, so you can regenerate it from the file alone without consulting the ledger. Your key becomes your index.
- **Threshold disclosure** — reveal the provenance of one token to one party, on your terms, without exposing the rest of the ledger.
- **Distributed attestation** — the Ed25519 verify key is already publishable. Build PKI around it: a registry of public keys for known signers, a chain of custody for documents that pass through multiple hands, each adding their own signature.
- **Supply chain integrity** — automated injection at document creation time, ledger entries as audit records, `verify` as a CI gate. A document pipeline where every artifact is hash-bound and tamper-evident from first export to final delivery.

This is the foundation of a provenance layer for documents — one that works offline, respects privacy, and requires nothing you don't already control.

---

## Install

```bash
pip install -e .
```

Requires `pikepdf` (libqpdf bindings) and `pynacl` (libsodium bindings).

---

## Usage

```bash
# Strip metadata and record original in the encrypted ledger.
entropy-inject inject confidential.pdf -o sanitized.pdf --notes "Client: Acme, Q3 report"

# Add an Ed25519 signature and run the deep-clean body pass.
entropy-inject inject confidential.pdf -o sanitized.pdf --sign --deep-clean

# Show all entropy fields embedded in the sanitized PDF.
entropy-inject read sanitized.pdf

# Verify a file hasn't been modified since sanitization (reads token from PDF).
entropy-inject verify sanitized.pdf

# Verify the Ed25519 signature — no ledger required.
entropy-inject verify-sig sanitized.pdf

# Look up the full provenance record for a token.
entropy-inject lookup 8a9aef47aa5fdd6b...

# List all ledger entries.
entropy-inject list

# Export the ledger to a portable encrypted bundle.
entropy-inject export backup.json

# Import on a different device.
entropy-inject import backup.json

# Print your Ed25519 verify key (safe to publish).
entropy-inject pubkey
```

Set `ENTROPY_PASSPHRASE` to avoid interactive prompts. Set `ENTROPY_EXPORT_PASSPHRASE` for export/import operations.

On first use the ledger is created at `~/.entropy-ledger/ledger.db` with a random salt at `~/.entropy-ledger/salt.bin`. Both are `chmod 0o600`. **Back up salt and DB together** — the salt is required to derive the key; without it, the ledger is unreadable.

---

## Programmatic use

```python
from entropy_inject import inject_entropy
from entropy_inject.ledger import Ledger, LedgerEntry

result = inject_entropy(
    "in.pdf", "out.pdf",
    sign=True,        # embed Ed25519 signature
    deep_clean=True,  # strip body-level fingerprints
)

with Ledger.open("my-passphrase") as ledger:
    ledger.append(LedgerEntry(
        token=result.token,
        input_hash=result.input_hash,
        output_hash=result.output_hash,
        binding=result.binding,
        timestamp=result.timestamp,
        original_metadata=result.original_metadata,
        signature=result.signature,
        verify_key=result.verify_key,
        notes="project: q3-report; client: acme",
    ))

    entry = ledger.lookup(result.token)
    print(entry.original_metadata["info"]["/Author"])
```

---

## Threat model — honest version

**What this actually defeats**

- Casual inspection via File → Properties, `exiftool`, `pdfinfo`, or any reader's metadata panel.
- Passive leakage of author, producer tool, creation/modification timestamps, subject, keywords, and title.
- Silent tampering: any modification to the file body breaks the hash-bound token, and `verify` will flag it.
- With `--sign`: unattributed distribution. The signature proves ownership without requiring the ledger.
- With `--deep-clean`: the most common body-level authoring fingerprints — catalog metadata, font subsetting prefixes, page thumbnails.

**What it does not defeat**

- Deep forensic analysis of the PDF body. ICC color profiles, image stream characteristics, object ordering patterns, embedded JavaScript, and stream filter choices can all carry tool fingerprints. `--deep-clean` reduces the surface; it does not eliminate it.
- An adversary who has the original unsanitized file and can diff bodies byte by byte.
- Re-export. If a recipient prints-to-PDF or re-saves through another tool, the token is lost along with the tamper evidence.
- Legal compulsion. The ledger is a local file. Physical or legal access to the device compromises it.

Preventing tampering regardless of any software is not achievable — any byte editor can rewrite a PDF. What is achievable, and what this tool provides, is making tampering **detectable** and making casual re-identification **impractical**.

---

## Security

- **Key derivation:** Argon2id (libsodium MODERATE opslimit / memlimit). Use SENSITIVE for archival copies if latency permits.
- **Per-entry encryption:** XChaCha20-Poly1305 via `nacl.secret.SecretBox`. Nonces are random per message, prepended to ciphertext.
- **File creation:** salt and signing key are created with `O_CREAT | O_EXCL` at mode `0o600` — no chmod race. The SQLite database is created under `umask(0o177)` for the same reason.
- **Export bundles:** re-encrypted with a fresh random salt under the export passphrase. The owner's main passphrase is never included.

---

## Layout

```
entropy_inject/
├── __init__.py    public API
├── tokens.py      CSPRNG token, file hashing, binding
├── stripper.py    /Info + XMP wipe, entropy injection, deep-clean orchestration
├── cleaner.py     catalog key removal, font prefix randomisation, page artifact stripping
├── signing.py     Ed25519 key management, sign_injection, verify_injection_signature
├── ledger.py      SQLite + Argon2id + XChaCha20-Poly1305, export/import bundles
└── cli.py         all subcommands and flags

tests/
├── conftest.py
├── test_tokens.py
├── test_ledger.py
├── test_stripper.py
├── test_signing.py
├── test_cleaner.py
└── test_cli.py     90 tests
```
