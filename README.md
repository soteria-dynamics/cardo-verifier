# Cardo archive verifier

Check a Cardo company archive offline, without an account and without Soteria Dynamics' servers.

[Cardo](https://soteriadynamics.com/en/cardo.html) is the accounting and payroll software of Soteria Dynamics Inc. (Quebec). Every company can download a complete archive of its data at any time. This repository holds what anyone needs to check such an archive on their own:

- `cardo_verify.py`: the verifier (Python 3.9+, standard library, plus PyNaCl or cryptography for the signatures);
- `cardo-ledger-signing.pub`: the public key that signs Cardo's ledger entries (Ed25519, hex);
- this file: the archive format and the ledger format.

The same key and formats are published at <https://soteriadynamics.com/en/cardo-formats.html> (French: <https://soteriadynamics.com/fr/cardo-formats.html>). This repository is the second public copy, so a signature can be checked without asking us.

## Run it

```
pip install pynacl                          # or: pip install cryptography
python3 cardo_verify.py archive.zip         # or the folder the archive was extracted to
```

Exit code: 0 intact, 1 a problem (each one named), 2 usage, 3 cannot verify (no Ed25519 library: it never passes without checking the signatures).

## What it proves, and what it cannot

It proves, offline, with only the key below:

1. **The files are the ones Cardo packed.** `MANIFEST.sha256` lists every file with its SHA-256, and `MANIFEST.sha256.sig` is Cardo's Ed25519 signature of it. Every file must match, none may be missing or added. Without the signature, anyone could change a file and write a new manifest: an archive with no signature, or a signature that does not verify, fails. Since the manifest covers the ledger's day files, the ledger cannot be cut short (its last entries dropped) or completed either.
2. **Every ledger entry is Cardo's.** Each entry's `entry_hash` and document `hash` are recomputed, each link to the entry before it checked, each signature verified against the key below. The first entry must start the chain (`genesis`), and every entry must belong to the same company. A line must be exactly in the form Cardo writes it (so a key written twice, extra spaces or a number written differently cannot show one thing and hash another).
3. **Entries written without a signature are covered, or they fail.** A signature covers its entry's `entry_hash`, which covers `prev_entry_hash`, the previous entry's `entry_hash`, and so on: so a signed entry commits to every entry before it reached by unbroken `entry_hash` links. After signing began (October 2026), an unsigned entry passes only if a later signed entry commits to it that way (each link checked, never "a signed entry comes after it"), and it is reported with a WARNING, its count and its lines. Entries written before signing began are counted and reported (covered in full, for their data only, or not at all): what protects those is the signed manifest and the OpenTimestamps proofs.
4. **The timestamps match.** Each proof in `ledger/ots/` must timestamp its day file's exact content (or the start of it, for a day still open when it was stamped). It reports the last point anchored and how many entries come after it, then prints one `ots verify` command per proof for the [OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client) (`pip install opentimestamps-client`), which checks the Bitcoin block.

It cannot prove offline:

- that this is the company's **latest** archive: an older genuine archive also verifies. Compare the archive's SHA-256 (`sha256sum archive.zip`) with the one Cardo shows; it is also written to the ledger (act `data.archive_generated`).
- the **Bitcoin dates**: that needs the `ots verify` commands it prints (and a Bitcoin node or block explorer).
- anything about a key other than the one below: the key always comes from this verifier (or the site), never from the archive.

It also refuses links (symbolic links), file names that climb out of the archive (`..`, absolute paths) and a name present twice in the ZIP.

## Signing key

```
a00a28c9274438788a5f701278a13a72d932f6da6b980936009d79ece64b71dc
```

Ed25519 public key, 32 bytes in hex. Its SHA-256 fingerprint (of the 32 raw bytes) is
`151755f74b38906bf73cdb36b9d3d2c6d1da1558bd29a89064cb7c9724d742b3`.

If the key ever changes, the old key stays listed here with the date it stopped signing.

## The archive

One ZIP file. Every text file is UTF-8; CSV files start with a byte order mark so Excel shows accents.

| Path | What it holds |
|---|---|
| `README.txt` | What is inside and how to check it, in French then English. |
| `MANIFEST.sha256` | One line per other file: its SHA-256, two spaces, its path (the `sha256sum` format). `sha256sum -c MANIFEST.sha256` checks them all, but proves nothing against a change on its own: the signature does. |
| `MANIFEST.sha256.sig` | `{"algorithm": "ed25519", "public_key": "<hex>", "signature": "<hex>"}`: the Ed25519 signature, with the ledger key, of the bytes `cardo-archive-manifest-v1` and a newline followed by the bytes of `MANIFEST.sha256`. Archives made before Cardo 0.407.1 have none and do not verify: make a new one. |
| `cardo/` | Every company table as `<table>.csv` (first row: the column names, as in the database), and `cardo.json` with all the tables (`{"tables": {"<table>": [rows]}}`). |
| `books/chart_of_accounts.csv` | `code, name, type, role, active, id` |
| `books/trial_balance.csv` | `code, name, type, debit, credit`, then a TOTAL row. Amounts in dollars. |
| `books/journal_entries.csv` | One row per entry line: `entry_no, date, account, account_name, debit, credit, memo, line_memo, source, ref, org_id, journal_id`. |
| `invoices/` | Each invoice as `pdf/<number>.pdf`, and `invoices.csv`, `payments.csv`, `quotes.csv`, `quote_lines.csv`, `clients.csv`. The PDF is rendered again for the archive: the `pdf_sha256` column is the fingerprint of the PDF at issue. |
| `governance/<entity>/` | `entity.json`, `hash_chain.csv` (`seq, category, title, kind, file_name, file_sha, author, created_at, prev_hash, hash, supersedes, id`), `documents/<category>/<seq>_<name>`, `ots/anchor-<id>-seq<n>-<head>.ots`, `signatures/request-<id>/` (request, certificate, each signer's `.asc` signature and key). |
| `fleet/` | One CSV per fleet table, and `files/` with each unit's photos and attachments. |
| `ledger/` | The company ledger as written: `YYYY/MM/YYYYMMDD.ndjson`, `index.json`, and `ots/` with the OpenTimestamps proofs. |
| `chat/` | Only when asked for: each room's messages as text. |

Never in an archive: passwords, two-step verification secrets, private keys, API keys of connected services. Employees' social insurance numbers and bank accounts are included only encrypted, as Cardo keeps them; a company can get them back one by one on request to the person in charge of personal information at Soteria Dynamics.

A part that cannot be read when the archive is made (a service down) means no archive is offered: Cardo names the missing part instead of handing out an incomplete archive. The SHA-256 of each complete archive is written to the company ledger (act `data.archive_generated`).

## The ledger

One JSON object per line (NDJSON), one file per day (UTC), in order. An entry:

| Field | Meaning |
|---|---|
| `hash` | SHA-256 of `data` in canonical JSON (the document hash). |
| `engine` | `cardo:<company>`. |
| `timestamp` | When it was written, ISO 8601 UTC. |
| `prev_hash` | The `hash` of the entry before it, `genesis` for the first. |
| `prev_entry_hash` | The `entry_hash` of the entry before it, `genesis` for the first (entries written before this field existed have none; they are linked by `prev_hash`). |
| `data` | The act: `act` names it (for example `books.journal_posted`, `pay.employee_added`), the other fields describe it. Personal values that must be erasable are written as `<field>_sha256`, a salted fingerprint. |
| `entry_hash` | SHA-256 of the whole entry in canonical JSON, without `entry_hash`, `signature` and `signature_status`. |
| `signature` | `{"algorithm": "ed25519", "public_key": "<hex>", "signature": "<hex>"}`: the Ed25519 signature of the `entry_hash` text (64 ASCII hex characters). |
| `signature_status` | `signed`, or `unsigned` / `no_signer` when no key was available. Not covered by the hash: the verifier looks at `signature` itself, never at this field. |

**Canonical JSON**: keys sorted, no spaces (`,` and `:` as separators), every character outside ASCII escaped as `\uXXXX`, encoded in UTF-8. In Python: `json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. A few early entries hashed `data` with non-ASCII characters left as they are (`ensure_ascii=False`); the verifier accepts that older form for `hash` and counts it.

Because each `entry_hash` covers `prev_entry_hash`, changing any entry breaks the link of every entry after it, and a signed entry vouches for every entry before it reached by `prev_entry_hash` links. Older entries linked only by `prev_hash` are vouched for only through their `data`.

Since 2026-11-16 Cardo never writes an unsigned entry: without its key, an act waits in a queue until a process that holds the key writes it, signed. The 17 unsigned entries of 2026-11-13 on Soteria Dynamics' own ledger (written by a maintenance script that could not read the key) are each covered by a later signature, and the verifier reports them.

**Timestamps**: each day file is anchored in the Bitcoin blockchain through OpenTimestamps. The proof `ledger/ots/<first 16 hex of the file's SHA-256>.ots` timestamps the one-line text `<file SHA-256 in hex>` followed by a newline. So:

```
h=$(sha256sum ledger/2026/11/20261113.ndjson | cut -d' ' -f1)
ots verify -d "$(printf '%s\n' "$h" | sha256sum | cut -d' ' -f1)" "ledger/ots/${h:0:16}.ots"
```

A day file still open when the archive was made may have no proof for its last content yet.

## Licence

MIT, see `LICENSE`.
