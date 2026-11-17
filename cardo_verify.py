#!/usr/bin/env python3
"""Check a Cardo company archive offline, without Soteria Dynamics.

    python3 cardo_verify.py <archive.zip | extracted folder>

1. MANIFEST.sha256 carries Cardo's Ed25519 signature (MANIFEST.sha256.sig), and every file matches
   it (no file missing, changed or added). So no file of the archive, the ledger included, can be
   changed, added, dropped or cut short without the signature failing.
2. Every ledger entry under ledger/: its entry_hash (SHA-256 of the canonical JSON), its document
   hash, its links to the entry before it, its Ed25519 signature. An entry without a signature
   passes only when a later signed entry commits to it through the chain of entry_hash links
   (each one is checked), and it is reported. One company only, starting at its first entry.
3. The OpenTimestamps proofs: each proof must commit to its day file's exact content; prints the
   last point anchored and the `ots verify` command for each proof (Bitcoin is checked by `ots`).

The signing key is the one written below (published on soteriadynamics.com): never a key found in
the archive. Python 3.9+, standard library, plus PyNaCl or cryptography (`pip install pynacl`).
Exit code: 0 = intact, 1 = a problem, 2 = usage, 3 = cannot verify (no Ed25519 library).
The formats are described in README.md next to this file. Licence: MIT.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

# Cardo's ledger signing key (Ed25519, public half), published at
# https://soteriadynamics.com/en/cardo-formats.html and in cardo-ledger-signing.pub.
CARDO_KEY = "a00a28c9274438788a5f701278a13a72d932f6da6b980936009d79ece64b71dc"
NOT_HASHED = ("entry_hash", "signature", "signature_status")
MANIFEST, MANIFEST_SIG = "MANIFEST.sha256", "MANIFEST.sha256.sig"
MANIFEST_CONTEXT = b"cardo-archive-manifest-v1\n"   # what is signed: this line, then the manifest's bytes
DAY_FILE = re.compile(r"ledger/(\d{4})/(\d{2})/\1\2\d{2}\.ndjson")
MANIFEST_LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")
HEX64 = re.compile(r"[0-9a-f]{64}")
# An .ots file: magic, version 1, SHA-256 op (0x08), then the 32-byte digest it timestamps.
OTS_HEAD = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01\x08"


def canonical(obj) -> bytes:
    """Keys sorted, no spaces, every non-ASCII character escaped as \\uXXXX."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entry_hash(rec: dict) -> str:
    return sha256(canonical({k: v for k, v in rec.items() if k not in NOT_HASHED}))


def show(name: str) -> str:
    """A file name as text that cannot carry a line break or a terminal control into the output."""
    return name if name.isprintable() else ascii(name)


def _ed25519():
    try:
        from nacl.signing import VerifyKey

        def check(pub: str, msg: bytes, sig: str) -> bool:
            try:
                VerifyKey(bytes.fromhex(pub)).verify(msg, bytes.fromhex(sig))
                return True
            except Exception:  # noqa: BLE001 (any failure = not valid)
                return False
        return check
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        def check(pub: str, msg: bytes, sig: str) -> bool:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), msg)
                return True
            except Exception:  # noqa: BLE001
                return False
        return check
    except ImportError:
        return None


def _safe_name(n: str) -> bool:
    parts = n.split("/")
    return bool(n) and n.isprintable() and "\\" not in n and not n.startswith("/") and \
        all(p not in ("", ".", "..") for p in parts)


class Source:
    """The archive as {relative path: bytes}, from a ZIP or an extracted folder. A link, a name that
    climbs out of the archive or a name present twice is a problem, and the file is not read."""

    def __init__(self, path: Path, problems: list):
        self.files: dict[str, bytes] = {}
        if path.is_dir():
            for root, dirs, files in os.walk(path):   # never follows links
                for d in dirs:
                    if os.path.islink(os.path.join(root, d)):
                        problems.append(f"a link in the archive folder: {show(os.path.relpath(os.path.join(root, d), path))}")
                for f in files:
                    p = os.path.join(root, f)
                    rel = Path(os.path.relpath(p, path)).as_posix()
                    if not stat.S_ISREG(os.lstat(p).st_mode):
                        problems.append(f"not a plain file (a link?): {show(rel)}")
                    elif not _safe_name(rel):
                        problems.append(f"unsafe file name: {show(rel)}")
                    else:
                        with open(p, "rb") as fh:
                            self.files[rel] = fh.read()
            return
        with zipfile.ZipFile(path) as z:   # ponytail: whole archive in memory; stream it if archives outgrow RAM
            for info in z.infolist():
                n = info.filename
                if n.endswith("/"):
                    continue
                if stat.S_ISLNK(info.external_attr >> 16):
                    problems.append(f"a link in the archive: {show(n)}")
                elif not _safe_name(n):
                    problems.append(f"unsafe file name: {show(n)}")
                elif n in self.files:
                    problems.append(f"the same name twice in the ZIP (tools disagree on which one is real): {show(n)}")
                else:
                    self.files[n] = z.read(info)


def check_manifest(src: Source, key: str, verify, problems: list) -> int:
    man = src.files.get(MANIFEST)
    if man is None:
        problems.append("MANIFEST.sha256 is missing")
        return 0
    listed: set[str] = set()
    try:
        lines = man.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        problems.append("MANIFEST.sha256 is not UTF-8")
        return 0
    for i, line in enumerate(lines, 1):
        if not line and i == len(lines):
            continue
        m = MANIFEST_LINE.fullmatch(line)
        if not m or not _safe_name(m.group(2)):
            problems.append(f"MANIFEST.sha256 line {i} is not '<sha256>  <path>'")
            continue
        want, name = m.groups()
        if name in listed or name in (MANIFEST, MANIFEST_SIG):
            problems.append(f"MANIFEST.sha256 lists {show(name)} twice (or lists itself)")
        listed.add(name)
        if name not in src.files:
            problems.append(f"missing file: {show(name)}")
        elif sha256(src.files[name]) != want:
            problems.append(f"changed file: {show(name)}")
    for extra in sorted(set(src.files) - listed - {MANIFEST, MANIFEST_SIG}):
        problems.append(f"file not in the manifest: {show(extra)}")
    raw = src.files.get(MANIFEST_SIG)
    if raw is None:
        problems.append("MANIFEST.sha256 is not signed (no MANIFEST.sha256.sig): anyone could have changed the files "
                        "and written a new manifest, or cut the ledger short (archives made before Cardo 0.407.1: "
                        "make a new archive)")
        return len(listed)
    try:
        sig = json.loads(raw)
        ok = isinstance(sig, dict) and sig.get("algorithm") == "ed25519" and isinstance(sig.get("signature"), str)
    except ValueError:
        ok = False
    if not ok:
        problems.append("MANIFEST.sha256.sig is not an Ed25519 signature record")
    elif sig.get("public_key") != key:
        problems.append("MANIFEST.sha256 is signed with a key other than Cardo's published key")
    elif not verify(key, MANIFEST_CONTEXT + man, sig["signature"]):
        problems.append("the signature of MANIFEST.sha256 does not verify (the manifest was changed)")
    return len(listed)


def _no_constants(name):
    raise ValueError(f"{name} is not JSON")


def _ranges(idx: list[int], recs: list) -> list[str]:
    """Consecutive entries as 'file:first-last (first time to last time)'."""
    out, start = [], None
    for k, i in enumerate(idx):
        if start is None:
            start = i
        if k + 1 == len(idx) or idx[k + 1] != i + 1 or recs[idx[k + 1]][0] != recs[i][0]:
            f, a, ta = recs[start][0], recs[start][1], recs[start][2].get("timestamp", "?")
            b, tb = recs[i][1], recs[i][2].get("timestamp", "?")
            out.append(f"{f}:{a}-{b} ({ta[:19]} to {tb[:19]} UTC)" if a != b else f"{f}:{a} ({ta[:19]} UTC)")
            start = None
    return out


def check_ledger(src: Source, key: str, verify, problems: list, warnings: list) -> dict:
    days = sorted(n for n in src.files if n.startswith("ledger/") and n.endswith(".ndjson"))
    for n in days:
        if not DAY_FILE.fullmatch(n):
            problems.append(f"not a ledger day file name (ledger/YYYY/MM/YYYYMMDD.ndjson): {show(n)}")
    days = [n for n in days if DAY_FILE.fullmatch(n)]
    recs: list[tuple[str, int, dict]] = []
    for name in days:
        try:
            text = src.files[name].decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{name}: not UTF-8")
            continue
        if text and not text.endswith("\n"):
            problems.append(f"{name}: the last line is cut (no line end)")
        for i, line in enumerate(text.split("\n")[:-1] if text.endswith("\n") else text.split("\n"), 1):
            where = f"{name}:{i}"
            try:
                rec = json.loads(line, parse_constant=_no_constants)
            except ValueError:
                problems.append(f"{where}: not valid JSON")
                continue
            # The exact form Cardo writes: so what anyone reads (numbers, keys, escapes) is what was hashed
            if not isinstance(rec, dict) or json.dumps(rec, separators=(",", ":")) != line:
                problems.append(f"{where}: not in the form Cardo writes (spaces, a key twice, a number written differently)")
                continue
            if not (isinstance(rec.get("data"), dict) and all(isinstance(rec.get(k), str) for k in
                                                               ("hash", "engine", "timestamp", "prev_hash", "entry_hash"))):
                problems.append(f"{where}: a required field is missing (hash, engine, timestamp, prev_hash, entry_hash, data)")
                continue
            recs.append((name, i, rec))

    n = len(recs)
    eh_ok, full_link, doc_ok, sig_ok = [False] * n, [False] * n, [False] * n, [False] * n
    old_form = 0
    seen: dict[str, str] = {}
    engines: set[str] = set()
    for j, (name, i, rec) in enumerate(recs):
        where = f"{name}:{i}"
        engines.add(rec["engine"])
        eh_ok[j] = rec["entry_hash"] == entry_hash(rec)
        if not eh_ok[j]:
            problems.append(f"{where}: entry_hash does not match the entry (changed)")
        if rec["entry_hash"] in seen:
            problems.append(f"{where}: the same entry as {seen[rec['entry_hash']]} (an entry repeated)")
        seen.setdefault(rec["entry_hash"], where)
        doc_ok[j] = rec["hash"] == sha256(canonical(rec["data"]))
        if not doc_ok[j]:
            # early entries hashed their data with non-ASCII left unescaped (the first canonical form)
            if rec["hash"] == sha256(json.dumps(rec["data"], sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=False).encode("utf-8")):
                old_form += 1
                doc_ok[j] = True
            else:
                problems.append(f"{where}: hash does not match data (changed)")
        if j == 0:
            if rec["prev_hash"] != "genesis" or rec.get("prev_entry_hash", "genesis") != "genesis":
                problems.append(f"{where}: first entry does not start the chain (genesis): entries before it are missing")
        else:
            prev = recs[j - 1][2]
            if rec["prev_hash"] != prev["hash"]:
                problems.append(f"{where}: prev_hash does not point to the entry before it")
            if "prev_entry_hash" in rec:
                full_link[j] = rec["prev_entry_hash"] == prev["entry_hash"] and eh_ok[j - 1]
                if rec["prev_entry_hash"] != prev["entry_hash"]:
                    problems.append(f"{where}: prev_entry_hash does not point to the entry before it")
        sig = rec.get("signature")
        if sig is not None:
            if not isinstance(sig, dict) or sig.get("algorithm") != "ed25519" or not isinstance(sig.get("signature"), str):
                problems.append(f"{where}: the signature is not an Ed25519 signature record")
            elif sig.get("public_key") != key:
                problems.append(f"{where}: signed with a key other than Cardo's published key")
            elif not (eh_ok[j] and verify(key, rec["entry_hash"].encode("ascii"), sig["signature"])):
                problems.append(f"{where}: signature does not verify")
            else:
                sig_ok[j] = True

    # What the signatures cover. A valid signature covers its entry_hash, which covers prev_entry_hash,
    # which is the previous entry's entry_hash: so a signed entry covers every entry before it reached by
    # unbroken entry_hash links (each checked above). Older links (prev_hash only) cover the previous
    # entry's data, not its other fields.
    full, data_only = [False] * n, [False] * n
    for j in range(n - 1, -1, -1):
        nxt = j + 1 < n and full[j + 1]
        full[j] = sig_ok[j] or (nxt and full_link[j + 1])
        data_only[j] = not full[j] and nxt and doc_ok[j] and recs[j + 1][2]["prev_hash"] == recs[j][2]["hash"]
    first_signed = next((j for j in range(n) if sig_ok[j]), None)
    if n and first_signed is None:
        problems.append("no ledger entry carries a valid signature: the ledger cannot be authenticated")
    late = [j for j in range(n) if first_signed is not None and j > first_signed and recs[j][2].get("signature") is None]
    late_bad = [j for j in late if not full[j]]
    late_ok = [j for j in late if full[j]]
    for r in _ranges(late_bad, recs):
        problems.append(f"{r}: unsigned after signing began, and no later signed entry commits to it")
    if late_ok:
        warnings.append(f"{len(late_ok)} entries were written without a signature after signing began; each is "
                        "covered by the signature of a later entry through the chain of entry_hash links (checked): "
                        + "; ".join(_ranges(late_ok, recs)))
    legacy = list(range(first_signed if first_signed is not None else 0))
    legacy_none = [j for j in legacy if not full[j] and not data_only[j]]
    legacy_data = [j for j in legacy if data_only[j]]
    if legacy_none or legacy_data:
        warnings.append(f"{len(legacy)} entries were written before signing began (October 2026): "
                        f"{len(legacy) - len(legacy_none) - len(legacy_data)} covered in full by the first signature, "
                        f"{len(legacy_data)} only for their data, {len(legacy_none)} not at all; what dates and protects "
                        "those is the signed manifest of this archive and the OpenTimestamps proofs of their day files")
    if len(engines) > 1:
        problems.append(f"entries of more than one company: {', '.join(sorted(map(show, engines)))}")
    bad_engine = [e for e in engines if not e.startswith("cardo:")]
    if bad_engine:
        problems.append(f"not a Cardo company ledger: {', '.join(sorted(map(show, bad_engine)))}")
    return {"files": len(days), "entries": n, "signed": sum(sig_ok), "legacy": len(legacy),
            "late_unsigned": len(late_ok), "old_form": old_form,
            "company": next(iter(engines))[len("cardo:"):] if len(engines) == 1 else None,
            "last": recs[-1] if recs else None, "recs": recs}


def check_ots(src: Source, led: dict, problems: list) -> tuple[list[str], tuple | None, int]:
    """Each proof ledger/ots/<first 16 hex of the content's SHA-256>.ots timestamps the text
    "<content SHA-256 in hex>\\n". A day file still growing when stamped has a proof for an earlier,
    shorter content: the proof for the longest such start of the file anchors those entries.
    Returns (ots verify commands, last anchored (file, line, timestamp), entries after it)."""
    cmds, last, per_file = [], None, {}
    for name in sorted(n for n in src.files if DAY_FILE.fullmatch(n)):
        body = src.files[name]
        h, starts, upto, line_no = hashlib.sha256(), [], None, 0
        for k, line in enumerate(body.split(b"\n")[:-1], 1):   # the file's start up to each line end
            h.update(line + b"\n")
            starts.append((k, h.hexdigest()))
        for lines, fh in reversed(starts):   # the longest start with a proof
            proof = f"ledger/ots/{fh[:16]}.ots"
            if proof not in src.files:
                continue
            digest = sha256((fh + "\n").encode("ascii"))
            pb = src.files[proof]
            if not (pb.startswith(OTS_HEAD) and pb[len(OTS_HEAD):len(OTS_HEAD) + 32].hex() == digest):
                problems.append(f"{proof}: this proof does not timestamp {name} (another digest)")
                continue
            upto, line_no = proof, lines
            cmds.append(f"ots verify -d {digest} {proof}   # {name}, lines 1-{lines}")
            break
        if upto is None:
            cmds.append(f"# {name}: no proof for its content yet (the day was still open, or not yet anchored)")
        per_file[name] = line_no
    after = 0
    for (name, i, rec) in led["recs"]:
        if i <= per_file.get(name, 0):
            last, after = (name, i, rec["timestamp"]), 0
        else:
            after += 1
    return cmds, last, after


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check a Cardo company archive offline.")
    ap.add_argument("archive", type=Path, help="the archive ZIP, or the folder it was extracted to")
    ap.add_argument("--key", default=CARDO_KEY, help=argparse.SUPPRESS)   # tests, or a key Cardo publishes later
    a = ap.parse_args(argv)
    if not a.archive.exists():
        print(f"not found: {a.archive}", file=sys.stderr)
        return 2
    key = a.key.lower()
    if not HEX64.fullmatch(key):
        print("--key: 64 hex characters", file=sys.stderr)
        return 2
    verify = _ed25519()
    if verify is None:
        print("CANNOT VERIFY: no Ed25519 library, so no signature can be checked. Install one and run again:\n"
              "  pip install pynacl        (or: pip install cryptography)")
        return 3
    problems: list[str] = []
    warnings: list[str] = []
    if key != CARDO_KEY:
        warnings.append(f"checked against the key given with --key ({key}), NOT Cardo's published key")
    try:
        src = Source(a.archive, problems)
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as e:   # unreadable, encrypted or bad ZIP
        print(f"NOT INTACT: the archive cannot be read ({type(e).__name__}: {e})")
        return 1
    listed = check_manifest(src, key, verify, problems)
    led = check_ledger(src, key, verify, problems, warnings)
    cmds, anchored, after = check_ots(src, led, problems)
    readme = src.files.get("README.txt", b"").decode("utf-8", "replace")
    m = re.search(r"^Entreprise / Company: (.*)$", readme, re.M)
    if m and led["company"] is not None and m.group(1).strip() != led["company"]:
        problems.append(f"README.txt names company {show(m.group(1).strip())}, the ledger is {show(led['company'])}'s")
    gen = re.search(r"^Générée / Generated: (.*)$", readme, re.M)

    print(f"Company: {show(led['company'] or '?')}" + (f"   archive generated {show(gen.group(1).strip())}" if gen else ""))
    print(f"Files in the manifest: {listed}")
    print(f"Ledger: {led['entries']} entries in {led['files']} day files, {led['signed']} signatures verified, "
          f"{led['late_unsigned']} unsigned after signing began (covered by a later signature), "
          f"{led['legacy']} written before signing began, {led['old_form']} in the first canonical form")
    if led["last"]:
        name, i, rec = led["last"]
        print(f"Last entry: {name}:{i}, {rec['timestamp'][:19]} UTC, entry_hash {rec['entry_hash']}")
    if anchored:
        print(f"Last point anchored by OpenTimestamps: {anchored[0]}:{anchored[1]} ({anchored[2][:19]} UTC); "
              f"{after} entries after it not timestamped yet")
    else:
        print("No entry is anchored by an OpenTimestamps proof in this archive")
    for w in warnings:
        print("WARNING:", w)
    for p in problems:
        print("PROBLEM:", p)
    if problems:
        print(f"NOT INTACT: {len(problems)} problem(s)")
    else:
        print("OK: intact. Every file is as Cardo signed it, every ledger entry since signing began is covered by "
              "Cardo's signature" + (f"; the last {after} entries are not yet timestamped (OpenTimestamps)" if after else "")
              + ". Not provable offline: that this is Cardo's latest archive (compare the archive's SHA-256 with"
              " the one Cardo shows, act data.archive_generated) and the Bitcoin dates (run the commands below).")
    print("\nTimestamps (OpenTimestamps client: pip install opentimestamps-client), run in the archive folder:")
    for c in cmds:
        print("  " + c)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
