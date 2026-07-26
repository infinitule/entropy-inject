"""Command-line interface for entropy-inject.

Usage
-----
  entropy-inject inject INPUT.pdf -o OUTPUT.pdf [--notes "..."]
                                                [--sign] [--deep-clean] [--force]
  entropy-inject verify FILE.pdf [--token TOKEN]
  entropy-inject verify-sig FILE.pdf
  entropy-inject lookup TOKEN
  entropy-inject list
  entropy-inject read FILE.pdf
  entropy-inject delete TOKEN
  entropy-inject update-notes TOKEN --notes "..."
  entropy-inject export BUNDLE.json
  entropy-inject import BUNDLE.json
  entropy-inject pubkey

The ledger passphrase is read from the ENTROPY_PASSPHRASE environment
variable, or prompted interactively.  The export / import passphrase is
read from ENTROPY_EXPORT_PASSPHRASE, or prompted separately.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

import pikepdf

from .ledger import DEFAULT_DB_PATH, Ledger, LedgerEntry
from .stripper import inject_entropy
from .tokens import hash_file


# ---- passphrase helpers -----------------------------------------------


def _get_passphrase(prompt: str = "Ledger passphrase: ") -> str:
    pw = os.environ.get("ENTROPY_PASSPHRASE")
    return pw if pw else getpass.getpass(prompt)


def _get_export_passphrase(prompt: str = "Export passphrase: ") -> str:
    pw = os.environ.get("ENTROPY_EXPORT_PASSPHRASE")
    return pw if pw else getpass.getpass(prompt)


def _open_ledger(db_path: str | None) -> Ledger:
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    return Ledger.open(_get_passphrase(), db_path=path)


# ---- PDF entropy field reader -----------------------------------------


def _read_entropy_from_pdf(path: str | Path) -> dict | None:
    """Return a dict of all /EntropyXxx fields from the PDF, or None."""
    try:
        with pikepdf.open(path) as pdf:
            info = pdf.docinfo
            if info is None:
                return None
            token = info.get("/EntropyID")
            if token is None:
                return None

            def _get(key: str) -> str:
                v = info.get(key)
                return str(v) if v is not None else ""

            return {
                "token": str(token),
                "binding": _get("/EntropyBinding"),
                "input_hash": _get("/EntropyInputHash"),
                "timestamp": _get("/EntropyTimestamp"),
                "signature": _get("/EntropySignature"),
                "verify_key": _get("/EntropyVerifyKey"),
            }
    except Exception as exc:
        print(f"[fail] could not open PDF: {exc}", file=sys.stderr)
        return None


def _read_token_from_pdf(path: str | Path) -> str | None:
    fields = _read_entropy_from_pdf(path)
    return fields["token"] if fields else None


# ---- commands ---------------------------------------------------------


def cmd_inject(args: argparse.Namespace) -> int:
    try:
        result = inject_entropy(
            args.input,
            args.output,
            sign=args.sign,
            deep_clean=args.deep_clean,
            force=args.force,
        )
    except FileNotFoundError as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        return 1
    except FileExistsError as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        return 1

    print(f"[ok] sanitised -> {result.output_path}")
    print(f"     token        {result.token}")
    print(f"     input_hash   {result.input_hash}")
    print(f"     output_hash  {result.output_hash}")
    print(f"     binding      {result.binding}")
    if result.signature:
        print(f"     signature    {result.signature[:32]}…")
        print(f"     verify_key   {result.verify_key}")
    if result.deep_clean_report:
        r = result.deep_clean_report
        print(
            f"     deep_clean   catalog_keys_removed={len(r.get('removed_catalog_keys', []))}"
            f"  font_names={r.get('font_names_rewritten', 0)}"
            f"  page_artifacts={r.get('page_artifacts_removed', 0)}"
        )

    entry = LedgerEntry(
        token=result.token,
        input_hash=result.input_hash,
        output_hash=result.output_hash,
        binding=result.binding,
        timestamp=result.timestamp,
        original_metadata=result.original_metadata,
        notes=args.notes or "",
        signature=result.signature,
        verify_key=result.verify_key,
    )
    try:
        with _open_ledger(args.db) as ledger:
            ledger.append(entry)
    except Exception as exc:
        print(
            f"\n[warn] ledger write failed: {exc}\n"
            f"       The sanitised PDF is intact.  Save the token above;\n"
            f"       you can recover provenance with: entropy-inject lookup <token>",
            file=sys.stderr,
        )
        return 5
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    current_hash = hash_file(args.file)
    token = args.token or _read_token_from_pdf(args.file)
    if token is None:
        print("[fail] no token supplied and none found in PDF", file=sys.stderr)
        return 2

    with _open_ledger(args.db) as ledger:
        entry = ledger.lookup(token)
        if entry is None:
            print(f"[fail] token not found in ledger: {token}", file=sys.stderr)
            return 3

    if entry.input_hash == current_hash:
        print(f"[ok]   file matches original input_hash  ({current_hash})")
        return 0
    if entry.output_hash == current_hash:
        print(f"[ok]   file matches sanitised output_hash ({current_hash})")
        return 0

    print("[fail] file hash does not match ledger record — tampering or wrong file")
    print(f"       current:     {current_hash}")
    print(f"       input_hash:  {entry.input_hash}")
    print(f"       output_hash: {entry.output_hash}")
    return 4


def cmd_verify_sig(args: argparse.Namespace) -> int:
    """Verify an Ed25519 injection signature without the ledger."""
    fields = _read_entropy_from_pdf(args.file)
    if fields is None:
        print("[fail] no entropy marker found in PDF", file=sys.stderr)
        return 1

    missing = [f for f in ("token", "input_hash", "timestamp", "signature", "verify_key")
               if not fields.get(f)]
    if missing:
        print(f"[fail] PDF is missing fields required for signature verification: "
              f"{', '.join(missing)}", file=sys.stderr)
        print("       (PDF may predate --sign support or was injected without --sign)",
              file=sys.stderr)
        return 2

    from .signing import verify_injection_signature
    ok = verify_injection_signature(
        fields["verify_key"],
        fields["token"],
        fields["input_hash"],
        fields["timestamp"],
        fields["signature"],
    )
    if ok:
        print("[ok]   signature valid")
        print(f"       verify_key  {fields['verify_key']}")
        print(f"       token       {fields['token'][:16]}…")
        print(f"       input_hash  {fields['input_hash']}")
        print(f"       timestamp   {fields['timestamp']}")
        return 0

    print("[fail] signature INVALID — PDF may have been tampered with", file=sys.stderr)
    return 4


def cmd_lookup(args: argparse.Namespace) -> int:
    with _open_ledger(args.db) as ledger:
        entry = ledger.lookup(args.token)
    if entry is None:
        print(f"[fail] token not found: {args.token}", file=sys.stderr)
        return 3
    print(json.dumps(
        {
            "token": entry.token,
            "input_hash": entry.input_hash,
            "output_hash": entry.output_hash,
            "binding": entry.binding,
            "timestamp": entry.timestamp,
            "signature": entry.signature,
            "verify_key": entry.verify_key,
            "notes": entry.notes,
            "original_metadata": entry.original_metadata,
        },
        indent=2,
        ensure_ascii=False,
    ))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    with _open_ledger(args.db) as ledger:
        entries = list(ledger.all_entries())
    for e in entries:
        notes_preview = (e.notes[:40] + "…") if len(e.notes) > 40 else e.notes
        signed = " [signed]" if e.signature else ""
        print(f"{e.timestamp}  {e.token[:16]}…{signed}  {notes_preview}")
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    fields = _read_entropy_from_pdf(args.file)
    if fields is None:
        print("[info] no /EntropyID marker present", file=sys.stderr)
        return 1
    for key, value in fields.items():
        if value:
            print(f"{key:<12} {value}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    with _open_ledger(args.db) as ledger:
        removed = ledger.delete(args.token)
    if removed:
        print(f"[ok] deleted ledger entry for token {args.token[:16]}…")
        return 0
    print(f"[fail] token not found: {args.token}", file=sys.stderr)
    return 3


def cmd_update_notes(args: argparse.Namespace) -> int:
    with _open_ledger(args.db) as ledger:
        updated = ledger.update_notes(args.token, args.notes)
    if updated:
        print(f"[ok] notes updated for token {args.token[:16]}…")
        return 0
    print(f"[fail] token not found: {args.token}", file=sys.stderr)
    return 3


def cmd_export(args: argparse.Namespace) -> int:
    export_pw = _get_export_passphrase("Export passphrase (for the bundle): ")
    with _open_ledger(args.db) as ledger:
        count = ledger.export_bundle(args.output, export_pw)
    print(f"[ok] exported {count} entr{'y' if count == 1 else 'ies'} -> {args.output}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    export_pw = _get_export_passphrase("Export passphrase (from the bundle): ")
    with _open_ledger(args.db) as ledger:
        try:
            imported, skipped = Ledger.import_bundle(
                args.bundle, export_pw, ledger,
                skip_duplicates=not args.overwrite,
            )
        except ValueError as exc:
            print(f"[fail] {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"[fail] decryption failed — wrong passphrase? ({exc})",
                  file=sys.stderr)
            return 1
    print(f"[ok] imported {imported}, skipped {skipped} duplicate(s)")
    return 0


def cmd_pubkey(args: argparse.Namespace) -> int:
    """Print the Ed25519 verify key (safe to publish)."""
    from .signing import DEFAULT_KEY_PATH, load_or_create_signing_key
    key_path = Path(args.key) if getattr(args, "key", None) else DEFAULT_KEY_PATH
    key = load_or_create_signing_key(key_path)
    print(key.verify_key.encode().hex())
    return 0


# ---- argparse wiring --------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="entropy-inject",
        description="Strip PDF metadata and replace it with a random entropy token.",
    )
    p.add_argument(
        "--db",
        help="path to ledger database (default: ~/.entropy-ledger/ledger.db)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # inject
    pi = sub.add_parser(
        "inject", help="strip metadata from a PDF and record it in the ledger"
    )
    pi.add_argument("input", help="input PDF")
    pi.add_argument("-o", "--output", required=True, help="output PDF")
    pi.add_argument("--notes", help="free-form notes stored encrypted in the ledger")
    pi.add_argument(
        "--sign", action="store_true",
        help="sign (token, input_hash, timestamp) with the owner's Ed25519 key"
    )
    pi.add_argument(
        "--deep-clean", dest="deep_clean", action="store_true",
        help="run the deep-clean pass (catalog, font prefixes, page artifacts)"
    )
    pi.add_argument(
        "--force", action="store_true",
        help="overwrite the output file if it already exists"
    )
    pi.set_defaults(func=cmd_inject)

    # verify
    pv = sub.add_parser(
        "verify", help="check a PDF's current hash against its ledger record"
    )
    pv.add_argument("file", help="PDF to verify")
    pv.add_argument(
        "--token",
        help="token (defaults to reading /EntropyID from the PDF)",
    )
    pv.set_defaults(func=cmd_verify)

    # verify-sig
    pvs = sub.add_parser(
        "verify-sig",
        help="verify the Ed25519 injection signature embedded in a PDF (no ledger needed)",
    )
    pvs.add_argument("file", help="PDF to verify")
    pvs.set_defaults(func=cmd_verify_sig)

    # lookup
    pl = sub.add_parser("lookup", help="show the ledger entry for a token")
    pl.add_argument("token")
    pl.set_defaults(func=cmd_lookup)

    # list
    pls = sub.add_parser("list", help="list all ledger entries (brief)")
    pls.set_defaults(func=cmd_list)

    # read
    pr = sub.add_parser("read", help="print the entropy fields embedded in a PDF")
    pr.add_argument("file")
    pr.set_defaults(func=cmd_read)

    # delete
    pd = sub.add_parser("delete", help="remove a ledger entry by token")
    pd.add_argument("token")
    pd.set_defaults(func=cmd_delete)

    # update-notes
    pun = sub.add_parser("update-notes", help="update the notes for a ledger entry")
    pun.add_argument("token")
    pun.add_argument("--notes", required=True, help="replacement notes text")
    pun.set_defaults(func=cmd_update_notes)

    # export
    pex = sub.add_parser(
        "export",
        help="export all ledger entries to a portable encrypted bundle",
    )
    pex.add_argument("output", help="path to write the bundle (JSON)")
    pex.set_defaults(func=cmd_export)

    # import
    pim = sub.add_parser(
        "import",
        help="import entries from an encrypted bundle into the current ledger",
    )
    pim.add_argument("bundle", help="path to the bundle file")
    pim.add_argument(
        "--overwrite", action="store_true",
        help="replace existing entries with the same token",
    )
    pim.set_defaults(func=cmd_import)

    # pubkey
    ppk = sub.add_parser(
        "pubkey",
        help="print the Ed25519 verify key (safe to share with third parties)",
    )
    ppk.add_argument(
        "--key",
        help="path to signing key (default: ~/.entropy-ledger/signing.key)",
    )
    ppk.set_defaults(func=cmd_pubkey)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
