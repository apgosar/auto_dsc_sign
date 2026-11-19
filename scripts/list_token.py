"""Check the ePass 2003 driver and list tokens + certificates WITHOUT logging in.

Usage (from the project folder):
    .venv\\Scripts\\python.exe scripts\\list_token.py
    .venv\\Scripts\\python.exe scripts\\list_token.py --lib "C:\\Windows\\System32\\eps2003csp11.dll"
    .venv\\Scripts\\python.exe scripts\\list_token.py --test-login     # ONE login attempt with TOKEN_PIN from .env

Listing certificates needs no PIN (they are public objects), so the default run can never
lock the token. --test-login uses the PIN once; the token locks after repeated wrong PINs.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    from app.config import settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", default=settings.PKCS11_LIB_PATH, help="PKCS#11 DLL path")
    ap.add_argument("--test-login", action="store_true", help="Try ONE login with TOKEN_PIN from .env")
    args = ap.parse_args()

    print(f"PKCS#11 library : {args.lib}")
    if not Path(args.lib).is_file():
        print("  !! DLL not found. Install the ePass 2003 driver (see README, section 2).")
        return 2

    import pkcs11
    from asn1crypto import x509
    from pkcs11 import Attribute, ObjectClass

    lib = pkcs11.lib(args.lib)
    try:
        print(f"Library info    : {lib.manufacturer_id.strip()} / {lib.library_description.strip()} v{lib.library_version}")
    except Exception:  # noqa: BLE001
        pass
    slots = lib.get_slots(token_present=True)
    if not slots:
        print("  !! No token detected. Plug in the ePass 2003 USB token and try again.")
        return 3

    for slot in slots:
        token = slot.get_token()
        print("\n" + "=" * 70)
        print(f"Slot            : {slot.slot_description.strip()}")
        print(f"Token label     : {token.label.strip()!r}   <- use as TOKEN_LABEL")
        print(f"Manufacturer    : {token.manufacturer_id.strip()}  Model: {token.model.strip()}  Serial: {token.serial.decode(errors='ignore').strip() if isinstance(token.serial, bytes) else token.serial}")
        print(f"Flags           : {token.flags}")
        with token.open() as session:  # read-only, no login
            certs = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
            print(f"Certificates    : {len(certs)}")
            for i, obj in enumerate(certs, 1):
                try:
                    cert = x509.Certificate.load(bytes(obj[Attribute.VALUE]))
                except Exception as exc:  # noqa: BLE001
                    print(f"  [{i}] unreadable certificate: {exc}")
                    continue
                label = obj[Attribute.LABEL]
                cid = bytes(obj[Attribute.ID]).hex() if obj[Attribute.ID] else ""
                v = cert["tbs_certificate"]["validity"]
                ku = sorted(cert.key_usage_value.native) if cert.key_usage_value else []
                print(f"  [{i}] label   : {label!r}")
                print(f"      subject : {cert.subject.human_friendly}")
                print(f"      issuer  : {cert.issuer.human_friendly}")
                print(f"      valid   : {v['not_before'].native:%Y-%m-%d} -> {v['not_after'].native:%Y-%m-%d}")
                print(f"      usage   : {', '.join(ku) or '-'}")
                print(f"      id      : {cid}")
                if "non_repudiation" in ku or "digital_signature" in ku:
                    print("      => usable for signing (the app picks this kind automatically)")

        if args.test_login:
            if not settings.TOKEN_PIN:
                print("\nTOKEN_PIN is empty in .env; skipping login test.")
                continue
            print("\nTesting ONE login with TOKEN_PIN from .env ...")
            try:
                with token.open(user_pin=settings.TOKEN_PIN) as s:
                    keys = list(s.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
                    print(f"  Login OK. Private keys visible: {len(keys)}")
            except pkcs11.exceptions.PinIncorrect:
                print("  !! PIN INCORRECT. Fix TOKEN_PIN before retrying: the token locks after a few wrong PINs.")
                return 4
            except pkcs11.exceptions.PinLocked:
                print("  !! PIN LOCKED. Unlock it with the ePass 2003 token manager (needs the SO PIN).")
                return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
