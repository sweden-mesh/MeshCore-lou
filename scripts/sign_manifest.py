#!/usr/bin/env python3
"""Write the per-variant OTA manifest for one image, signed by the release key.

    sign_manifest.py <image.bin> <variant> <version> <base-version> <build> <file-url>
                     <partsig-file> <release-key-file> <out.json>

The node reads `<channel>/<variant>.json` (OtaVerifyLogic.h, docs/ota.md): `sha256` is the
image's hash, `sig` an Ed25519 signature by the release key over "sha256|version|file" --
the manifest's own text, so any changed field fails. The release key file holds the 32-byte
seed as 64 hex; it lives outside every repository. The matching public key is what
build.sh bakes in as OTA_RELEASE_PUBKEY:

    sign_manifest.py --pubkey <release-key-file>      prints it
    sign_manifest.py --keygen <release-key-file>      makes a new one (refuses to overwrite)
"""
import hashlib
import json
import os
import secrets
import sys

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


def key_from_file(path):
    seed = bytes.fromhex(open(path, encoding="utf-8").read().strip())
    if len(seed) != 32:
        sys.exit("the release key file must hold a 32-byte seed as 64 hex")
    return ECC.construct(curve="Ed25519", seed=seed)


def pubkey_hex(path):
    return key_from_file(path).public_key().export_key(format="raw").hex().upper()


def main(argv):
    if len(argv) == 3 and argv[1] == "--pubkey":
        print(pubkey_hex(argv[2]))
        return 0
    if len(argv) == 3 and argv[1] == "--keygen":
        if os.path.exists(argv[2]):
            sys.exit(f"{argv[2]} exists; a release key is replaced on purpose, not by accident")
        fd = os.open(argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32) + "\n")
        print(f"release key written to {argv[2]} (mode 600); public key: {pubkey_hex(argv[2])}")
        return 0
    if len(argv) != 10:
        sys.exit(__doc__)
    image, variant, version, base, build, file_url, partsig_file, key_file, out = argv[1:]
    sha = hashlib.sha256(open(image, "rb").read()).hexdigest()
    signer = eddsa.new(key_from_file(key_file), "rfc8032")
    sig = signer.sign(f"{sha}|{version}|{file_url}".encode("ascii")).hex()
    partsig = open(partsig_file, encoding="utf-8").read().strip() if os.path.exists(partsig_file) else ""
    manifest = {"version": version, "baseVersion": base, "build": int(build) if build.isdigit() else -1,
                "file": file_url, "sha256": sha, "sig": sig, "partSig": partsig, "variant": variant}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
    print(f"{out}: {variant} {version} sha256 {sha[:12]}... signed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
