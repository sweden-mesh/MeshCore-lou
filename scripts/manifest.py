#!/usr/bin/env python3
"""The per-variant OTA manifest, written unsigned where images are built and signed where
the release key is (TODO 22a rulings 15, 22; docs/ota.md).

    manifest.py unsigned <image.bin> <variant> <features> <version> <base-version> <build>
                         <partsig-file> <out.json>
    manifest.py sign <unsigned.json> <image.bin> <file-url> <release-key-file> <out.json>
    manifest.py verify <manifest.json> <release-pubkey-hex>
    manifest.py index <release-dir> <tag> <base-url> <release-key-file>
    manifest.py verify-index <firmware-index.json> <release-pubkey-hex>
    manifest.py --pubkey <release-key-file>       prints the public key build.sh bakes in
    manifest.py --keygen <release-key-file>       makes a new key (refuses to overwrite)

A node fetches `<channel>/<variant>.json`, where the variant is `<env>-<features>`. `sig` is
the release key's Ed25519 signature over "sha256|version|file", which every release since
ar-11 checks; `sig2` is over "sha256|version|file|variant|features", which every lou-14 image
checks against its own variant and features, so a node only ever installs its own
combination. `sign` refuses an unsigned manifest whose image is not the one given, whose
version does not name its features, or whose variant does not end in them. The key file
holds the 32-byte seed as 64 hex and lives outside every repository and CI.
"""
import hashlib
import json
import os
import re
import secrets
import sys

FEATURE_TOKENS = ("as", "ar", "rc", "asar", "asrc", "arrc", "asarrc")


def key_from_file(path):
    from Crypto.PublicKey import ECC
    seed = bytes.fromhex(open(path, encoding="utf-8").read().strip())
    if len(seed) != 32:
        sys.exit("the release key file must hold a 32-byte seed as 64 hex")
    return ECC.construct(curve="Ed25519", seed=seed)


def pubkey_hex(path):
    return key_from_file(path).public_key().export_key(format="raw").hex().upper()


def sha256_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def features_of_version(version):
    m = re.search(r"-lou-\d+-([a-z]+)-", version)
    return m.group(1) if m and m.group(1) in FEATURE_TOKENS else None


def check_names(variant, features, version):
    if features not in FEATURE_TOKENS:
        return f"'{features}' is not a combination"
    if features_of_version(version) != features:
        return f"version {version} does not name the features {features}"
    if not variant.endswith("-" + features):
        return f"variant {variant} is not for the features {features}"
    return None


def unsigned(image, variant, features, version, base, build, partsig_file, out):
    problem = check_names(variant, features, version)
    if problem:
        sys.exit(problem)
    partsig = open(partsig_file, encoding="utf-8").read().strip() if os.path.exists(partsig_file) else ""
    manifest = {"version": version, "baseVersion": base, "build": int(build) if build.isdigit() else -1,
                "fileName": os.path.basename(image), "sha256": sha256_of(image), "partSig": partsig,
                "variant": variant, "features": features}
    write(out, manifest)
    print(f"{out}: {variant} {version} sha256 {manifest['sha256'][:12]}... unsigned")


def sign(unsigned_json, image, file_url, key_file, out):
    from Crypto.Signature import eddsa
    m = json.load(open(unsigned_json, encoding="utf-8"))
    sha = sha256_of(image)
    if sha != m.get("sha256"):
        sys.exit(f"{image} is not the image {unsigned_json} describes (sha256 differs)")
    if os.path.basename(image) != m.get("fileName") or not file_url.endswith("/" + m["fileName"]):
        sys.exit(f"{file_url} does not name {m.get('fileName')}")
    problem = check_names(m.get("variant", ""), m.get("features", ""), m.get("version", ""))
    if problem:
        sys.exit(problem)
    signer = eddsa.new(key_from_file(key_file), "rfc8032")
    m["file"] = file_url
    m["sig"] = signer.sign(f"{sha}|{m['version']}|{file_url}".encode("ascii")).hex()
    m["sig2"] = signer.sign(
        f"{sha}|{m['version']}|{file_url}|{m['variant']}|{m['features']}".encode("ascii")).hex()
    write(out, m)
    print(f"{out}: {m['variant']} {m['version']} signed (sig, sig2)")


def verify(manifest_json, pub_hex):
    """Exit 0 when both signatures are the release key's and the names agree, 1 otherwise."""
    from Crypto.Signature import eddsa
    m = json.load(open(manifest_json, encoding="utf-8"))
    v = eddsa.new(eddsa.import_public_key(bytes.fromhex(pub_hex)), "rfc8032")
    try:
        v.verify(f"{m['sha256']}|{m['version']}|{m['file']}".encode("ascii"), bytes.fromhex(m["sig"]))
        v.verify(f"{m['sha256']}|{m['version']}|{m['file']}|{m['variant']}|{m['features']}".encode("ascii"),
                 bytes.fromhex(m["sig2"]))
    except (KeyError, ValueError) as e:
        print(f"{manifest_json}: not signed by {pub_hex[:12]}... ({e.__class__.__name__})")
        return 1
    problem = check_names(m["variant"], m["features"], m["version"])
    if problem:
        print(f"{manifest_json}: {problem}")
        return 1
    print(f"{manifest_json}: {m['variant']} signed")
    return 0


IMAGE_RE = re.compile(r"^(?P<env>.+?)-(?P<mcu>[a-z0-9]+)-(?P<base>v[0-9.]+)-(?P<rev>lou-\d+)-"
                      r"(?P<features>[a-z]+)-(?P<hash>[0-9a-f]{7,})(?P<merged>-merged)?\.(?P<ext>bin|uf2|zip|hex)$")
FLASH = {"bin": "app image at 0x10000 (OTA, or a cable flash that keeps the settings)",
         "merged": "full image at 0x0 (a clean device)",
         "uf2": "drag and drop onto the bootloader drive",
         "zip": "nRF DFU package", "hex": "SWD"}


def index_rows(release_dir, base_url):
    """One row per image file in the release, from its name and its bytes: the page reads
    this and never parses a name itself (TODO 22a ruling 25)."""
    rows = []
    for name in sorted(os.listdir(release_dir)):
        m = IMAGE_RE.match(name)
        if not m:
            continue
        form = "merged" if m.group("merged") else m.group("ext")
        env = m.group("env")
        rows.append({
            "board": env, "base": "observer" if env.endswith("_observer_mqtt") else "core",
            "features": m.group("features"), "mcu": m.group("mcu"),
            "version": f"{m.group('mcu')}-{m.group('base')}-{m.group('rev')}-{m.group('features')}-{m.group('hash')}",
            "file": name, "url": f"{base_url}/{name}", "sha256": sha256_of(os.path.join(release_dir, name)),
            "form": form, "flash": FLASH[form],
            "manifest": f"{env}-{m.group('features')}.json" if env.endswith("_observer_mqtt") else None,
        })
    return rows


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def index(release_dir, tag, base_url, key_file):
    from Crypto.Signature import eddsa
    rows = index_rows(release_dir, base_url)
    if not rows:
        sys.exit(f"no images in {release_dir}")
    body = {"format": 1, "release": tag, "images": rows}
    sig = eddsa.new(key_from_file(key_file), "rfc8032").sign(canonical(body)).hex()
    write(os.path.join(release_dir, "firmware-index.json"), dict(body, sig=sig))
    print(f"firmware-index.json: {len(rows)} images, signed")


def verify_index(index_json, pub_hex):
    """The signature covers the index with `sig` taken out, as canonical JSON (sorted keys,
    no spaces, ASCII): exit 0 when it is the release key's, 1 otherwise."""
    from Crypto.Signature import eddsa
    doc = json.load(open(index_json, encoding="utf-8"))
    sig = doc.pop("sig", "")
    try:
        eddsa.new(eddsa.import_public_key(bytes.fromhex(pub_hex)), "rfc8032").verify(
            canonical(doc), bytes.fromhex(sig))
    except ValueError:
        print(f"{index_json}: not signed by {pub_hex[:12]}...")
        return 1
    print(f"{index_json}: {len(doc['images'])} images, signed")
    return 0


def write(out, manifest):
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")


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
    if len(argv) == 10 and argv[1] == "unsigned":
        unsigned(*argv[2:])
        return 0
    if len(argv) == 7 and argv[1] == "sign":
        sign(*argv[2:])
        return 0
    if len(argv) == 4 and argv[1] == "verify":
        return verify(*argv[2:])
    if len(argv) == 6 and argv[1] == "index":
        index(*argv[2:])
        return 0
    if len(argv) == 4 and argv[1] == "verify-index":
        return verify_index(*argv[2:])
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
