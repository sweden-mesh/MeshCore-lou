#!/usr/bin/env python3
"""The per-variant OTA manifest, written unsigned where images are built and signed where
the release key is (TODO 22a rulings 15, 22; docs/ota.md).

    manifest.py unsigned <image.bin> <variant> <features> <version> <base-version> <build>
                         <partsig-file> <out.json>
    manifest.py alias <arrc.unsigned.json> ar|rc <out.json>
    manifest.py candidate <candidate-dir>
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

From lou-21 an Observer board has one image, the full one (arrc), and its nodes on ar and rc
reach it by their ordinary update: `alias` writes the manifest such a node asks for,
`<env>-ar.json` or `<env>-rc.json`, with that variant and those features (what the node
compares with its own, and what `sig2` covers) and the arrc image's version, file and hash.
`"aliasOf": "<env>-arrc"` marks it; the node reads its fields by name and never sees it. An
alias is refused unless it is for ar or rc, of an Observer board, and offers an arrc version.
`candidate` says what does not hold together in a directory of images and unsigned
manifests: a manifest not named for its variant, an Observer image without exactly one
manifest of its own, or an arrc image that leaves the board's ar or rc nodes without one.
"""
import hashlib
import json
import os
import re
import secrets
import sys

FEATURE_TOKENS = ("as", "ar", "rc", "asar", "asrc", "arrc", "asarrc")
FULL = "arrc"                    # the one image of an Observer board from lou-21
ALIAS_FEATURES = ("ar", "rc")    # the images its nodes may still run, each sent to the full one
OBSERVER_ENV = "_observer_mqtt"


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
    # a release candidate's revision ends in rc or rcN (-lou-20rc-arrc-): not the feature rc
    m = re.search(r"-lou-\d+(?:rc\d*)?-([a-z]+)-", version)
    return m.group(1) if m and m.group(1) in FEATURE_TOKENS else None


def check_names(variant, features, version, alias_of=None):
    """A manifest's own names agree; an alias (alias_of given) names the node that asks and
    offers the full image instead, so there the version says arrc and the features do not."""
    if features not in FEATURE_TOKENS:
        return f"'{features}' is not a combination"
    if alias_of is None and features_of_version(version) != features:
        return f"version {version} does not name the features {features}"
    if not variant.endswith("-" + features):
        return f"variant {variant} is not for the features {features}"
    if alias_of is None:
        return None
    env = variant[:-len(features) - 1]
    if features not in ALIAS_FEATURES:
        return f"an alias is for {' or '.join(ALIAS_FEATURES)}, not {features}"
    if features_of_version(version) != FULL:
        return f"an alias offers the {FULL} image, and version {version} is not one"
    if not env.endswith(OBSERVER_ENV):
        return f"{variant} is not an Observer image, and only those have aliases"
    if alias_of != f"{env}-{FULL}":
        return f"{variant} is an alias of {env}-{FULL}, not of {alias_of}"
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


def alias(full_json, features, out):
    m = json.load(open(full_json, encoding="utf-8"))
    if "sig" in m or "sig2" in m or "aliasOf" in m or m.get("features") != FULL:
        sys.exit(f"{full_json} is not the unsigned manifest of an {FULL} image")
    full = m.get("variant", "")
    a = dict(m, variant=full[:-len(FULL)] + features, features=features, aliasOf=full)
    problem = (check_names(full, FULL, m.get("version", ""))
               or check_names(a["variant"], features, a["version"], full))
    if problem:
        sys.exit(problem)
    write(out, a)
    print(f"{out}: {a['variant']} -> {full} {a['version']} unsigned alias")


def candidate(cand_dir):
    """Exit 0 when the candidate's images and unsigned manifests hold together, 1 with each
    problem otherwise. Nothing is signed before this passes (release-candidate.sh)."""
    problems, by_image, variants = [], {}, set()
    names = sorted(os.listdir(cand_dir))
    for name in names:
        if not name.endswith(".unsigned.json"):
            continue
        m = json.load(open(os.path.join(cand_dir, name), encoding="utf-8"))
        if m.get("variant") != name[:-len(".unsigned.json")]:
            problems.append(f"{name} is for {m.get('variant')}, not the variant it is named for")
        problem = check_names(m.get("variant", ""), m.get("features", ""), m.get("version", ""),
                              m.get("aliasOf"))
        if problem:
            problems.append(f"{name}: {problem}")
        by_image.setdefault(m.get("fileName"), []).append(m)
        variants.add(m.get("variant"))
    for name in names:
        im = IMAGE_RE.match(name)
        if not im or im.group("merged") or im.group("ext") != "bin" \
                or not im.group("env").endswith(OBSERVER_ENV):
            continue
        env, features = im.group("env"), im.group("features")
        of = by_image.get(name, [])
        own = [m for m in of if m.get("aliasOf") is None]
        if len(own) != 1 or own[0].get("variant") != f"{env}-{features}":
            problems.append(f"{name} has {len(own)} manifests of its own, not one for {env}-{features}")
        for m in of:
            if m.get("aliasOf") is not None and m["aliasOf"] != f"{env}-{features}":
                problems.append(f"{m.get('variant')} is an alias of {m['aliasOf']}, but describes {name}")
        if features == FULL:
            for old in ALIAS_FEATURES:
                if f"{env}-{old}" not in variants:
                    problems.append(f"{env}: nothing is offered to its {old} nodes (no {env}-{old} "
                                    f"manifest, its own or an alias of {env}-{FULL})")
    for p in problems:
        print(p)
    return 1 if problems else 0


def sign(unsigned_json, image, file_url, key_file, out):
    from Crypto.Signature import eddsa
    m = json.load(open(unsigned_json, encoding="utf-8"))
    sha = sha256_of(image)
    if sha != m.get("sha256"):
        sys.exit(f"{image} is not the image {unsigned_json} describes (sha256 differs)")
    if os.path.basename(image) != m.get("fileName") or not file_url.endswith("/" + m["fileName"]):
        sys.exit(f"{file_url} does not name {m.get('fileName')}")
    problem = check_names(m.get("variant", ""), m.get("features", ""), m.get("version", ""),
                          m.get("aliasOf"))
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
    problem = check_names(m["variant"], m["features"], m["version"], m.get("aliasOf"))
    if problem:
        print(f"{manifest_json}: {problem}")
        return 1
    print(f"{manifest_json}: {m['variant']} signed" + (f", alias of {m['aliasOf']}" if "aliasOf" in m else ""))
    return 0


IMAGE_RE = re.compile(r"^(?P<env>.+?)-(?P<mcu>[a-z0-9]+)-(?P<base>v[0-9.]+)-(?P<rev>lou-\d+(?:rc\d*)?)-"
                      r"(?P<features>[a-z]+)-(?P<hash>[0-9a-f]{7,})(?P<merged>-merged)?\.(?P<ext>bin|uf2|zip|hex)$")
FLASH = {"bin": "app image at 0x10000 (OTA, or a cable flash that keeps the settings)",
         "merged": "full image at 0x0 (a clean device)",
         "uf2": "drag and drop onto the bootloader drive",
         "zip": "nRF DFU package", "hex": "SWD"}


def index_rows(release_dir, base_url):
    """One row per image file in the release, from its name and its bytes: the page reads
    this and never parses a name itself (TODO 22a ruling 25). `manifest` is the image's own;
    `manifests` adds the aliases found beside it, every name a node may ask for it by."""
    aliases = {}
    for name in sorted(os.listdir(release_dir)):
        if not name.endswith(".json") or name.endswith(".unsigned.json") or name == "firmware-index.json":
            continue
        doc = json.load(open(os.path.join(release_dir, name), encoding="utf-8"))
        if isinstance(doc, dict) and "aliasOf" in doc:
            aliases.setdefault(doc.get("fileName"), []).append(name)
    rows = []
    for name in sorted(os.listdir(release_dir)):
        m = IMAGE_RE.match(name)
        if not m:
            continue
        form = "merged" if m.group("merged") else m.group("ext")
        env = m.group("env")
        own = f"{env}-{m.group('features')}.json" if env.endswith(OBSERVER_ENV) else None
        app = name.replace("-merged.bin", ".bin")   # a manifest names the app image
        rows.append({
            "board": env, "base": "observer" if env.endswith(OBSERVER_ENV) else "core",
            "features": m.group("features"), "mcu": m.group("mcu"),
            "version": f"{m.group('mcu')}-{m.group('base')}-{m.group('rev')}-{m.group('features')}-{m.group('hash')}",
            "file": name, "url": f"{base_url}/{name}", "sha256": sha256_of(os.path.join(release_dir, name)),
            "form": form, "flash": FLASH[form],
            "manifest": own, "manifests": ([own] + aliases.get(app, [])) if own else [],
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
    if len(argv) == 5 and argv[1] == "alias":
        alias(*argv[2:])
        return 0
    if len(argv) == 3 and argv[1] == "candidate":
        return candidate(argv[2])
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
