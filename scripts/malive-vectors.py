#!/usr/bin/env python3
"""The announce's vectors (src/helpers/MeshAliveLogic.h and MeshReportLogic.h, lou-21), made here and
shared with the tools.

    python3 scripts/malive-vectors.py            write test/data/malive-vectors.json and
                                                 test/test_mqtt_v3/malive_vectors.h
    python3 scripts/malive-vectors.py --check    exit 1 when either is stale

This is a second implementation of the format, in Python on the `cryptography` package; the
host suite (test/test_mqtt_v3/test_mesh_alive.cpp) rebuilds every vector with the firmware's
own code and must get the same bytes. The seeds are mcc3's (test/data/mcc3-vectors.json):
the owner is its command key, the announcing node its node, the Observer node that hears it
its other node.
Ed25519 is deterministic, so the signatures by those fixed identities are vectors too.
Without `cryptography`, --check compares the header with the JSON and no more.
"""
import base64
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MCC3 = ROOT / "test/data/mcc3-vectors.json"
SOURCE = ROOT / "test/data/malive-vectors.json"
HEADER = ROOT / "test/test_mqtt_v3/malive_vectors.h"

P = 2 ** 255 - 19
KIND, KIND_SEEN = 0x4D, 0x53
MAX_VERSION, MAX_NAME, SEALED, TAG = 14, 16, 47, 8
SIGNED, SIG = 100, 64
PAYLOAD = 1 + SIGNED + SIG


def up(b):
    return b.hex().upper()


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def utf8_cut(raw, limit):
    """The longest prefix of at most `limit` bytes that ends on a character boundary."""
    if len(raw) <= limit:
        return raw
    n = limit
    while n > 0 and raw[n] & 0xC0 == 0x80:
        n -= 1
    return raw[:n]


def crypto():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    def public(seed):
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def shared(seed, peer_public):
        """MeshCore's key exchange between two Ed25519 keys: X25519 of the seed's scalar
        (SHA-512(seed)[0:32], clamped) and the peer's key moved to Curve25519, u = (1+y)/(1-y)."""
        scalar = hashlib.sha512(seed).digest()[:32]
        y = int.from_bytes(peer_public, "little") & ((1 << 255) - 1)
        u = (1 + y) * pow(1 - y, P - 2, P) % P
        return x25519.X25519PrivateKey.from_private_bytes(scalar).exchange(
            x25519.X25519PublicKey.from_public_bytes(u.to_bytes(32, "little")))

    def derive(secret, label, node_public):
        return HKDF(hashes.SHA256(), 32, None, (label + up(node_public)).encode()).derive(secret)

    def seal(key, nonce, aad, plain):
        return ChaCha20Poly1305(key).encrypt(nonce, plain, aad)

    def sign(seed, message):
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(message)

    return public, shared, derive, seal, sign


def owner_tag(command_key, node_key, boot, sequence):
    return hashlib.sha256(b"mcc3/own|" + command_key + node_key + struct.pack("<II", boot, sequence)).digest()[:4]


def signed(payload):
    return b"mcc3/ann|" + payload[1:1 + SIGNED]


def announce(seal, sign, seed, key, command_key, node_key, f):
    version = utf8_cut(f["version"].encode(), MAX_VERSION)
    name = utf8_cut(f["name"].encode(), MAX_NAME)
    plain = struct.pack("<IIIBH", f["uptime"], f["clock"], f["last_counter"], f["flags"], f["battery_mv"])
    plain += bytes([len(version)]) + version + bytes([len(name)]) + name
    plain = plain.ljust(SEALED, b"\0")
    tag = owner_tag(command_key, node_key, f["boot"], f["sequence"])
    head = node_key[:1] + node_key + bytes([KIND]) + tag + struct.pack("<II", f["boot"], f["sequence"])
    nonce = bytes(4) + struct.pack("<II", f["boot"], f["sequence"])
    sealed = seal(key, nonce, head[1:], plain)
    payload = head + sealed[:SEALED + TAG]
    payload += sign(seed, signed(payload))
    opened = dict(f, version=version.decode(), name=name.decode())
    return {
        "owner_tag": up(tag), "nonce": up(nonce), "aad": up(head[1:]), "plaintext": up(plain),
        "full_tag": up(sealed[SEALED:]), "signed": up(signed(payload)), "signature": up(payload[1 + SIGNED:]),
        "bytes": len(payload), "payload": up(payload), "opened": opened,
    }


def seen(catcher_key, payload, f):
    raw = bytes([KIND_SEEN]) + payload[1:] + struct.pack("<bBB", f["snr"], f["hops"], f["via"])
    return {
        "topic": "mcc/seen/%s" % up(catcher_key), "bytes": len(raw), "payload": b64(raw),
        "opened": dict(f, node_key=up(payload[1:33]), announce=up(payload)),
    }


def generate():
    public, shared, derive, seal, sign = crypto()
    mcc3 = json.loads(MCC3.read_bytes())["keys"]
    seeds = {"owner": mcc3["seeds"]["command"], "node": mcc3["seeds"]["node"],
             "catcher": mcc3["seeds"]["other_node"], "other_owner": mcc3["seeds"]["other_owner"]}
    pub = {k: public(bytes.fromhex(v)) for k, v in seeds.items()}
    s_node = shared(bytes.fromhex(seeds["node"]), pub["owner"])
    s_catcher = shared(bytes.fromhex(seeds["catcher"]), pub["owner"])
    assert s_node == shared(bytes.fromhex(seeds["owner"]), pub["node"])
    assert up(s_node) == mcc3["shared_secret"]
    k_malive = derive(s_node, "mcc3/malive/", pub["node"])
    # The catching node announcing itself, which no Observer image does: a second node.
    k_malive_catcher = derive(s_catcher, "mcc3/malive/", pub["catcher"])

    fields = [
        ("A1", "node", {"boot": 7, "sequence": 1, "uptime": 42, "clock": 1795000000, "last_counter": 12,
                        "flags": 0x0C, "battery_mv": 3987, "version": "lou-21-arrc", "name": "SE-JKP-LOUTEST2"}),
        ("A2 no battery, no clock, a name cut inside a word", "node",
         {"boot": 7, "sequence": 2, "uptime": 82850, "clock": 0, "last_counter": 0,
          "flags": 0x00, "battery_mv": 0, "version": "lou-21-rc", "name": "SE-JKP-Norrängen-7016"}),
        ("A3 a name cut before a character that would not fit, a version cut", "node",
         {"boot": 4294967295, "sequence": 4294967295, "uptime": 4294967295, "clock": 4294967295,
          "last_counter": 4294967295, "flags": 0xFF, "battery_mv": 65535, "version": "lou-21-arrc-extra",
          "name": "SE-JKP-Torpa-12å"}),
        ("A4 another node of the same owner", "catcher",
         {"boot": 1, "sequence": 1, "uptime": 9, "clock": 1795000100, "last_counter": 3,
          "flags": 0x08, "battery_mv": 4120, "version": "lou-21-rc", "name": "SE-JKP-Solar"}),
    ]
    announces = []
    for name, who, f in fields:
        key = k_malive if who == "node" else k_malive_catcher
        v = {"name": name, "node": who, "fields": f}
        v.update(announce(seal, sign, bytes.fromhex(seeds[who]), key, pub["owner"], pub[who], f))
        announces.append(v)

    def seen_entry(name, a, f):
        v = {"name": name, "announce": a["name"]}
        v.update(seen(pub["catcher"], bytes.fromhex(a["payload"]), f))
        return v

    seen_entries = [
        seen_entry("S1 a flood, two hops", announces[0], {"snr": -22, "hops": 2, "via": 2}),
        seen_entry("S2 a zero-hop state packet", announces[1], {"snr": 47, "hops": 0, "via": 0}),
        seen_entry("S3 direct along a path, another node", announces[3], {"snr": -80, "hops": 0, "via": 1}),
    ]

    # Reporting (src/helpers/MeshReportLogic.h): A1 between the node and the catching node.
    a1_raw = bytes.fromhex(announces[0]["payload"])
    report_id = a1_raw[1 + SIGNED:1 + SIGNED + 4]
    node_pub, catcher_pub = pub["node"], pub["catcher"]

    def packet(name, kind, raw, named=False, path_len=0, path=b""):
        return {"name": name, "kind": kind, "announce": announces[0]["name"], "named": named,
                "path_len": path_len, "path": up(path), "bytes": len(raw), "payload": up(raw)}

    path2 = bytes([0x11, 0x22])
    packets = [
        packet("P1 a state packet naming the catching node", "state",
               bytes([0xA0]) + catcher_pub[:2] + a1_raw[1:], named=True),
        packet("P2 a state packet naming nobody", "state", bytes([0xA0, 0, 0]) + a1_raw[1:]),
        packet("P3 the ack", "ack", bytes([0xB0]) + node_pub[:4] + report_id + catcher_pub),
        packet("P4 the announce along a path of two", "direct",
               a1_raw + catcher_pub[:2] + bytes([2]) + path2, path_len=2, path=path2),
        packet("P5 the path ack for a path of two", "path-ack",
               node_pub[:1] + catcher_pub + bytes([0x4B]) + report_id + bytes([2]) + path2.ljust(16, b"\0"),
               path_len=2, path=path2),
    ]

    # A guest's forward (lou-21, MqttControlV3.h): the stranger other_owner relays through the
    # catching node to the node, sealed under K_gfwd; the body is a 0xC2 request the relay
    # never opens, so any 132 bytes that start so stand in for it.
    s_guest = shared(bytes.fromhex(seeds["other_owner"]), pub["catcher"])
    assert s_guest == shared(bytes.fromhex(seeds["catcher"]), pub["other_owner"])
    k_gfwd = derive(s_guest, "mcc3/gfwd/", pub["catcher"])
    body = bytes([0xC2]) + bytes(range(1, 132))
    fwd_fields = {"counter": 3, "expiry": 1795000300, "rid": "000102030405060708090A0B0C0D0E0F",
                  "target": up(pub["node"]), "route": 1, "path_len": 0, "path": "", "body": up(body)}
    plain = struct.pack("<II", 3, 1795000300) + bytes(range(16)) + pub["node"] + bytes([1, 0]) + bytes(57)
    plain += bytes([len(body)]) + body
    gnonce = bytes(range(0x70, 0x7C))
    ghead = bytes([0x47]) + pub["other_owner"] + gnonce
    graw = ghead + seal(k_gfwd, gnonce, ghead, plain)
    rnonce = bytes(range(0x80, 0x8C))
    rplain = struct.pack("<IBIBbB", 3, 10, 1795000010, 0, -128, 0xFF) + bytes(64) + bytes([0])
    rplain = rplain.ljust(256, b"\0")
    rhead = bytes([0x66]) + rnonce
    rraw = rhead + seal(k_gfwd, rnonce, rhead, rplain)
    guest_forwards = [{
        "name": "G1 a stranger's flood in the relay's region home through the catching node to the node",
        "relay": "catcher", "guest": "other_owner", "k_gfwd": up(k_gfwd), "fields": fwd_fields,
        "nonce": up(gnonce), "bytes": len(graw), "payload": b64(graw),
        "result": {"status": 10, "status_name": "guest-cap", "clock": 1795000010, "nonce": up(rnonce),
                   "bytes": len(rraw), "payload": b64(rraw)},
    }]

    def flipped(hexed, at):
        raw = bytearray(bytes.fromhex(hexed))
        raw[at] ^= 0x01
        return up(bytes(raw))

    def resigned(hexed):
        """Signed again by the node, as somebody holding its identity could: what the seal and
        the owner tag must then refuse on their own."""
        raw = bytes.fromhex(hexed)[:1 + SIGNED]
        return up(raw + sign(bytes.fromhex(seeds["node"]), signed(raw)))

    a1 = announces[0]
    other = announce(seal, sign, bytes.fromhex(seeds["node"]), k_malive, pub["other_owner"], pub["node"],
                     fields[0][2])
    refusals = [
        {"name": "the kind byte is not 0x4D", "input": flipped(a1["payload"], 33), "outcome": "not-announce"},
        {"name": "one byte short", "input": a1["payload"][:-2], "outcome": "not-announce"},
        {"name": "one byte long", "input": a1["payload"] + "00", "outcome": "not-announce"},
        {"name": "the 101 bytes of lou-21 as first built", "input": a1["payload"][:202], "outcome": "not-announce"},
        {"name": "a signature byte changed", "input": flipped(a1["payload"], 130), "outcome": "bad-signature"},
        {"name": "the boot counter changed", "input": flipped(a1["payload"], 38), "outcome": "bad-signature"},
        {"name": "the node key changed", "input": flipped(a1["payload"], 20), "outcome": "bad-signature"},
        {"name": "a sealed byte changed", "input": flipped(a1["payload"], 60), "outcome": "bad-signature"},
        {"name": "made for another command key", "input": other["payload"], "outcome": "other-owner"},
        {"name": "the boot counter changed, signed again", "input": resigned(flipped(a1["payload"], 38)),
         "outcome": "other-owner"},
        {"name": "a sealed byte changed, signed again", "input": resigned(flipped(a1["payload"], 60)),
         "outcome": "does-not-open"},
        {"name": "the tag changed, signed again", "input": resigned(flipped(a1["payload"], 100)),
         "outcome": "does-not-open"},
    ]

    return {
        "_source": "generated by scripts/malive-vectors.py in MeshCore-lou; do not edit",
        "_doc": "docs/mqtt-control.md, Announcing; src/helpers/MeshAliveLogic.h",
        "constants": {
            "kind": KIND, "payload_bytes": PAYLOAD, "sealed_bytes": SEALED, "tag_bytes": TAG,
            "signed_bytes": SIGNED, "signature_bytes": SIG, "label_signature": "mcc3/ann|",
            "max_version": MAX_VERSION, "max_name": MAX_NAME,
            "label_owner_tag": "mcc3/own|", "label_malive": "mcc3/malive/",
            "kind_seen": KIND_SEEN, "seen_bytes": PAYLOAD + 3, "seen_base64url_chars": len(b64(bytes(PAYLOAD + 3))),
            "via": {"zero_hop": 0, "direct": 1, "flood": 2}, "seen_queue": 8, "seen_gap_seconds": 2,
            "seen_again_after_seconds": 600,
            "state_bytes": 167, "ack_bytes": 41, "path_ack_bytes": 55, "kind_path_ack": 0x4B,
            "control_state": 0xA0, "control_ack": 0xB0, "report_id": "the signature's first 4 bytes",
            "interval_seconds": 82800, "interval_spread_seconds": 8280,
        },
        "keys": {
            "seeds": seeds,
            "public": {k: up(v) for k, v in pub.items()},
            "shared_node_owner": up(s_node),
            "shared_catcher_owner": up(s_catcher),
            "k_malive_node": up(k_malive),
            "k_malive_catcher": up(k_malive_catcher),
        },
        "announces": announces,
        "seen": seen_entries,
        "packets": packets,
        "guest_forwards": guest_forwards,
        "refusals": refusals,
    }


def c_str(value):
    """A C string literal holding the UTF-8 bytes, octal escapes for anything not plain."""
    out = []
    for b in value.encode("utf-8"):
        if 0x20 <= b < 0x7F and b not in (0x22, 0x5C, 0x3F):
            out.append(chr(b))
        else:
            out.append("\\%03o" % b)
    return '"' + "".join(out) + '"'


def row(*fields):
    return "  { " + ", ".join(fields) + " },"


def render(d):
    k = d["keys"]
    lines = [
        "// Generated by scripts/malive-vectors.py from test/data/malive-vectors.json. Do not edit.",
        "#pragma once",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "struct MAliveVecAnnounce { const char* name; const char* node; uint32_t boot, sequence, uptime, "
        "clock, last_counter; uint8_t flags; uint16_t battery_mv; const char* version; "
        "const char* name_field; const char* opened_version; const char* opened_name; "
        "const char* owner_tag; const char* nonce; const char* plaintext; const char* signed_bytes; "
        "const char* signature; const char* payload; };",
        "struct MAliveVecSeen { const char* name; const char* announce; const char* topic; int snr; "
        "uint8_t hops; uint8_t via; size_t bytes; const char* payload; };",
        "struct MAliveVecPacket { const char* name; const char* kind; bool named; uint8_t path_len; "
        "const char* path; size_t bytes; const char* payload; };",
        "struct MAliveVecGuest { const char* name; const char* k_gfwd; uint32_t counter, expiry; const char* body; "
        "const char* nonce; size_t bytes; const char* payload; const char* result_nonce; const char* result; };",
        "struct MAliveVecRefusal { const char* name; const char* input; const char* outcome; };",
        "",
    ]
    for name in ("owner", "node", "catcher", "other_owner"):
        lines.append("static const char* const MALIVE_SEED_%s = %s;" % (name.upper(), c_str(k["seeds"][name])))
        lines.append("static const char* const MALIVE_PUB_%s = %s;" % (name.upper(), c_str(k["public"][name])))
    for name in ("shared_node_owner", "shared_catcher_owner", "k_malive_node", "k_malive_catcher"):
        lines.append("static const char* const MALIVE_%s = %s;" % (name.upper(), c_str(k[name])))
    lines.append("")

    lines.append("static const MAliveVecAnnounce MALIVE_ANNOUNCES[] = {")
    for v in d["announces"]:
        f, o = v["fields"], v["opened"]
        lines.append(row(c_str(v["name"]), c_str(v["node"]),
                         *("%uu" % f[n] for n in ("boot", "sequence", "uptime", "clock", "last_counter")),
                         str(f["flags"]), str(f["battery_mv"]), c_str(f["version"]), c_str(f["name"]),
                         c_str(o["version"]), c_str(o["name"]), c_str(v["owner_tag"]), c_str(v["nonce"]),
                         c_str(v["plaintext"]), c_str(v["signed"]), c_str(v["signature"]), c_str(v["payload"])))
    lines.append("};")

    lines.append("static const MAliveVecSeen MALIVE_SEEN[] = {")
    for v in d["seen"]:
        o = v["opened"]
        lines.append(row(c_str(v["name"]), c_str(v["announce"]), c_str(v["topic"]), str(o["snr"]), str(o["hops"]),
                         str(o["via"]), str(v["bytes"]), c_str(v["payload"])))
    lines.append("};")

    lines.append("static const MAliveVecPacket MALIVE_PACKETS[] = {")
    for v in d["packets"]:
        lines.append(row(c_str(v["name"]), c_str(v["kind"]), "true" if v["named"] else "false", str(v["path_len"]),
                         c_str(v["path"]), str(v["bytes"]), c_str(v["payload"])))
    lines.append("};")

    lines.append("static const MAliveVecGuest MALIVE_GUESTS[] = {")
    for v in d["guest_forwards"]:
        f = v["fields"]
        lines.append(row(c_str(v["name"]), c_str(v["k_gfwd"]), "%uu" % f["counter"], "%uu" % f["expiry"],
                         c_str(f["body"]), c_str(v["nonce"]), str(v["bytes"]), c_str(v["payload"]),
                         c_str(v["result"]["nonce"]), c_str(v["result"]["payload"])))
    lines.append("};")

    lines.append("static const MAliveVecRefusal MALIVE_REFUSALS[] = {")
    for v in d["refusals"]:
        lines.append(row(c_str(v["name"]), c_str(v["input"]), c_str(v["outcome"])))
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def main():
    check = "--check" in sys.argv[1:]
    try:
        text = json.dumps(generate(), indent=1, ensure_ascii=False) + "\n"
    except ImportError:
        if not check:
            print("the `cryptography` package is needed to make the vectors", file=sys.stderr)
            return 1
        text = None
    if check:
        stale = [p for p, want in ((SOURCE, text), (HEADER, None)) if not p.exists()
                 or (want is not None and p.read_text() != want)]
        if not stale and HEADER.read_text() != render(json.loads(SOURCE.read_bytes())):
            stale.append(HEADER)
        for p in stale:
            print("%s is stale: run scripts/malive-vectors.py" % p.relative_to(ROOT), file=sys.stderr)
        if not stale:
            print("announce vectors: up to date%s" % ("" if text else " (header only: no `cryptography`)"))
        return 1 if stale else 0
    SOURCE.write_text(text)
    HEADER.write_text(render(json.loads(text)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
