#!/usr/bin/env python3
"""Tests of scripts/manifest.py and scripts/release-candidate.sh: the manifests of a release,
the alias manifests of an Observer board's full image, and the candidate check. Every key
here is made for the test; the fixtures under test/data are signed with the host suites'
test key (seed 40..5f), which test_ota_verify verifies them with on the node's side.

    python3 scripts/test_manifest.py          (needs pycryptodome, as signing does)
    UPDATE_FIXTURES=1 python3 scripts/test_manifest.py   after a deliberate change of format
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import manifest  # noqa: E402

ENV = "Heltec_v3_repeater_observer_mqtt"
HASH = "1a2b3c4d"
BASE_URL = "https://github.com/sweden-mesh/MeshCore-lou/releases/download/v1.18.0-lou-21"
TEST_SEED = bytes(range(0x40, 0x60)).hex()
TEST_PUB = "2543B92FF1095511476ADC8369DB6DDC933665A11978DDA1404EE1066CA9559D"
FIXTURE_IMAGE = b"a firmware image, lou-21 arrc\n"


def run(*args, ok=True):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "manifest.py"), *args],
                       capture_output=True, text=True)
    if ok and r.returncode != 0:
        raise AssertionError(f"manifest.py {' '.join(args)}: {r.stdout}{r.stderr}")
    return r


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(path):
    return json.loads(text(path))


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.key = os.path.join(self.d, "test.key")
        run("--keygen", self.key)
        self.pub = run("--pubkey", self.key).stdout.strip()

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.d, name)

    def image(self, features, env=ENV, where=None, rev="lou-21"):
        """An image file as build.sh names it; it carries the key, as a real one does."""
        name = f"{env}-esp32s3-v1.18.0-{rev}-{features}-{HASH}.bin"
        with open(os.path.join(where or self.d, name), "wb") as f:
            f.write(f"image {env} {features} {self.pub}\n".encode())
        return name

    def unsigned(self, features, env=ENV, where=None):
        where = where or self.d
        name = self.image(features, env, where)
        out = os.path.join(where, f"{env}-{features}.unsigned.json")
        run("unsigned", os.path.join(where, name), f"{env}-{features}", features,
            name[len(env) + 1:-len(".bin")], "v1.18.0", "0", self.path("no.partsig"), out)
        return name, out

    def signed(self, unsigned_json, image, out):
        run("sign", unsigned_json, self.path(image), f"{BASE_URL}/{image}", self.key, self.path(out))
        return self.path(out)


class Alias(Case):
    def test_an_alias_takes_the_full_images_version_file_and_hash(self):
        image, full = self.unsigned("arrc")
        out = self.path(f"{ENV}-ar.unsigned.json")
        run("alias", full, "ar", out)
        a, m = load(out), load(full)
        self.assertEqual((a["variant"], a["features"], a["aliasOf"]), (f"{ENV}-ar", "ar", f"{ENV}-arrc"))
        for field in ("version", "baseVersion", "build", "fileName", "sha256", "partSig"):
            self.assertEqual(a[field], m[field])
        self.assertIn("-lou-21-arrc-", a["version"])
        self.assertNotIn("aliasOf", m)

    def test_an_alias_is_signed_over_its_own_names_and_verifies(self):
        from Crypto.Signature import eddsa
        image, full = self.unsigned("arrc")
        for old in ("ar", "rc"):
            run("alias", full, old, self.path(f"{ENV}-{old}.unsigned.json"))
            out = self.signed(self.path(f"{ENV}-{old}.unsigned.json"), image, f"{ENV}-{old}.json")
            self.assertEqual(run("verify", out, self.pub).returncode, 0)
            a = load(out)
            self.assertEqual(a["file"], f"{BASE_URL}/{image}")
            v = eddsa.new(eddsa.import_public_key(bytes.fromhex(self.pub)), "rfc8032")
            v.verify(f"{a['sha256']}|{a['version']}|{a['file']}".encode(), bytes.fromhex(a["sig"]))
            v.verify(f"{a['sha256']}|{a['version']}|{a['file']}|{ENV}-{old}|{old}".encode(),
                     bytes.fromhex(a["sig2"]))
        # The full image's own sig2 is not the alias's: the names are under the signature.
        own = load(self.signed(full, image, f"{ENV}-arrc.json"))
        self.assertNotEqual(own["sig2"], a["sig2"])
        self.assertEqual(own["sig"], a["sig"])

    def test_an_alias_of_anything_but_an_arrc_image_is_refused(self):
        _, ar = self.unsigned("ar")
        r = run("alias", ar, "rc", self.path("x.json"), ok=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.path("x.json")))
        # Written by hand, then: neither signed nor accepted once signed by other means.
        image = self.image("ar")
        m = dict(load(ar), variant=f"{ENV}-rc", features="rc", aliasOf=f"{ENV}-arrc")
        manifest.write(self.path("hand.unsigned.json"), m)
        r = run("sign", self.path("hand.unsigned.json"), self.path(image), f"{BASE_URL}/{image}",
                self.key, self.path("hand.json"), ok=False)
        self.assertIn("is not one", r.stderr)
        self.assertFalse(os.path.exists(self.path("hand.json")))

    def test_an_alias_for_arrc_itself_or_another_combination_is_refused(self):
        _, full = self.unsigned("arrc")
        for features in ("arrc", "as", "asar", "nope"):
            self.assertNotEqual(run("alias", full, features, self.path("x.json"), ok=False).returncode, 0)
        self.assertEqual(manifest.check_names(f"{ENV}-arrc", "arrc", "esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d",
                                              f"{ENV}-arrc"), "an alias is for ar or rc, not arrc")

    def test_an_alias_for_a_core_image_is_refused(self):
        image, full = self.unsigned("arrc", env="RAK_4631_repeater")
        r = run("alias", full, "ar", self.path("x.json"), ok=False)
        self.assertIn("not an Observer image", r.stderr)
        m = dict(load(full), variant="RAK_4631_repeater-ar", features="ar", aliasOf="RAK_4631_repeater-arrc")
        manifest.write(self.path("hand.unsigned.json"), m)
        r = run("sign", self.path("hand.unsigned.json"), self.path(image), f"{BASE_URL}/{image}",
                self.key, self.path("hand.json"), ok=False)
        self.assertIn("not an Observer image", r.stderr)

    def test_an_alias_must_name_the_full_image_of_its_own_board(self):
        self.assertIsNone(manifest.check_names(f"{ENV}-ar", "ar", "esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d",
                                               f"{ENV}-arrc"))
        self.assertIsNotNone(manifest.check_names(f"{ENV}-ar", "ar", "esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d",
                                                  "heltec_v4_repeater_observer_mqtt-arrc"))
        self.assertIsNotNone(manifest.check_names(f"{ENV}-ar", "ar", "esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d", ""))

    def test_the_mark_cannot_be_taken_off_or_put_on_after_signing(self):
        image, full = self.unsigned("arrc")
        run("alias", full, "ar", self.path(f"{ENV}-ar.unsigned.json"))
        a = load(self.signed(self.path(f"{ENV}-ar.unsigned.json"), image, f"{ENV}-ar.json"))
        del a["aliasOf"]
        manifest.write(self.path("stripped.json"), a)
        self.assertEqual(run("verify", self.path("stripped.json"), self.pub, ok=False).returncode, 1)
        own = dict(load(self.signed(full, image, f"{ENV}-arrc.json")), aliasOf=f"{ENV}-arrc")
        manifest.write(self.path("marked.json"), own)
        self.assertEqual(run("verify", self.path("marked.json"), self.pub, ok=False).returncode, 1)


class Real(Case):
    def test_a_real_ar_manifest_of_an_observer_image_still_verifies(self):
        image, ar = self.unsigned("ar")
        out = self.signed(ar, image, f"{ENV}-ar.json")
        self.assertEqual(run("verify", out, self.pub).returncode, 0)
        self.assertNotIn("aliasOf", load(out))
        # and the one an old release holds
        old = os.path.join(ROOT, "test", "data", "manifest-lou-14-example.json")
        self.assertEqual(run("verify", old, TEST_PUB).returncode, 0)

    def test_a_real_manifest_whose_version_names_other_features_is_refused(self):
        name = self.image("arrc")
        r = run("unsigned", self.path(name), f"{ENV}-ar", "ar", name[len(ENV) + 1:-4], "v1.18.0", "0",
                self.path("no.partsig"), self.path("x.json"), ok=False)
        self.assertIn("does not name the features ar", r.stderr)

    def test_the_fixtures_are_what_manifest_py_writes(self):
        """test/data/manifest-lou-21-*.json, which test_ota_verify reads: made again with the
        host suites' test key and compared whole (Ed25519 signs the same bytes the same way)."""
        key = self.path("suite.key")
        with open(key, "w") as f:
            f.write(TEST_SEED + "\n")
        self.assertEqual(run("--pubkey", key).stdout.strip(), TEST_PUB)
        name = f"{ENV}-esp32s3-v1.18.0-lou-21-arrc-{HASH}.bin"
        with open(self.path(name), "wb") as f:
            f.write(FIXTURE_IMAGE)
        full = self.path(f"{ENV}-arrc.unsigned.json")
        run("unsigned", self.path(name), f"{ENV}-arrc", "arrc", name[len(ENV) + 1:-4], "v1.18.0", "0",
            self.path("no.partsig"), full)
        run("alias", full, "ar", self.path(f"{ENV}-ar.unsigned.json"))
        for variant, fixture in ((f"{ENV}-arrc", "manifest-lou-21-example-arrc.json"),
                                 (f"{ENV}-ar", "manifest-lou-21-example-alias-ar.json")):
            run("sign", self.path(f"{variant}.unsigned.json"), self.path(name), f"{BASE_URL}/{name}", key,
                self.path(fixture))
            committed = os.path.join(ROOT, "test", "data", fixture)
            if os.environ.get("UPDATE_FIXTURES"):
                with open(committed, "w") as f:
                    f.write(text(self.path(fixture)))
            self.assertEqual(text(committed), text(self.path(fixture)))
            self.assertEqual(run("verify", committed, TEST_PUB).returncode, 0)


class Release(Case):
    """release-candidate.sh on a candidate as build-matrix.sh leaves one; nothing is uploaded."""

    def candidate(self, aliases=("ar", "rc")):
        cand = self.path("candidate-lou-21")
        os.mkdir(cand)
        _, full = self.unsigned("arrc", where=cand)
        for old in aliases:
            run("alias", full, old, os.path.join(cand, f"{ENV}-{old}.unsigned.json"))
        for features in ("ar", "rc", "arrc"):
            self.image(features, env="RAK_4631_repeater", where=cand)
        self.sums(cand)
        return cand

    def sums(self, cand):
        if os.path.exists(os.path.join(cand, "SHA256SUMS")):
            os.remove(os.path.join(cand, "SHA256SUMS"))
        names = sorted(os.listdir(cand))
        with open(os.path.join(cand, "SHA256SUMS"), "w") as f:
            subprocess.run(["sha256sum", *names], cwd=cand, stdout=f, check=True)

    def release(self, cand):
        return subprocess.run(
            ["bash", os.path.join(ROOT, "scripts", "release-candidate.sh"), "-c", cand, "-t", "v1.18.0-lou-21",
             "-k", self.key, "-o", self.path("release")],
            capture_output=True, text=True, env=dict(os.environ, PYTHON=sys.executable))

    def test_one_observer_image_is_released_with_three_manifests(self):
        r = self.release(self.candidate())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("3 signed manifests, 2 of them aliases", r.stdout)
        out = self.path("release")
        image = f"{ENV}-esp32s3-v1.18.0-lou-21-arrc-{HASH}.bin"
        for features in ("ar", "rc", "arrc"):
            m = load(os.path.join(out, f"{ENV}-{features}.json"))
            self.assertEqual(run("verify", os.path.join(out, f"{ENV}-{features}.json"), self.pub).returncode, 0)
            self.assertEqual((m["fileName"], m["features"]), (image, features))
        self.assertEqual(sorted(n for n in os.listdir(out) if n.endswith(".json")),
                         [f"{ENV}-ar.json", f"{ENV}-arrc.json", f"{ENV}-rc.json", "firmware-index.json"])
        index = os.path.join(out, "firmware-index.json")
        self.assertEqual(run("verify-index", index, self.pub).returncode, 0)
        rows = {r["file"]: r for r in load(index)["images"]}
        self.assertEqual(rows[image]["manifest"], f"{ENV}-arrc.json")
        self.assertEqual(rows[image]["manifests"], [f"{ENV}-arrc.json", f"{ENV}-ar.json", f"{ENV}-rc.json"])
        core = rows[f"RAK_4631_repeater-esp32s3-v1.18.0-lou-21-ar-{HASH}.bin"]
        self.assertEqual((core["manifest"], core["manifests"]), (None, []))
        # a changed list is a changed index: the signature covers it
        doc = load(index)
        doc["images"][0]["manifests"] = ["other.json"]
        manifest.write(self.path("edited.json"), doc)
        self.assertEqual(run("verify-index", self.path("edited.json"), self.pub, ok=False).returncode, 1)

    def test_an_arrc_image_that_leaves_ar_or_rc_nodes_without_a_manifest_is_refused(self):
        r = self.release(self.candidate(aliases=("ar",)))
        self.assertEqual(r.returncode, 1)
        self.assertIn("nothing is offered to its rc nodes", r.stderr)
        self.assertFalse(os.path.exists(self.path("release")))

    def test_all_three_images_of_a_board_need_no_alias(self):
        cand = self.candidate(aliases=())
        for features in ("ar", "rc"):
            self.unsigned(features, where=cand)
        self.sums(cand)
        r = self.release(cand)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("3 signed manifests, 0 of them aliases", r.stdout)

    def test_a_second_manifest_of_its_own_or_a_misnamed_one_is_refused(self):
        cand = self.candidate()
        m = load(os.path.join(cand, f"{ENV}-arrc.unsigned.json"))
        manifest.write(os.path.join(cand, f"{ENV}-copy.unsigned.json"), m)
        self.sums(cand)
        r = self.release(cand)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not the variant it is named for", r.stderr)
        self.assertIn("has 2 manifests of its own", r.stderr)

    def test_a_core_image_has_no_manifest_and_no_alias(self):
        cand = self.candidate()
        name = f"RAK_4631_repeater-esp32s3-v1.18.0-lou-21-arrc-{HASH}.bin"
        m = dict(load(os.path.join(cand, f"{ENV}-ar.unsigned.json")), variant="RAK_4631_repeater-ar",
                 aliasOf="RAK_4631_repeater-arrc", fileName=name,
                 sha256=hashlib.sha256(f"image RAK_4631_repeater arrc {self.pub}\n".encode()).hexdigest())
        manifest.write(os.path.join(cand, "RAK_4631_repeater-ar.unsigned.json"), m)
        self.sums(cand)
        r = self.release(cand)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not an Observer image", r.stderr)

    def test_a_candidate_of_core_images_alone_is_released(self):
        cand = self.path("candidate-lou-21")
        os.mkdir(cand)
        self.image("ar", env="RAK_4631_repeater", where=cand)
        self.sums(cand)
        r = self.release(cand)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 signed manifests, 0 of them aliases", r.stdout)


if __name__ == "__main__":
    unittest.main()
