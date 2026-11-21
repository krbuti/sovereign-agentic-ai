"""Key-rotation coverage checker + derived-copy inventory + crypto-shredding.

Simulates envelope encryption across every store that holds source data OR a
derived copy (chunks, embeddings, vector index, search index, semantic cache,
traces, backups). Encodes the runbook rules:

  R1  Rotation creates a new ACTIVE key version; previous becomes ARCHIVED.
      New writes use ACTIVE; ARCHIVED versions still decrypt old data.
      (AWS KMS automatic/on-demand rotation keeps all old backing material and
      does NOT re-encrypt data; Salesforce Shield archives old tenant secrets.)
  R2  Re-encryption ("sync") is an explicit background job, per store.
  R3  A version may be DESTROYED only when coverage of that version is 0 objects
      across ALL stores, including derived copies and backups (Shield: "Don't
      destroy any of them until you synchronize the data they encrypt").
  R4  Cap on active+archived versions (Shield: 50 per type) -> forces sync.
  R5  Rotation frequency limit (Shield: 24h prod for fields/files; 7 days for
      search index) -> configurable per store class.
  R6  Crypto-shredding: each source document gets its own DEK; every derived
      copy of that doc is encrypted under the SAME doc DEK (wrapped by the KEK).
      Destroying the doc DEK renders all copies unreadable; the inventory then
      verifies that no copy exists that was NOT under the doc DEK (e.g. a
      plaintext search index term list), which must be physically deleted.

The cipher is a TOY (HMAC-SHA256 counter keystream + HMAC tag) so the
simulation actually decrypts/re-encrypts with stdlib only. NOT for production;
use AWS KMS / Cloud KMS + AES-GCM (e.g. AWS Encryption SDK, Tink).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

# ------------------------------- toy AEAD ---------------------------------- #


def _ks(key: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return out[:n]


def seal(key: bytes, pt: bytes, aad: bytes = b"") -> bytes:
    nonce = secrets.token_bytes(12)
    ct = bytes(a ^ b for a, b in zip(pt, _ks(key, nonce, len(pt))))
    tag = hmac.new(key, nonce + aad + ct, hashlib.sha256).digest()[:16]
    return nonce + ct + tag


def open_(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    if not hmac.compare_digest(tag, hmac.new(key, nonce + aad + ct, hashlib.sha256).digest()[:16]):
        raise ValueError("auth failed")
    return bytes(a ^ b for a, b in zip(ct, _ks(key, nonce, len(ct))))


# ------------------------------ key ring ----------------------------------- #
class KeyError_(Exception):
    pass


@dataclass
class KeyVersion:
    version: int
    material: bytes | None
    state: str = "ACTIVE"            # ACTIVE | ARCHIVED | DESTROYED
    created_h: float = 0.0


class KeyRing:
    """A customer-managed KEK (think: one KMS key / one Shield tenant-secret type)."""

    def __init__(self, name: str, max_versions: int = 50, min_rotation_h: float = 24):
        self.name, self.max_versions, self.min_rotation_h = name, max_versions, min_rotation_h
        self.versions: dict[int, KeyVersion] = {1: KeyVersion(1, secrets.token_bytes(32))}
        self.clock_h = 0.0

    @property
    def active(self) -> KeyVersion:
        return next(v for v in self.versions.values() if v.state == "ACTIVE")

    def undestroyed(self) -> int:
        return sum(1 for v in self.versions.values() if v.state != "DESTROYED")

    def rotate(self) -> int:
        if self.clock_h - self.active.created_h < self.min_rotation_h:
            raise KeyError_(f"R5: rotation too frequent (<{self.min_rotation_h}h)")
        if self.undestroyed() >= self.max_versions:
            raise KeyError_("R4: version cap reached - sync and destroy old versions first")
        self.active.state = "ARCHIVED"
        n = max(self.versions) + 1
        self.versions[n] = KeyVersion(n, secrets.token_bytes(32), "ACTIVE", self.clock_h)
        return n

    def material(self, version: int) -> bytes:
        v = self.versions[version]
        if v.state == "DESTROYED" or v.material is None:
            raise KeyError_(f"version {version} destroyed - data unrecoverable")
        return v.material


# --------------------------- stores & inventory ---------------------------- #
@dataclass
class StoredObject:
    obj_id: str
    store: str
    source_doc: str
    region: str
    kek_version: int                  # version of KEK that wraps the DEK
    wrapped_dek: bytes | None         # None => object NOT under a per-doc DEK (risk)
    blob: bytes


@dataclass
class Platform:
    kek: KeyRing
    allowed_regions: frozenset = frozenset({"eu-central-1", "eu-west-1", "europe-west3"})
    objects: dict[str, StoredObject] = field(default_factory=dict)
    doc_deks: dict[str, tuple[int, bytes]] = field(default_factory=dict)   # doc -> (kekver, wrapped)

    # -- write path ---------------------------------------------------------
    def _doc_dek(self, doc: str) -> bytes:
        if doc not in self.doc_deks:
            dek = secrets.token_bytes(32)
            av = self.kek.active
            self.doc_deks[doc] = (av.version, seal(av.material, dek, doc.encode()))
        ver, wrapped = self.doc_deks[doc]
        return open_(self.kek.material(ver), wrapped, doc.encode())

    def write(self, obj_id: str, store: str, doc: str, data: bytes, region: str,
              under_doc_dek: bool = True) -> None:
        if region not in self.allowed_regions:
            raise ValueError(f"residency: {region} not allowed")
        av = self.kek.active
        if under_doc_dek:
            dek = self._doc_dek(doc)
            blob, wrapped = seal(dek, data, obj_id.encode()), self.doc_deks[doc][1]
            ver = self.doc_deks[doc][0]
        else:   # e.g. a managed index that only supports service-level CMEK
            blob, wrapped, ver = seal(av.material, data, obj_id.encode()), None, av.version
        self.objects[obj_id] = StoredObject(obj_id, store, doc, region, ver, wrapped, blob)

    def read(self, obj_id: str) -> bytes:
        o = self.objects[obj_id]
        if o.wrapped_dek is None:
            return open_(self.kek.material(o.kek_version), o.blob, obj_id.encode())
        if o.source_doc not in self.doc_deks:
            raise KeyError_("doc DEK shredded - unrecoverable")
        return open_(self._doc_dek(o.source_doc), o.blob, obj_id.encode())

    # -- coverage & sync ----------------------------------------------------
    def coverage(self) -> dict:
        av = self.kek.active.version
        per_store: dict[str, dict[str, int]] = {}
        by_version: dict[int, int] = {}
        shredded = 0
        for o in self.objects.values():
            if o.wrapped_dek is not None and o.source_doc not in self.doc_deks:
                shredded += 1                   # ciphertext with no key: excluded
                continue
            ver = self.doc_deks[o.source_doc][0] if o.wrapped_dek is not None else o.kek_version
            s = per_store.setdefault(o.store, {"total": 0, "active": 0})
            s["total"] += 1
            s["active"] += int(ver == av)
            by_version[ver] = by_version.get(ver, 0) + 1
        total = sum(s["total"] for s in per_store.values())
        act = sum(s["active"] for s in per_store.values())
        return {"active_version": av, "pct_active": round(100 * act / total, 1) if total else 100.0,
                "per_store": per_store, "objects_by_version": by_version,
                "shredded_ciphertexts": shredded}

    def sync(self, batch: int = 10**9) -> int:
        """Background re-encryption: re-wrap doc DEKs (cheap) and re-seal
        service-level objects (expensive) under the ACTIVE KEK version."""
        av, n = self.kek.active, 0
        for doc, (ver, wrapped) in list(self.doc_deks.items()):
            if n >= batch:
                break
            if ver != av.version:
                dek = open_(self.kek.material(ver), wrapped, doc.encode())
                self.doc_deks[doc] = (av.version, seal(av.material, dek, doc.encode()))
                n += 1
        for o in self.objects.values():
            if n >= batch:
                break
            if o.wrapped_dek is None and o.kek_version != av.version:
                pt = open_(self.kek.material(o.kek_version), o.blob, o.obj_id.encode())
                o.blob, o.kek_version = seal(av.material, pt, o.obj_id.encode()), av.version
                n += 1
        for o in self.objects.values():          # keep metadata consistent
            if o.wrapped_dek is not None and o.source_doc in self.doc_deks:
                o.kek_version, o.wrapped_dek = self.doc_deks[o.source_doc]
        return n

    def destroy_version(self, version: int) -> None:
        v = self.kek.versions[version]
        if v.state == "ACTIVE":
            raise KeyError_("cannot destroy ACTIVE version")
        remaining = self.coverage()["objects_by_version"].get(version, 0)
        if remaining:
            raise KeyError_(f"R3: BLOCKED - {remaining} objects still under v{version}; run sync")
        v.state, v.material = "DESTROYED", None

    # -- crypto-shred -------------------------------------------------------
    def crypto_shred(self, doc: str) -> dict:
        copies = [o for o in self.objects.values() if o.source_doc == doc]
        not_under_dek = [o.obj_id for o in copies if o.wrapped_dek is None]
        self.doc_deks.pop(doc, None)                      # destroy the per-doc DEK
        for oid in not_under_dek:                         # must be physically deleted
            del self.objects[oid]
        unreadable = []
        for o in [o for o in self.objects.values() if o.source_doc == doc]:
            try:
                self.read(o.obj_id)
            except KeyError_:
                unreadable.append(o.obj_id)
        return {"doc": doc, "copies_found": len(copies),
                "shredded_via_dek": sorted(unreadable),
                "physically_deleted": sorted(not_under_dek),
                "stores": sorted({o.store for o in copies})}


def demo() -> None:
    kek = KeyRing("kms/eng-qa-kek", max_versions=3, min_rotation_h=24)
    p = Platform(kek)
    for i in range(4):
        d = f"sop-{i}"
        p.write(f"{d}/src", "s3_source", d, b"SOP text", "eu-central-1")
        p.write(f"{d}/chunk0", "chunks", d, b"chunk", "eu-central-1")
        p.write(f"{d}/emb0", "vector_index", d, b"\x00\x01", "eu-central-1")
        p.write(f"{d}/bkp", "backup", d, b"SOP text", "eu-west-1")
    p.write("sop-0/terms", "search_index", "sop-0", b"etch bath HF", "eu-central-1",
            under_doc_dek=False)
    print("initial   :", p.coverage())
    kek.clock_h = 25
    print("rotated to v", kek.rotate())
    print("after rot :", p.coverage()["pct_active"], "% on active (no auto re-encrypt)")
    try:
        p.destroy_version(1)
    except KeyError_ as e:
        print("destroy v1:", e)
    p.sync(batch=2)
    print("partial   :", p.coverage()["pct_active"], "%")
    p.sync()
    print("full sync :", p.coverage()["pct_active"], "%")
    p.destroy_version(1)
    print("destroy v1: OK; states =", {v: k.state for v, k in kek.versions.items()})
    print("read ok   :", p.read("sop-1/chunk0"))
    print("shred     :", p.crypto_shred("sop-0"))


if __name__ == "__main__":
    demo()
