"""Publish tool/release_catalog.json for the dashboards: catalog/catalog-<version>.json and manifest.json.

A new version is written when the catalog content changed, or when the published one was last checked RECHECK_DAYS or
more ago. A run that only moves checked_utc forward otherwise keeps the current version, so the repository does not
grow on every scheduled check. Dashboards read the check time from the catalog they install and warn after 7 days
(catalog_max_age_days), so without the second rule a month with no changes would look unchecked. Standard library only.

  python3 tool/publish.py          publish if changed; prints the result
"""
import datetime as dt, hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "tool" / "release_catalog.json"
OUT = ROOT / "catalog"
MANIFEST = ROOT / "manifest.json"
RECHECK_DAYS = 3


def content_key(cat):
    """Everything except the check time, so a run that found nothing new is not a new version."""
    return hashlib.sha256(json.dumps({k: v for k, v in cat.items() if k != "checked_utc"}, sort_keys=True).encode()).hexdigest()


def main():
    cat = json.loads(SRC.read_text())
    if cat.get("stale") or cat.get("problems"):
        print("Not published: the catalog is marked stale or has open problems."); return 1
    old = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    key = content_key(cat)
    def when(s): return dt.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    checked, published = when(cat.get("checked_utc")), when(old.get("checked_utc"))
    recheck = bool(checked and published and checked - published >= dt.timedelta(days=RECHECK_DAYS))
    if old.get("content_key") == key and not recheck:
        print(f"Unchanged: version {old.get('version')} is current."); return 0
    version = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%MZ")
    body = (json.dumps(cat, indent=2) + "\n").encode()
    OUT.mkdir(exist_ok=True)
    name = f"catalog-{version}.json"
    (OUT / name).write_bytes(body)
    manifest = dict(schema=cat.get("schema"), version=version, current_cycle=cat["current_cycle"], checked_utc=cat.get("checked_utc"),
                    catalog_url=f"catalog/{name}", sha256=hashlib.sha256(body).hexdigest(), content_key=key,
                    previous=old.get("catalog_url"))
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Published {name} (cycle {cat['current_cycle']})."); return 0


if __name__ == "__main__":
    sys.exit(main())
