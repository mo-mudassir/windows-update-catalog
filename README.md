# Windows update catalog

A release catalog of Windows client updates, rebuilt on a schedule from Microsoft's public sources and published as a static file. It has:

- **`releases`:** every Windows 10 and 11 version back to 1507, with support end dates. A version Microsoft marks "End of updates" without a date takes the date of its last security update, marked `end_estimated`.
- **`builds`:** every build Microsoft Learn lists for every version, with its KB, date and type (security, preview, out-of-band, hotpatch). Entries are never removed.
- **`insider`:** every Windows Insider flight on Flight Hub, with its release, channels and dates. Entries are never removed, so flights stay known after they leave the page.
- **`cycles`:** the last 12 monthly security releases, with each version's KB and target build, previews, out-of-band and hotpatch fixes, and the CVEs each KB fixes.

The data comes only from public Microsoft pages:

- [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) and [Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information) on Microsoft Learn
- [Flight Hub](https://learn.microsoft.com/en-us/windows-insider/flight-hub/) for Windows Insider builds
- The [MSRC security update API](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/index)

## Using it

Read [`manifest.json`](manifest.json). It names the current catalog file and its SHA-256 checksum:

```
https://raw.githubusercontent.com/mo-mudassir/windows-update-catalog/main/manifest.json
```

Download the file in `catalog_url` (relative to the manifest), check that its SHA-256 matches `sha256`, and check `schema` before using it. Each published file is never changed. A new version gets a new file name.

## How it is built

- **Build catalog** runs every 6 hours, and hourly on days 8 to 16 of each month, which cover Patch Tuesday and the days after it. It runs `tool/catalog_update.py`, which checks that every supported version is present, that builds are higher than the month before, and that MSRC agrees on each KB and build.
- When every check passes and the content changed, `tool/publish.py` writes a new `catalog/catalog-<version>.json` and updates `manifest.json`. A run that finds nothing new publishes nothing.
- When a check fails, nothing is published. The job opens a pull request labelled `catalog-review` with the proposed catalog and the reasons. A person checks them against Microsoft's sources. Merging publishes it, and closing the pull request rejects it.

## Rollback

Point `catalog_url` and `sha256` in `manifest.json` back at an earlier file in `catalog/`, and commit.

## Scope

This repository holds public Microsoft data and the scripts that read it. It holds no device or customer data.
