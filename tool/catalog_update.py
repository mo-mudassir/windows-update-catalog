"""Refresh app/release_catalog.json from Microsoft's public pages. Standard library only.

Sources (public, no sign-in):
  - Microsoft Learn release information for Windows 11 and Windows 10: versions, support dates,
    every monthly security (B), preview (D) and out-of-band (OOB) build and KB, and the hotpatch calendar.
  - MSRC security update API: cross-checks each security release (KB and build) and lists the CVEs each KB fixes.

  python3 tool/catalog_update.py              update if not checked in the past day
  python3 tool/catalog_update.py --force      fetch now
  python3 tool/catalog_update.py --check      show what would change, write nothing
  python3 tool/catalog_update.py --scheduled  as --force, then rebuild the share zip and notify (used by the schedule)
  python3 tool/catalog_update.py --install-schedule | --remove-schedule   daily check on this Mac (launchd)

Rules:
  - Version entries (build, name, support dates) are never deleted. Out-of-support versions stay, so devices
    on them are still named and flagged.
  - Monthly entries (KBs, target builds, previews, out-of-band fixes, CVEs) are kept for the last 12 released cycles.
  - Out-of-band fixes keep their build revision (oob_revs) and release date (oob_dates) per version. Hotpatch
    out-of-band fixes (hotpatch_oob) are not in the Learn tables, so their builds (hotpatch_oob_revs) and date are
    read once from the public Microsoft Support KB article title.
  - Each month also keeps kb_builds (every KB and the builds it applies to), and servicing_siblings lists versions
    that share a KB. A version with no Patch Tuesday entry in a month takes a sibling's target (queries.py).
  - A new security release is published only when every check passes (all supported versions present,
    builds higher than the month before, MSRC agrees on KB and build). Otherwise the proposal is written to
    app/release_catalog.pending.json with the reasons, and the current catalog is left unchanged.
"""
import argparse, datetime as dt, html, json, os, pathlib, re, subprocess, sys, urllib.request

APP = pathlib.Path(__file__).resolve().parent; ROOT = APP.parent
CAT_PATH = APP / "release_catalog.json"; PENDING = APP / "release_catalog.pending.json"
LEARN = {"11": "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
         "10": "https://learn.microsoft.com/en-us/windows/release-health/release-information"}
MSRC = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{}"
KEEP_MONTHS = json.loads((APP / "settings.json").read_text()).get("catalog", {}).get("retained_cycles", 12)
PLIST = pathlib.Path.home() / "Library" / "LaunchAgents" / "io.github.windows-update-catalog.plist"
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def fetch(url, accept="text/html", timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (windows-update-dashboard catalog)", "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def cells(row):
    return [re.sub(r"\s+", " ", html.unescape(re.sub(r"<.*?>", "", c))).strip() for c in re.findall(r"<t[dh][^>]*>.*?</t[dh]>", row, re.S)]


def tables(page):
    """[(position, rows)] for every table on the page."""
    return [(m.start(), [cells(r) for r in re.findall(r"<tr.*?</tr>", m.group(0), re.S)]) for m in re.finditer(r"<table.*?</table>", page, re.S)]


def headings(page):
    return [(m.start(), m.group(1), m.group(2)) for m in re.finditer(r"<strong>Version ([^<(]+?)(?: \(RTM\))? \(OS build (\d+)\)</strong>", page)]


def ended_bases(page):
    """Versions whose history heading says "End of updates", for example "Version 1903 (OS build 18362) - End of updates"."""
    return set(re.findall(r"<strong>Version [^<]+?\(OS build (\d+)\)</strong>\s*-\s*End of updates", page))


def date_or_none(s):
    m = re.search(r"\d{4}-\d{2}-\d{2}", s or "")
    return m.group(0) if m else None


def parse_learn(os_major, page):
    """Return versions {base: {...}}, rows [(base, type, month, date, rev, kb)], version_names {token: base}."""
    heads = headings(page); tabs = tables(page)
    hot_at = page.find("hotpatch calendar")
    token_base = {tok.strip(): base for _, tok, base in heads}
    versions, rows = {}, []
    for pos, rs in tabs:
        if not rs: continue
        hdr = rs[0]
        if hdr and hdr[0] == "Version" and len(hdr) >= 5:                       # current versions / LTSC tables
            ltsc = "Mainstream" in hdr[3]
            for r in rs[1:]:
                if len(r) < 5: continue
                tok = re.sub(r"\d$", "", r[0].split("(")[-1].rstrip(")").strip()) if "(" in r[0] else re.sub(r"(\d{2}H\d)\d$", r"\1", r[0])
                base = token_base.get(tok) or token_base.get(r[0])
                latest = (r[-1] or "").split(".")[0]
                base = base or (latest if latest.isdigit() else None)
                if not base: continue
                v = versions.setdefault(base, {})
                if ltsc:
                    v["ltsc_edition"] = dict(label=("11 LTSC " if os_major == "11" else "10 LTSC ") + (r[0].split()[0] if r[0][:4].isdigit() else "2024"),
                                             available=date_or_none(r[2]), mainstream=date_or_none(r[3]), extended=date_or_none(r[4]),
                                             iot_only="IoT" in r[4] or (os_major == "11"))
                else:
                    v.update(token=tok, available=date_or_none(r[2]), end_pro=date_or_none(r[3]), end_enterprise=date_or_none(r[4]),
                             ended_pro="End of updates" in r[3], ended_ent="End of updates" in r[4])
            continue
        if hdr[:2] == ["Servicing option", "Update type"] or hdr[:2] == ["Month", "Update type"]:
            before = [h for h in heads if h[0] < pos]
            if not before: continue
            base = before[-1][2]; hot = hot_at != -1 and pos > hot_at
            for r in rs[1:]:
                if hot:
                    if len(r) < 6: continue
                    ut, kind, date, build, kb = r[1], r[2], r[3], r[4], r[5]
                    m = re.match(r"(\d{4})\.(\d{2})", ut); typ = "HP" if kind.lower().startswith("hotpatch") else "HPB"
                else:
                    if len(r) < 5: continue
                    ut, date, build, kb = r[1], r[2], r[3], r[4]
                    m = re.match(r"(\d{4})-(\d{2})\s+(\w+)", ut); typ = m.group(3) if m else None
                if not m or not re.fullmatch(r"\d+\.\d+", build or ""): continue
                rows.append((base, typ, f"{m.group(1)}-{m.group(2)}", date_or_none(date), int(build.split(".")[1]), (kb or "").upper()))
    for _, tok, base in heads:
        versions.setdefault(base, {}).setdefault("token", tok.strip())
    for base in ended_bases(page): versions.setdefault(base, {})["ended"] = True
    for paragraph in re.findall(r"<p\b[^>]*>(.*?)</p>", page, re.S):
        text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", paragraph))).strip().lower()
        if "new devices" not in text or not ("not designed as a feature update" in text or "only available on new devices" in text): continue
        match = re.search(r"version\s+(\d{2}h\d)", text)
        base = token_base.get(match.group(1).upper()) if match else None
        if base: versions.setdefault(base, {})["new_devices_only"] = True
    return versions, rows, token_base


def kb_page(kb):
    """(builds, date) from a public Microsoft Support KB article's title, for updates the Learn tables leave out, such
    as hotpatch out-of-band fixes. The title reads like "September 14, 2026 ... KB5129241 (OS Builds 26200.9448 and
    26100.9448) Out-of-band". Returns (builds, date, title); builds and date are None when the page cannot be read or has none."""
    try: page = fetch("https://support.microsoft.com/help/" + "".join(c for c in kb if c.isdigit()))
    except Exception: return None, None, None
    t = re.search(r"<title>(.*?)</title>", page, re.S); t = html.unescape(t.group(1)) if t else ""
    m = re.search(r"OS Builds? ([0-9.,\sand]+)", t); d = re.search(r"([A-Z][a-z]+) (\d{1,2}), (\d{4})", t)
    builds = re.findall(r"\d{5}\.\d+", m.group(1)) if m else []
    date = None
    if d:
        try: date = dt.datetime.strptime(" ".join(d.groups()), "%B %d %Y").date().isoformat()
        except ValueError: pass
    return (builds or None), date, t


def kb_kind(title):
    """What a KB is, from its article title: hotpatch_oob, oob, preview, or other (security releases, .NET, ...)."""
    t = (title or "").lower()
    if "out-of-band" in t: return "hotpatch_oob" if "hotpatch" in t else "oob"
    return "preview" if "preview" in t else "other"


MAX_LOOKUPS = 40                                     # KB pages read per catalog run at most; the rest wait for the next run


def device_kbs():
    """KB numbers this machine's saved snapshots saw installed or present (installs, companions, new_kbs). Only the KB
    numbers are used, to look them up on Microsoft's public pages; no tenant data leaves the machine."""
    out = set()
    for f in (ROOT / "data" / "snapshots").glob("*/*/*.json"):
        if f.stem not in ("installs", "companions", "new_kbs"): continue
        try: rows = json.loads(f.read_text())
        except (OSError, ValueError): continue
        out |= {str(r.get("kb", "")).upper() for r in rows if isinstance(r, dict) and re.fullmatch(r"KB\d{6,8}", str(r.get("kb", "")).upper())}
    return out


def msrc_month(month):
    """{base_token_key: {...}} per Windows product from the MSRC CVRF document for YYYY-MM, or None if unavailable."""
    y, m = month.split("-")
    try:
        d = json.loads(fetch(MSRC.format(f"{y}-{MON[int(m) - 1]}"), accept="application/json", timeout=60))
    except Exception:
        return None
    names = {p["ProductID"]: p["Value"] for p in d.get("ProductTree", {}).get("FullProductName", [])}
    prod = {}                                         # pid -> ("11"|"10"|"server", token)
    for pid, n in names.items():
        mm = re.match(r"Windows (11|10) [Vv]ersion (\w+) for x64-based Systems$", n)
        if mm: prod[pid] = (mm.group(1), mm.group(2))
    fixes, full_fixes, cves, dotnet, client = {}, {}, {}, {}, set()
    for v in d.get("Vulnerability", []):
        cve = v.get("CVE")
        sev = {pid: (t.get("Description") or {}).get("Value", "") for t in v.get("Threats", []) if t.get("Type") == 3 for pid in t.get("ProductID", [])}
        rem_ids = {pid for r in v.get("Remediations", []) for pid in r.get("ProductID", [])}
        flags = {"exploited": {}, "disclosed": {}}
        for t in v.get("Threats", []):
            if t.get("Type") != 1: continue
            text = (t.get("Description") or {}).get("Value", "")
            for field, label in (("exploited", "Exploited"), ("disclosed", "Publicly Disclosed")):
                flag = re.search(re.escape(label) + r":\s*(Yes|No)\b", text, re.I)
                if not flag: continue
                for pid in t.get("ProductID") or rem_ids:
                    value = flag.group(1).lower() == "yes"
                    flags[field][pid] = value if pid not in flags[field] or flags[field][pid] == value else None
        for r in v.get("Remediations", []):
            kb = (r.get("Description") or {}).get("Value", "")
            if not kb.isdigit(): continue
            kb = "KB" + kb
            for pid in r.get("ProductID", []):
                if re.match(r"Windows (11|10) [Vv]ersion ", names.get(pid, "")): client.add(kb)      # any client product: x64, ARM64, 32-bit
                if pid in prod:
                    fb = r.get("FixedBuild") or ""
                    if re.fullmatch(r"10\.0\.\d+\.\d+", fb):
                        fixes.setdefault(prod[pid], set()).add((kb, int(fb.split(".")[3])))
                        full_fixes.setdefault(prod[pid], set()).add((kb, fb))
                    c = cves.setdefault(kb, dict(all=set(), critical=set(), exploited=set(), disclosed=set(), exploited_unknown=set(), disclosed_unknown=set()))
                    c["all"].add(cve)
                    if sev.get(pid) == "Critical": c["critical"].add(cve)
                    for field in flags:
                        if flags[field].get(pid) is True: c[field].add(cve)
                        elif flags[field].get(pid) is None: c[field + "_unknown"].add(cve)
                elif ".NET" in names.get(pid, "") and "Windows 1" in names.get(pid, ""):
                    dotnet[kb] = f".NET Framework {MON[int(m) - 1]} {y} cumulative update"
    return dict(fixes=fixes, full_fixes=full_fixes, cves=cves, dotnet=dotnet, client=client)



def stale_reason(catalog, today=None):
    today = today or dt.date.today()
    grace = json.loads((APP / "settings.json").read_text()).get("catalog", {}).get("publication_grace_days", 2)
    first = today.replace(day=1); patch = first + dt.timedelta(days=(1 - first.weekday()) % 7 + 7)
    required = first if today > patch + dt.timedelta(days=grace) else first - dt.timedelta(days=1)
    month = required.strftime("%Y-%m")
    if month not in catalog.get("cycles", {}):
        return f"The {month} security update is missing after its publication grace period. The release catalog is stale. Run the starter while online."
    return None


def same_as_before(old, month, base, s):
    """A stream already in the catalog with the same KB and target build was accepted before; only new or changed streams need MSRC evidence."""
    p = old.get("cycles", {}).get(month, {}).get("streams", {}).get(base) or {}
    return p.get("kb") == s["kb"] and p.get("target_rev") == s["target_rev"]


UPDATE_TYPE = {"B": "security", "C": "preview", "D": "preview", "OOB": "out-of-band", "HP": "hotpatch", "HPB": "hotpatch baseline", "A": "other", "E": "other"}
FLIGHT_HUB = "https://learn.microsoft.com/en-us/windows-insider/flight-hub/"


def build_index(old, rows):
    """Every build Microsoft Learn lists for every version, never trimmed: "base.rev" -> kb, date, month, type. Entries
    are never deleted, so a build stays known after Microsoft moves it off the page. A security build is not
    overwritten by another row type for the same build."""
    idx = dict(old.get("builds") or {})
    for base, typ, month, date, rev, kb in rows:
        key = f"{base}.{rev}"; cur = idx.get(key)
        if cur and cur.get("type") == "security" and UPDATE_TYPE.get(typ) != "security": continue
        idx[key] = dict(kb=kb or None, date=date, month=month, type=UPDATE_TYPE.get(typ, "other"))
    return dict(sorted(idx.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))))


def insider_flights(old):
    """Windows Insider builds from Flight Hub: "base.rev" -> release, channels {channel: date}, enablement. Builds are
    never deleted, so flights that drop off the page stay known. If Flight Hub can't be read, the old list is kept."""
    flights = json.loads(json.dumps(old.get("insider") or {}))
    try: page = fetch(FLIGHT_HUB)
    except Exception as e:
        print(f"Flight Hub could not be read ({type(e).__name__}); keeping {len(flights)} known Insider builds.")
        return flights
    heads = [(m.start(), re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))).strip())
             for m in re.finditer(r"<h2[^>]*>(.*?)</h2>", page, re.S)]
    for pos, rs in tables(page):
        if not rs or not rs[0] or rs[0][0] != "Build": continue
        head = [h for h in heads if h[0] < pos]
        if not head: continue
        m = re.search(r"Windows (\d+), (?:version )?(.+)$", head[-1][1])
        release = f"{m.group(1)} {m.group(2)}" if m else head[-1][1]
        chans = rs[0][1:]
        for r in rs[1:]:
            cell = (r[0] if r else "").strip()
            build = cell.rstrip("*").strip()
            if not re.fullmatch(r"\d{5}\.\d+", build): continue
            e = flights.setdefault(build, dict(release=release, channels={}))
            e["release"] = release
            if cell.endswith("*"): e["enablement"] = True
            for ch, val in zip(chans, r[1:]):
                if ch and ch != "SDK" and val:
                    try: e["channels"][ch] = dt.datetime.strptime(val.strip(), "%m/%d/%Y").date().isoformat()
                    except ValueError: pass
            if not e["channels"]: del flights[build]
    return dict(sorted(flights.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))))


def build_catalog(old, today):
    pages = {k: fetch(u) for k, u in LEARN.items()}
    versions, rows, tokens, problems = {}, [], {}, []
    for k, p in pages.items():
        v, r, t = parse_learn(k, p)
        versions[k] = v; rows += r; tokens[k] = t
        if not v or not r or not t: problems.append(f"Windows {k}: incomplete Microsoft Learn release data")
    if len(rows) < 30: problems.append(f"only {len(rows)} update rows parsed from Microsoft Learn; the page layout may have changed")

    # ---- versions: update, never delete ----
    rel = json.loads(json.dumps(old.get("releases", {})))
    ltsc = json.loads(json.dumps(old.get("ltsc_in_name", {})))
    for major, vs in versions.items():
        for base, v in vs.items():
            e = rel.setdefault(base, {})
            if v.get("token") and not e.get("name"): e["name"] = f"{major} {v['token']}"
            if v.get("available"): e["available"] = v["available"]
            if v.get("end_pro"): e["end_pro"] = v["end_pro"]
            if v.get("end_enterprise"): e["end_enterprise"] = v["end_enterprise"]
            if v.get("new_devices_only"): e["new_devices_only"] = True
            le = v.get("ltsc_edition")
            if le:
                end = le["mainstream"] or le["extended"]
                entry = ltsc.setdefault(base, {}); entry["name"] = le["label"].replace("LTSC 2016", "LTSB 2016")
                if le["mainstream"] and le["extended"] and le["iot_only"]: entry.update(end=le["mainstream"], iot_end=le["extended"])
                elif le["extended"]: entry["end"] = le["extended"]
                elif end: entry["end"] = end
                if base not in rel or rel[base].get("ltsc") or not rel[base].get("end_enterprise"):   # LTSC build, or its GA edition ended long ago
                    rel.setdefault(base, {}).update(name=entry["name"], ltsc=True, end_enterprise=entry["end"], end_pro=entry["end"])

    # A version Microsoft marks "End of updates" without an end date takes the date of its last security update as its
    # end, marked end_estimated, so it counts as out of support instead of having no support date.
    last_b = {}
    for b_, t_, m_, d_, r_, kb_ in rows:
        if t_ == "B" and d_ and d_ > last_b.get(b_, ""): last_b[b_] = d_
    for major, vs in versions.items():
        for base, v in vs.items():
            e = rel.get(base)
            if not e or not v.get("ended"): continue
            e["ended"] = True
            if not (e.get("end_pro") or e.get("end_enterprise")) and last_b.get(base):
                e.update(end_pro=last_b[base], end_enterprise=last_b[base], end_estimated=True)

    # Comparison eligibility is dashboard policy, not Microsoft hardware or upgrade eligibility.
    for base, r in rel.items():
        if r.get("ltsc") or r.get("new_devices_only"): r["eligible_for_feature"] = False
        else: r.setdefault("eligible_for_feature", str(r.get("name", "")).split(" ", 1)[0] == "11")

    # ---- end of free support: the last Patch Tuesday build on or before each release's end date, and the first build
    # after it (Extended Security Updates where the release has them). From every Learn row, not only kept months.
    for base, e in rel.items():
        end = max(filter(None, [e.get("end_enterprise"), e.get("end_pro")]), default=None)
        if not end: continue
        bs = sorted((d_, r_, kb) for b_, t_, m_, d_, r_, kb in rows if b_ == base and t_ == "B" and d_)
        before = [x for x in bs if x[0] <= end]; after = [x for x in bs if x[0] > end]
        if before: e["final_free_build"], e["final_free_kb"], e["final_free_date"] = f"{base}.{before[-1][1]}", before[-1][2], before[-1][0]
        if after and e.get("esu"): e["esu_from_rev"] = after[0][1]

    # ---- monthly cycles from Learn rows ----
    released = sorted({m for _, t, m, d, _, _ in rows if t == "B" and d and d <= today.isoformat()})
    retained = set(released[-KEEP_MONTHS:])
    cyc = {}
    # Every KB and the builds it applies to, per month, from all Learn rows. A version with only a preview or an
    # out-of-band row this month (for example a release published after Patch Tuesday) has no stream below, but its
    # KB rows stay here, so versions that share a KB (one servicing line, same revision numbers) can be found.
    kbb = {}
    for base, typ, month, date, rev, kb in rows:
        if month in retained and date and date <= today.isoformat() and kb: kbb.setdefault(month, {}).setdefault(kb, set()).add(f"{base}.{rev}")
    for base, typ, month, date, rev, kb in rows:
        if month not in retained or not date or date > today.isoformat(): continue
        c = cyc.setdefault(month, dict(streams={}, release_date=None))
        s = c["streams"].setdefault(base, {})
        if typ == "B":
            s.update(target_rev=rev, kb=kb, date=date)
            c["release_date"] = min(filter(None, [c["release_date"], date]))
        elif typ == "D": s["preview"] = dict(rev=rev, kb=kb, date=date)
        elif typ == "OOB": s.setdefault("oob", []).append(kb); s.setdefault("oob_revs", {})[kb] = rev; s.setdefault("oob_dates", {})[kb] = date
        elif typ in ("HP", "HPB"):
            s["hotpatch"] = dict(rev=rev, kb=kb, date=date, restart=typ == "HPB")
    for month, c in list(cyc.items()):                  # months with no security release yet are not cycles
        c["streams"] = {b: s for b, s in c["streams"].items() if "target_rev" in s}
        if not c["streams"]: del cyc[month]
    for c in cyc.values():                               # hotpatch out-of-band fixes carry the base's OOB KB on hotpatch devices
        for s in c["streams"].values():
            if "oob" in s: s["oob"] = sorted(set(s["oob"]))

    # ---- MSRC cross-check and CVEs ----
    cur = max((m for m, c in cyc.items() if c["release_date"] <= today.isoformat()), default=None)
    if not cur: problems.append("no security release found on Microsoft Learn")
    for month, c in cyc.items():
        ms = msrc_month(month)
        c["cves"] = {}
        if ms is None or not ms.get("fixes") or not ms.get("cves"):
            problems.append(f"MSRC data for {month} is missing or incomplete; its releases cannot be cross-checked")
            continue
        base_of = {}
        for major, t in tokens.items():
            for tok, base in t.items(): base_of[(major, tok)] = base
        full = {}
        for key, fx in ms.get("full_fixes", {}).items():
            if key in base_of: full.setdefault(base_of[key], set()).update(fx)
        expected = dict(old.get("cycles", {}).get(month, {}).get("streams", {})); expected.update(c["streams"])
        if month == cur:
            for base, release in old.get("releases", {}).items():
                end = max(filter(None, [release.get("end_enterprise"), release.get("end_pro")]), default=None)
                if release.get("available", "") > c["release_date"]: continue
                if release.get("esu") or end and end >= c["release_date"]: expected.setdefault(base, None)
        for base in expected:
            s = c["streams"].get(base)
            if not s:
                problems.append(f"{month}: missing expected stream for {rel.get(base, {}).get('name', base)}")
            elif (s["kb"], f"10.0.{base}.{s['target_rev']}") not in full.get(base, set()) and not same_as_before(old, month, base, s):
                problems.append(f"{month} {rel.get(base, {}).get('name', base)}: no MSRC product, KB and full-build evidence for {s['kb']} 10.0.{base}.{s['target_rev']}")
        for kb, v in ms["cves"].items():
            c["cves"][kb] = dict(total=len(v["all"]), all_ids=sorted(v["all"]), critical=len(v["critical"]), exploited=sorted(v["exploited"]), critical_ids=sorted(v["critical"])[:8],
                                  disclosed=sorted(v.get("disclosed", [])), exploited_unknown=sorted(v.get("exploited_unknown", set()) - v["exploited"]), disclosed_unknown=sorted(v.get("disclosed_unknown", set()) - v.get("disclosed", set())))
        c["dotnet"] = ms["dotnet"]; c["msrc_kbs"] = ms["client"]

    # ---- checks on the newest security release ----
    months = sorted(cyc)
    if cur and months.index(cur) > 0:
        prev = cyc[months[months.index(cur) - 1]]
        for base, ps in prev["streams"].items():
            end = max(filter(None, [rel.get(base, {}).get("end_enterprise"), ltsc.get(base, {}).get("end"), ltsc.get(base, {}).get("iot_end")]), default=None)
            still = rel.get(base, {}).get("esu") or (end and end >= cyc[cur]["release_date"])
            if still and base not in cyc[cur]["streams"]:
                problems.append(f"{cur}: no security release found for {rel.get(base, {}).get('name', base)}, which was updated the month before")
            elif base in cyc[cur]["streams"] and cyc[cur]["streams"][base]["target_rev"] <= ps["target_rev"]:
                problems.append(f"{cur}: {rel.get(base, {}).get('name', base)} target build is not higher than the month before")

    # ---- KBs the Learn tables leave out (hotpatch and other out-of-band fixes), found automatically ----
    # Sources, in order: every remediation KB for a Windows client product in each month's MSRC CVRF document, then
    # every KB this machine's snapshots saw on devices. Each new KB is looked up once on its public KB page and
    # classified from the title (kb_kind); results are kept in kb_lookups, so a KB is read only once. Out-of-band fixes
    # are filed under the month whose Patch Tuesday they follow. Hand-added hotpatch_oob entries still apply as overrides.
    known = {k for c in cyc.values() for s in c["streams"].values() for k in [s.get("kb")] + s.get("oob", []) + [(s.get("preview") or {}).get("kb"), (s.get("hotpatch") or {}).get("kb")] if k}
    look = dict(old.get("kb_lookups") or {})
    cand = [(k, "msrc") for m in sorted(cyc) for k in sorted(cyc[m].get("msrc_kbs") or ())] + [(k, "devices") for k in sorted(device_kbs())]
    n_look = 0
    for kb, src in cand:
        if kb in known or kb in look or n_look >= MAX_LOOKUPS: continue
        builds, date, title = kb_page(kb); n_look += 1
        if title is None: continue                      # unreadable now: try again on the next run
        look[kb] = dict(kind=kb_kind(title), builds=builds or [], date=date, source=src)
    rel_ = sorted((c["release_date"], m) for m, c in cyc.items() if c.get("release_date"))
    month_for = lambda d: max([m for r_, m in rel_ if r_ <= d], default=None) if d else None
    for kb, e in look.items():
        m = month_for(e.get("date")); c = cyc.get(m)
        if not c or e.get("kind") not in ("oob", "hotpatch_oob"): continue
        for x in e.get("builds") or []:
            b_, r_ = x.split("."); s = c["streams"].get(b_)
            if not s: continue
            if e["kind"] == "hotpatch_oob":
                s["hotpatch_oob"] = sorted(set(s.get("hotpatch_oob", [])) | {kb}); s.setdefault("hotpatch_oob_revs", {})[kb] = int(r_)
            elif kb not in s.get("oob", []):
                s["oob"] = sorted(set(s.get("oob", [])) | {kb}); s.setdefault("oob_revs", {})[kb] = int(r_)
            if e.get("date"): s.setdefault("oob_dates", {})[kb] = e["date"]
            kbb.setdefault(m, {}).setdefault(kb, set()).add(x)

    # ---- assemble, keeping hand-written names for KBs ----
    out_cycles = {}
    for month in months:
        c = cyc[month]; oc = old.get("cycles", {}).get(month, {})
        for base, s in c["streams"].items():            # keep hand-added fields (hotpatch out-of-band KBs, notes)
            o = oc.get("streams", {}).get(base, {})
            for k in ("hotpatch_oob", "hotpatch_oob_revs", "note"):       # hand-added overrides, kept; found ones are merged in above
                if k in o: s[k] = sorted(set(s.get(k, [])) | set(o[k])) if isinstance(o[k], list) else dict(o[k], **(s.get(k) or {})) if isinstance(o[k], dict) else o[k]
            for k, v in (o.get("oob_dates") or {}).items(): s.setdefault("oob_dates", {}).setdefault(k, v)
            if set(o.get("oob", [])) - set(s.get("oob", [])): s["oob"] = sorted(set(s.get("oob", [])) | set(o["oob"]))
        # Hotpatch out-of-band fixes are not in the Learn tables: their builds and date come from the KB article, once.
        for kb in sorted({k for s in c["streams"].values() for k in s.get("hotpatch_oob", [])}):
            if all(kb in (s.get("hotpatch_oob_revs") or {}) for s in c["streams"].values() if kb in s.get("hotpatch_oob", [])): continue
            builds, date, _ = kb_page(kb)
            for x in builds or []:
                b_, r_ = x.split(".")
                if b_ in c["streams"]:
                    st_ = c["streams"][b_]; st_.setdefault("hotpatch_oob", []); st_["hotpatch_oob"] = sorted(set(st_["hotpatch_oob"]) | {kb})
                    st_.setdefault("hotpatch_oob_revs", {})[kb] = int(r_)
                    if date: st_.setdefault("oob_dates", {})[kb] = date
                kbb.setdefault(month, {}).setdefault(kb, set()).add(x)
        for base, s in c["streams"].items():
            for kb, r_ in (s.get("hotpatch_oob_revs") or {}).items(): kbb.setdefault(month, {}).setdefault(kb, set()).add(f"{base}.{r_}")
        own = {k for s in c["streams"].values() for k in [s["kb"]] + s.get("oob", []) + s.get("hotpatch_oob", [])}
        comp = dict(oc.get("companions", {})); comp.update({k: v for k, v in c.get("dotnet", {}).items() if k not in own})
        comp = {k: v for k, v in comp.items() if k not in {s["kb"] for s in c["streams"].values()}}
        y, m = month.split("-"); mn = MON[int(m) - 1]
        labels = {}
        for base, s in c["streams"].items():
            lb = labels.setdefault(base, {})
            lb[str(s["target_rev"])] = mn
            if "preview" in s: lb[str(s["preview"]["rev"])] = f"{mn} preview"; comp.setdefault(s["preview"]["kb"], f"{mn} {y} optional preview update")
            for kb, r in s.get("oob_revs", {}).items(): lb[str(r)] = f"{mn} OOB"; comp.setdefault(kb, f"{mn} {y} out-of-band fix")
            if "hotpatch" in s:
                hp = s["hotpatch"]; lb.setdefault(str(hp["rev"]), f"{mn} {'baseline' if hp['restart'] else 'hotpatch'}")
                if not hp["restart"]: comp.setdefault(hp["kb"], f"{mn} {y} hotpatch")
        out_cycles[month] = dict(label=f"{month} security update", release_date=c["release_date"], streams=c["streams"],
                                 companions=comp, revision_labels=labels, cves=c.get("cves", {}),
                                 kb_builds={kb: sorted(bs, key=lambda x: -int(x.split(".")[0])) for kb, bs in sorted(kbb.get(month, {}).items())})
    # Shared-KB siblings: versions that got the same KB in any kept month are one servicing line. queries.py uses this
    # to give a version with no Patch Tuesday entry this month the target revision of a sibling that has one.
    sib = {}
    for bs_ in (bs for m in kbb.values() for bs in m.values()):
        bases = {x.split(".")[0] for x in bs_}
        for b in bases: sib.setdefault(b, set()).update(bases - {b})
    new = dict(old)
    new.update(
        _about="Built by tool/catalog_update.py from Microsoft Learn release information and the MSRC security update API. "
               "Version entries are never deleted; monthly entries are kept for the last 12 released cycles. kb_builds lists every KB of a month with the builds it applies to; "
               "servicing_siblings lists versions that share a KB (one servicing line, same revision numbers). Edit feature_target by hand.",
        schema=2, checked_utc=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        current_cycle=cur or old.get("current_cycle"), cycles=out_cycles or old.get("cycles", {}),
        releases=dict(sorted(rel.items(), key=lambda kv: -int(kv[0]))), ltsc_in_name=ltsc,
        kb_lookups=dict(sorted(look.items())),
        servicing_siblings={b: sorted(s, key=lambda x: -int(x)) for b, s in sorted(sib.items(), key=lambda kv: -int(kv[0])) if s},
        builds=build_index(old, rows), insider=insider_flights(old),
        sources=list(LEARN.values()) + [MSRC.format("YYYY-Mon"), FLIGHT_HUB])
    new.setdefault("feature_target", old.get("feature_target"))
    for month, before in old.get("cycles", {}).items():
        after = new.get("cycles", {}).get(month)
        if after is None:
            if len(out_cycles) >= KEEP_MONTHS and month < min(out_cycles): continue
            problems.append(f"{month}: a released cycle disappeared; retain the previous catalog pending review"); continue
        for base in set(before.get("streams", {})) - set(after.get("streams", {})):
            problems.append(f"{month}: stream {base} disappeared")
        for kb, cv in before.get("cves", {}).items():
            fresh = after.get("cves", {}).get(kb)
            if fresh is None: problems.append(f"{month} {kb}: its CVE set disappeared"); continue
            known = set(cv.get("all_ids") or []) | set(cv.get("critical_ids") or []) | set(cv.get("exploited") or [])
            if fresh.get("total", 0) < cv.get("total", 0) or known - set(fresh.get("all_ids") or []):
                problems.append(f"{month} {kb}: previously recorded CVEs disappeared")
    if stale_reason(new, today): problems.append(stale_reason(new, today))
    if problems: new.update(stale=True, checked_utc=old.get("checked_utc"))
    else: new["stale"] = False
    return new, problems


def summarize(old, new):
    out = []
    oc, nc = old.get("cycles", {}), new.get("cycles", {})
    if old.get("current_cycle") != new.get("current_cycle"): out.append(f"current cycle {old.get('current_cycle')} -> {new.get('current_cycle')}")
    for m in sorted(set(nc) - set(oc)): out.append(f"added {m}")
    for m in sorted(set(oc) - set(nc)): out.append(f"removed {m} (outside the last {KEEP_MONTHS} released cycles)")
    for m in sorted(set(oc) & set(nc)):
        for b, s in nc[m]["streams"].items():
            o = oc[m].get("streams", {}).get(b, {})
            if "preview" in s and "preview" not in o: out.append(f"{m} {b}: preview {s['preview']['kb']} ({b}.{s['preview']['rev']})")
            if set(s.get("oob", [])) - set(o.get("oob", [])): out.append(f"{m} {b}: out-of-band " + ", ".join(sorted(set(s["oob"]) - set(o.get("oob", [])))))
            if "hotpatch" in s and "hotpatch" not in o: out.append(f"{m} {b}: hotpatch {s['hotpatch']['kb']}")
        for b in set(nc[m]["streams"]) - set(oc[m].get("streams", {})): out.append(f"{m}: new version {b}")
    for b in sorted(set(new.get("releases", {})) - set(old.get("releases", {}))): out.append(f"new Windows version {b} ({new['releases'][b].get('name')})")
    for b, s in (new.get("servicing_siblings") or {}).items():
        if s != (old.get("servicing_siblings") or {}).get(b): out.append(f"{b} shares updates with " + ", ".join(s))
    return out


def notify(text):
    """A desktop notification on macOS; elsewhere a console line, which the scheduled run writes to data/catalog_update.log."""
    if sys.platform == "darwin":
        subprocess.run(["osascript", "-e", f'display notification {json.dumps(text)} with title "Windows Update dashboard catalog"'], capture_output=True)
    else: print(f"[{dt.datetime.now():%Y-%m-%d %H:%M}] NOTICE: {text}")


def update(force=False, check=False, quiet=False):
    """Returns (status, message). status: 'fresh' | 'updated' | 'unchanged' | 'pending' | 'offline'."""
    old = json.loads(CAT_PATH.read_text())
    last = old.get("checked_utc")
    if not force and not check and not stale_reason(old) and last and dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(last.replace("Z", "+00:00")) < dt.timedelta(hours=20):
        return "fresh", f"catalog checked {last}"
    if not force and not check and not stale_reason(old) and PENDING.exists() and dt.datetime.now().timestamp() - PENDING.stat().st_mtime < 20 * 3600:
        return "pending", f"catalog update still waits for review (proposal in {PENDING.relative_to(ROOT)})"   # don't download again on every start
    if not quiet: print("Checking Microsoft's release information. This can take one or two minutes...", flush=True)
    try:
        new, problems = build_catalog(old, dt.date.today())
    except Exception as e:
        return "offline", f"could not read Microsoft's pages ({type(e).__name__}: {str(e)[:120]}); keeping the catalog from {old.get('checked_utc', 'its last update')}"
    changes = summarize(old, new)
    if check:
        return ("pending" if problems else "unchanged" if not changes else "updated"), "; ".join(problems + changes) or "no changes"
    if problems:
        PENDING.write_text(json.dumps(dict(new, problems=problems), indent=2))
        return "pending", "catalog NOT updated, needs review: " + "; ".join(problems) + f" (proposal in {PENDING.relative_to(ROOT)})"
    if PENDING.exists(): PENDING.unlink()
    CAT_PATH.write_text(json.dumps(new, indent=2) + "\n")
    return ("updated" if changes else "unchanged"), ("; ".join(changes) if changes else "no changes") + f" (checked {new['checked_utc']})"


TASK = "Windows Update dashboard catalog"            # Windows Task Scheduler task name


def install_schedule():
    """Daily catalog check at 10:00 for the current user, no admin rights: Task Scheduler (schtasks) on Windows,
    launchd on macOS. The scheduled run writes its output to data/catalog_update.log."""
    if os.name == "nt":
        log = ROOT / "data" / "catalog_update.log"
        cmd = f'cmd /c ""{sys.executable}" "{APP / "catalog_update.py"}" --scheduled >> "{log}" 2>&1"'
        subprocess.run(["schtasks", "/Create", "/SC", "DAILY", "/ST", "10:00", "/TN", TASK, "/TR", cmd, "/F"], check=True)
        return print(f"Scheduled a daily catalog check at 10:00 (Task Scheduler task '{TASK}'). Remove with --remove-schedule.")
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    PLIST.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.github.windows-update-catalog</string>
<key>ProgramArguments</key><array><string>{sys.executable}</string><string>{APP / 'catalog_update.py'}</string><string>--scheduled</string></array>
<key>StartCalendarInterval</key><dict><key>Hour</key><integer>10</integer><key>Minute</key><integer>0</integer></dict>
<key>StandardOutPath</key><string>{ROOT / 'data' / 'catalog_update.log'}</string>
<key>StandardErrorPath</key><string>{ROOT / 'data' / 'catalog_update.log'}</string>
</dict></plist>
""")
    subprocess.run(["launchctl", "unload", str(PLIST)], capture_output=True)
    subprocess.run(["launchctl", "load", str(PLIST)], check=True)
    print(f"Scheduled a daily catalog check at 10:00 ({PLIST}). Remove with --remove-schedule.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for f in ("force", "check", "scheduled", "install_schedule", "remove_schedule"): ap.add_argument("--" + f.replace("_", "-"), action="store_true")
    a = ap.parse_args()
    if a.install_schedule: return install_schedule()
    if a.remove_schedule:
        if os.name == "nt":
            subprocess.run(["schtasks", "/Delete", "/TN", TASK, "/F"], capture_output=True)
            return print("Schedule removed.")
        subprocess.run(["launchctl", "unload", str(PLIST)], capture_output=True)
        if PLIST.exists(): PLIST.unlink()
        return print("Schedule removed.")
    status, msg = update(force=a.force or a.scheduled, check=a.check)
    print(f"[{dt.datetime.now():%Y-%m-%d %H:%M}] {status}: {msg}")
    if a.scheduled:
        if status == "updated":
            subprocess.run([sys.executable, str(APP / "run.py"), "--share"], check=False)
            notify("Catalog updated and share zip rebuilt: " + msg[:180])
        elif status == "pending":
            notify("Catalog needs review: " + msg[:180])
    return 0 if status != "pending" else 2


if __name__ == "__main__":
    sys.exit(main() or 0)
