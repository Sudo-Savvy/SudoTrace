import httpx

VT_BASE = "https://www.virustotal.com/api/v3"


async def _vt_get(api_key: str, path: str) -> dict:
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            f"{VT_BASE}/{path}",
            headers={"x-apikey": api_key},
        )
        if resp.status_code == 404:
            return {"not_found": True}
        resp.raise_for_status()
        return resp.json()


def _parse_stats(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(v for k, v in stats.items() if k != "type-unsupported")
    return {"malicious": malicious, "suspicious": suspicious, "total": total}


async def lookup_hash(api_key: str, hash_value: str) -> dict:
    raw = await _vt_get(api_key, f"files/{hash_value}")
    if raw.get("not_found"):
        return {"found": False, "type": "hash", "ioc": hash_value}

    attrs = raw.get("data", {}).get("attributes", {})
    stats = _parse_stats(attrs)

    results = attrs.get("last_analysis_results", {})
    flagged_vendors = [
        f"{vendor}: {r.get('result', '')}"
        for vendor, r in results.items()
        if r.get("category") in ("malicious", "suspicious") and r.get("result")
    ][:5]

    threat_label = (
        attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        or attrs.get("meaningful_name")
    )

    return {
        "found":      True,
        "type":       "hash",
        "ioc":        hash_value,
        "malicious":  stats["malicious"],
        "suspicious": stats["suspicious"],
        "total":      stats["total"],
        "name":       threat_label,
        "vendors":    flagged_vendors,
        "link":       f"https://www.virustotal.com/gui/file/{hash_value}",
    }


async def lookup_domain(api_key: str, domain: str) -> dict:
    raw = await _vt_get(api_key, f"domains/{domain}")
    if raw.get("not_found"):
        return {"found": False, "type": "domain", "ioc": domain}

    attrs = raw.get("data", {}).get("attributes", {})
    stats = _parse_stats(attrs)

    results = attrs.get("last_analysis_results", {})
    flagged_vendors = [
        f"{vendor}: {r.get('result', '')}"
        for vendor, r in results.items()
        if r.get("category") in ("malicious", "suspicious") and r.get("result")
    ][:5]

    # VT returns a dict of {categoriser: category} — join unique values
    raw_cats = attrs.get("categories", {})
    name = ", ".join(sorted(set(raw_cats.values())))[:80] if raw_cats else None

    return {
        "found":      True,
        "type":       "domain",
        "ioc":        domain,
        "malicious":  stats["malicious"],
        "suspicious": stats["suspicious"],
        "total":      stats["total"],
        "name":       name or None,
        "vendors":    flagged_vendors,
        "link":       f"https://www.virustotal.com/gui/domain/{domain}",
    }


async def lookup_ip(api_key: str, ip: str) -> dict:
    raw = await _vt_get(api_key, f"ip_addresses/{ip}")
    if raw.get("not_found"):
        return {"found": False, "type": "ip", "ioc": ip}

    attrs = raw.get("data", {}).get("attributes", {})
    stats = _parse_stats(attrs)

    return {
        "found":      True,
        "type":       "ip",
        "ioc":        ip,
        "malicious":  stats["malicious"],
        "suspicious": stats["suspicious"],
        "total":      stats["total"],
        "country":    attrs.get("country"),
        "asn":        attrs.get("asn"),
        "as_owner":   attrs.get("as_owner"),
        "link":       f"https://www.virustotal.com/gui/ip-address/{ip}",
    }
