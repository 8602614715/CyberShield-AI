import re

import tldextract

from app.core.constants import (
    DOMAIN_PATTERN,
    EMAIL_PATTERN,
    PHONE_PATTERN,
    UPI_PATTERN,
)


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = value.strip()
        lowered = normalized.lower()
        if normalized and lowered not in seen:
            seen.add(lowered)
            output.append(normalized)
    return output


def extract_entities(text: str, url: str = "", analyst_notes: str = "") -> dict:
    source = " ".join(part for part in [text, url, analyst_notes] if part).strip()
    lowered = source.lower()
    phones = unique_preserve_order(
        [match.group(0).replace(" ", "").replace("-", "") for match in PHONE_PATTERN.finditer(source)]
    )
    emails = unique_preserve_order([match.group(0).lower() for match in EMAIL_PATTERN.finditer(source)])
    upi_ids = unique_preserve_order([match.group(0).lower() for match in UPI_PATTERN.finditer(source)])
    urls = unique_preserve_order(
        re.findall(r"(https?://[^\s]+|www\.[^\s]+)", source, flags=re.IGNORECASE)
    )
    domains = []
    for candidate in urls + re.findall(DOMAIN_PATTERN, source):
        extracted = tldextract.extract(
            candidate if candidate.startswith("http") else f"http://{candidate}"
        )
        if extracted.domain and extracted.suffix:
            domains.append(f"{extracted.domain.lower()}.{extracted.suffix.lower()}")
    domains = unique_preserve_order(domains)

    keywords = []
    for keyword in [
        "otp",
        "password",
        "verify",
        "bank",
        "account",
        "loan",
        "upi",
        "wallet",
        "job",
        "gift",
        "click",
    ]:
        if keyword in lowered:
            keywords.append(keyword)

    entity_summary = {
        "phones": phones,
        "emails": emails,
        "upi_ids": upi_ids,
        "urls": urls,
        "domains": domains,
        "keywords": unique_preserve_order(keywords),
    }
    flat_entities = [
        *[f"phone:{value.lower()}" for value in phones],
        *[f"email:{value.lower()}" for value in emails],
        *[f"upi:{value.lower()}" for value in upi_ids],
        *[f"url:{value.lower()}" for value in urls],
        *[f"domain:{value.lower()}" for value in domains],
        *[f"keyword:{value.lower()}" for value in entity_summary["keywords"]],
    ]

    return {
        "entity_summary": entity_summary,
        "entities_flat": unique_preserve_order(flat_entities),
    }
