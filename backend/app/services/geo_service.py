import math

import tldextract

from app.core.constants import COMMON_CITIES, METRO_COORDS
from app.core.nlp import geolocator, get_nlp
from app.db.mongodb import collection

location_cache: dict[str, tuple[float, float]] = {}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * radius_km * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1 - a)))


def normalize_location(loc: str) -> str:
    return loc.lower().strip()


def fast_extract(text: str):
    text = text.lower()
    for city in COMMON_CITIES:
        if city in text:
            return city
    return None


def extract_location(text: str) -> str:
    loc = fast_extract(text)
    if loc:
        return loc

    doc = get_nlp()(text)
    for ent in doc.ents:
        if ent.label_ == "GPE":
            return ent.text.lower()

    return "unknown"


def get_existing_coords(location: str):
    existing = collection.find_one({"location": location})
    if existing and "lat" in existing:
        return (existing["lat"], existing["lng"])
    return None


def get_coordinates(location: str):
    location = normalize_location(location)

    if location in location_cache:
        return location_cache[location]

    db_coords = get_existing_coords(location)
    if db_coords:
        location_cache[location] = db_coords
        return db_coords

    try:
        if location == "unknown":
            coords = (20.5937, 78.9629)
        else:
            geo = geolocator.geocode(location + ", India")
            coords = (geo.latitude, geo.longitude) if geo else (20.5937, 78.9629)

        location_cache[location] = coords
        return coords
    except Exception:
        return (20.5937, 78.9629)


def build_reverse_place_names(lat: float, lon: float) -> list[str]:
    try:
        loc = geolocator.reverse(f"{lat}, {lon}", language="en", timeout=8, addressdetails=True)
        if not loc or not getattr(loc, "raw", None):
            return []
        addr = (loc.raw or {}).get("address") or {}
        ordered_keys = (
            "city",
            "town",
            "village",
            "suburb",
            "neighbourhood",
            "county",
            "state_district",
            "state",
        )
        out: list[str] = []
        seen: set[str] = set()
        for key in ordered_keys:
            val = addr.get(key)
            if isinstance(val, str) and val.strip():
                value = val.strip()
                low = value.lower()
                if low not in seen:
                    seen.add(low)
                    out.append(value)
        return out
    except Exception:
        return []


def geo_suggestions_for_coords(lat: float, lon: float) -> dict:
    reverse_names = build_reverse_place_names(lat, lon)
    metro_ranked = sorted(
        METRO_COORDS.items(),
        key=lambda item: haversine_km(lat, lon, item[1][0], item[1][1]),
    )
    metro_labels = [name.replace("_", " ").title() for name, _ in metro_ranked[:6]]

    combined: list[str] = []
    seen_lower: set[str] = set()
    for name in reverse_names + metro_labels:
        low = name.lower()
        if low not in seen_lower:
            seen_lower.add(low)
            combined.append(name)

    return {
        "suggestions": combined[:14],
        "reverse_geocoded": len(reverse_names) > 0,
    }
