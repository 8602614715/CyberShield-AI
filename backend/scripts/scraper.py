"""
Optional data-ingestion script. Run from repo root:
  python -m scripts.scraper
Or from backend/:
  python scripts/scraper.py
"""
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import spacy
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from geopy.geocoders import Nominatim
from pymongo import MongoClient

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))
load_dotenv(BACKEND_ROOT.parent / ".env")

MONGODB_URI = os.environ.get("MONGODB_URI", "")
if not MONGODB_URI:
    raise RuntimeError("Set MONGODB_URI in .env before running the scraper.")

nlp = spacy.load("en_core_web_sm")
geolocator = Nominatim(user_agent="cyberfraud_app", timeout=3)

client = MongoClient(MONGODB_URI)
db = client[os.environ.get("MONGODB_DB_NAME", "cybercrime")]
collection = db["reports"]

location_cache: dict[str, tuple[float, float]] = {}

COMMON_CITIES = [
    "delhi",
    "mumbai",
    "bangalore",
    "chennai",
    "hyderabad",
    "pune",
    "indore",
    "bhopal",
    "kolkata",
    "jaipur",
    "lucknow",
]


def is_valid(title: str) -> bool:
    title = title.lower()
    if len(title) < 20:
        return False
    blocked = ["sign in", "home", "login", "menu"]
    return not any(word in title for word in blocked)


def classify(text: str) -> str:
    text = text.lower()
    if any(x in text for x in ["otp", "password", "bank", "account", "phishing"]):
        return "phishing"
    if any(x in text for x in ["loan", "credit", "finance"]):
        return "finance"
    if any(x in text for x in ["job", "offer", "recruitment"]):
        return "employment"
    if any(x in text for x in ["upi", "payment", "wallet"]):
        return "payment fraud"
    return "other"


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
    doc = nlp(text)
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


def is_duplicate(title: str) -> bool:
    return collection.find_one({"title": title}) is not None


def main() -> None:
    url = "https://news.google.com/search?q=cyber%20fraud"
    response = requests.get(url, timeout=30)
    soup = BeautifulSoup(response.text, "html.parser")
    articles = soup.find_all("a")
    count = 0

    for anchor in articles:
        title = anchor.text.strip()
        if not title or not is_valid(title) or is_duplicate(title):
            continue

        location = extract_location(title)
        lat, lng = get_coordinates(location)
        collection.insert_one(
            {
                "title": title,
                "location": location,
                "lat": lat,
                "lng": lng,
                "type": classify(title),
                "created_at": datetime.now(timezone.utc),
            }
        )
        print(f"Inserted: {title} -> {location}")
        count += 1
        time.sleep(1)

    print(f"Total inserted: {count}")


if __name__ == "__main__":
    main()
