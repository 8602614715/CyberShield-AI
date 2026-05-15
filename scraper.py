import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from datetime import datetime
import spacy
from geopy.geocoders import Nominatim
import time

# -------- INIT --------
nlp = spacy.load("en_core_web_sm")
geolocator = Nominatim(user_agent="cyberfraud_app", timeout=3)

# -------- DB --------
client = MongoClient("mongodb+srv://satyamckt56_db_user:sixmarch2005@cluster0.b7icvyv.mongodb.net/cybercrime?appName=Cluster0")
db = client["cybercrime"]
collection = db["reports"]

# -------- CACHE --------
location_cache = {}

COMMON_CITIES = [
    "delhi", "mumbai", "bangalore", "chennai",
    "hyderabad", "pune", "indore", "bhopal",
    "kolkata", "jaipur", "lucknow"
]

# -------- CLEANING --------
def is_valid(title):
    title = title.lower()

    if len(title) < 20:
        return False

    blocked = ["sign in", "home", "login", "menu"]
    return not any(b in title for b in blocked)

# -------- CLASSIFICATION --------
def classify(text):
    text = text.lower()

    if any(x in text for x in ["otp", "password", "bank", "account", "phishing"]):
        return "phishing"
    elif any(x in text for x in ["loan", "credit", "finance"]):
        return "finance"
    elif any(x in text for x in ["job", "offer", "recruitment"]):
        return "employment"
    elif any(x in text for x in ["upi", "payment", "wallet"]):
        return "payment fraud"
    else:
        return "other"

# -------- NORMALIZE --------
def normalize_location(loc):
    return loc.lower().strip()

# -------- FAST LOCATION --------
def fast_extract(text):
    text = text.lower()
    for city in COMMON_CITIES:
        if city in text:
            return city
    return None

# -------- NLP LOCATION --------
def extract_location(text):
    loc = fast_extract(text)
    if loc:
        return loc

    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ == "GPE":
            return ent.text.lower()

    return "unknown"

# -------- DB CACHE --------
def get_existing_coords(location):
    existing = collection.find_one({"location": location})
    if existing and "lat" in existing:
        return (existing["lat"], existing["lng"])
    return None

# -------- GEO --------
def get_coordinates(location):
    location = normalize_location(location)

    # memory cache
    if location in location_cache:
        return location_cache[location]

    # DB cache
    db_coords = get_existing_coords(location)
    if db_coords:
        location_cache[location] = db_coords
        return db_coords

    try:
        if location == "unknown":
            coords = (20.5937, 78.9629)
        else:
            geo = geolocator.geocode(location + ", India")
            if geo:
                coords = (geo.latitude, geo.longitude)
            else:
                coords = (20.5937, 78.9629)

        location_cache[location] = coords
        return coords

    except:
        return (20.5937, 78.9629)

# -------- DUPLICATE CHECK --------
def is_duplicate(title):
    return collection.find_one({"title": title}) is not None

# -------- SCRAPING --------
url = "https://news.google.com/search?q=cyber%20fraud"
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")

articles = soup.find_all("a")

count = 0

for a in articles:
    title = a.text.strip()

    if not title or not is_valid(title):
        continue

    if is_duplicate(title):
        continue

    location = extract_location(title)
    lat, lng = get_coordinates(location)

    data = {
        "title": title,
        "location": location,
        "lat": lat,
        "lng": lng,
        "type": classify(title),
        "created_at": datetime.utcnow()
    }

    collection.insert_one(data)

    print(f"✅ {title} → {location}")

    count += 1
    time.sleep(1)  # avoid rate limit

print(f"\n🎯 Total inserted: {count}")
print("Scraping completed ✅")