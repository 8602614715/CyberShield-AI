import re

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

METRO_COORDS = {
    "delhi": (28.6139, 77.2090),
    "mumbai": (19.0760, 72.8777),
    "bangalore": (12.9716, 77.5946),
    "chennai": (13.0827, 80.2707),
    "hyderabad": (17.3850, 78.4867),
    "pune": (18.5204, 73.8567),
    "indore": (22.7196, 75.8577),
    "bhopal": (23.2599, 77.4126),
    "kolkata": (22.5726, 88.3639),
    "jaipur": (26.9124, 75.7873),
    "lucknow": (26.8467, 80.9462),
}

ALLOWED_ROLES = {"viewer", "analyst", "admin"}
CASE_STATUSES = {"new", "under_review", "confirmed_fraud", "false_positive", "closed"}

PHONE_PATTERN = re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}")
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}\b")
