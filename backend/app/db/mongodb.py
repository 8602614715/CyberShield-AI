from pymongo import MongoClient

from app.config import MONGODB_DB_NAME, MONGODB_URI

if not MONGODB_URI:
    raise RuntimeError(
        "MONGODB_URI is not set. Copy .env.example to the project root .env and configure it."
    )

client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB_NAME]
collection = db["reports"]
users = db["users"]
