from app.db.mongodb import collection, users


def ensure_indexes() -> None:
    """Create indexes idempotently for common queries."""
    try:
        collection.create_index([("created_at", -1)], name="reports_created_at_desc")
        collection.create_index([("location", 1)], name="reports_location_1")
        collection.create_index([("type", 1)], name="reports_type_1")
        collection.create_index([("created_by", 1)], name="reports_created_by_1")
        users.create_index([("email", 1)], name="users_email_unique", unique=True)
    except Exception:
        pass
