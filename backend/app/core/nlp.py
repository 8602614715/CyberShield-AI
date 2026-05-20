from geopy.geocoders import Nominatim

_nlp = None
geolocator = Nominatim(user_agent="cyberfraud_app", timeout=3)


def get_nlp():
    global _nlp
    if _nlp is None:
        import spacy

        _nlp = spacy.load("en_core_web_sm")
    return _nlp
