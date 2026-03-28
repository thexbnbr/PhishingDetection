from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import joblib
import pandas as pd
from urllib.parse import urlparse
from difflib import SequenceMatcher
import re
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))

rf = joblib.load("model_phishing.pkl")

def extract_features(url):
    features = {}
    
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc
        path   = parsed.path
        query  = parsed.query
    except:
        parsed = None
        domain = url
        path   = ""
        query  = ""

    
    features["url_length"]    = len(url)
    features["domain_length"] = len(domain)
    features["path_length"]   = len(path)
    features["nb_params"]     = len(query.split("&")) if query else 0

   
    features["nb_dots"]       = url.count(".")
    features["nb_hyphens"]    = url.count("-")
    features["nb_slashes"]    = url.count("/")
    features["nb_at"]         = url.count("@")
    features["nb_digits"]     = sum(c.isdigit() for c in url)
    features["nb_percent"]    = url.count("%")
    features["has_double_slash"] = int("//" in url[7:])  
    features["ratio_digits"]  = features["nb_digits"] / len(url) if len(url) > 0 else 0


    subdomains = domain.split(".")
    features["nb_subdomains"] = max(len(subdomains) - 2, 0)
    features["has_ip"]        = int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain)))
    features["has_port"]      = int(":" in domain)

    brands = ["paypal", "google", "apple", "amazon", "microsoft", "facebook"]
    features["has_brand"] = int(any(b in url.lower() for b in brands))

    tld = domain.split(".")[-1].lower()
    features["suspicious_tld"] = int(tld in {"tk", "ml", "ga", "cf", "xyz", "top"})

    features["is_http"] = int(url.startswith("http://"))

    domain_sans_tld = ".".join(domain.split(".")[:-1])  
    features["brand_not_main_domain"] = int(
    any(b in url.lower() for b in brands) and 
    not any(domain_sans_tld == b for b in brands)  
    )
    tld = subdomains[-1] if subdomains else ""

    def ressemble_a_une_marque(domain, seuil=0.85):
        brands = ["paypal", "google", "apple", "amazon", "microsoft", 
              "facebook", "netflix", "instagram", "youtube", "twitter"]
        domain_principal = domain.split(".")[0].lower()
    
        for brand in brands:
            similarite = SequenceMatcher(None, domain_principal, brand).ratio()
            if similarite >= seuil and domain_principal != brand:
                return 1
        return 0

    features["typosquatting"] = ressemble_a_une_marque(domain)  
    return features

class URLRequest(BaseModel):
    url: str

@app.post("/predict")
def predict(request: URLRequest):
    features = extract_features(request.url)
    X = pd.DataFrame([features])
    
    proba_bad = rf.predict_proba(X)[0][0]
    seuil = 0.3
    verdict = "PHISHING" if proba_bad >= seuil else "LÉGITIME"
    confiance = round(proba_bad * 100, 1) if verdict == "PHISHING" else round((1 - proba_bad) * 100, 1)
    
    return {
        "verdict": verdict,
        "confiance": confiance,
        "url": request.url
    }