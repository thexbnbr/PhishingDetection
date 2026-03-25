# Phishing URL Detection

A machine learning project to detect phishing URLs using feature engineering and a Random Forest classifier.

## Results

| Model | Accuracy | Recall (phishing) | F1 (phishing) |
|---|---|---|---|
| Logistic Regression | 0.76 | 0.63 | 0.55 |
| Random Forest | **0.90** | **0.79** | **0.77** |

With threshold tuning (0.3), recall on phishing URLs reaches **0.87** — detecting 87% of malicious URLs.

## Dataset

- 550,000 URLs labeled as `good` (legitimate) or `bad` (phishing)
- Source: [Kaggle — Phishing Site URLs](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls)
- Class distribution: 71% legitimate / 29% phishing

## Features engineered

17 features extracted from raw URLs, split into 4 categories:

**Length & structure** — `url_length`, `domain_length`, `path_length`, `nb_params`

**Character patterns** — `nb_dots`, `nb_hyphens`, `nb_slashes`, `nb_digits`, `nb_percent`, `ratio_digits`

**Domain analysis** — `nb_subdomains`, `has_ip`, `suspicious_tld`

**Semantic signals** — `has_brand`, `brand_not_main_domain`, `typosquatting`

The `typosquatting` feature uses sequence similarity to detect domains that impersonate known brands (e.g. `paypaal.com`, `g00gle.com`).

## How to run

```bash
git clone https://github.com/thexbnbr/phishing-detection
cd phishing-detection
pip install -r requirements.txt
jupyter notebook main.ipynb
```

## Predict a URL

```python
print(predire("https://paypaal.com"))   # → PHISHING
print(predire("https://paypal.com"))    # → LÉGITIME
print(predire("https://g00gle.com"))    # → PHISHING
```

## Stack

Python · pandas · scikit-learn · matplotlib · seaborn

## Author

[@thexbnbr](https://github.com/thexbnbr)
