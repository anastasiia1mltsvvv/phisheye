# PhishEye

PhishEye is a rule-based phishing URL analyzer built with Java Spring Boot and a lightweight HTML/JavaScript frontend.
It parses a URL into its parts (scheme, domain, path and query), checks them against common phishing indicators and returns an explainable risk score, so the user can see **why** a link looks suspicious.

## Features

- Explainable risk score (0–100) with a risk level: `LOW`, `MEDIUM` or `HIGH`
- Checks each part of the URL separately to reduce false positives
- REST API (`GET /analyze`) with input validation and clear error messages
- Unit-tested detection rules
- Frontend that renders results safely (text only, no HTML injection)

## Detection rules

| Rule | What it checks | Points |
|---|---|---|
| HTTP instead of HTTPS | Scheme is `http` | +20 |
| `@` in the address | User info before the domain, e.g. `https://paypal.com@evil.example` | +30 |
| IP-based URL | Domain is an IPv4 address | +30 |
| Suspicious TLD | Domain ends with `.xyz`, `.top`, `.click`, `.zip`, `.tk` and similar | +20 |
| Link shortener | Domain is exactly a known shortener (`bit.ly`, `t.co`, …) | +25 |
| Phishing keywords | Domain or path contains `login`, `verify`, `account`, … | +25 |
| Typosquatting | Domain contains look-alike characters, e.g. `g00gle` (0 instead of o) | +20 |
| Many hyphens | 3 or more hyphens in the domain | +15 |
| Many subdomains | 4 or more dots in the domain | +15 |
| Redirect parameter | Query parameter such as `redirect`, `next`, `url`, `target`, or a value starting with `http` | +15 |
| Many query parameters | 3 or more query parameters | +15 |
| Long URL | Longer than 75 characters | +15 |

Risk level: `HIGH` ≥ 60, `MEDIUM` ≥ 30, otherwise `LOW`. The score is capped at 100.

## Tech stack

- Java 21, Spring Boot
- JUnit 5
- HTML, CSS, JavaScript

## How to run

**Backend**

```bash
cd backend
./mvnw spring-boot:run
```

The API starts on `http://localhost:8080`.

**Frontend**

Open `frontend/index.html` in a browser, paste a URL and click **Analyze URL**.

**Tests**

```bash
cd backend
./mvnw test
```

## API example

```
GET /analyze?url=http://g00gle-account-security-login.xyz/redirect?user=anna%26target=paypal.com
```

```json
{
  "url": "http://g00gle-account-security-login.xyz/redirect?user=anna&target=paypal.com",
  "riskScore": 100,
  "riskLevel": "HIGH",
  "reasons": [
    "URL uses HTTP instead of HTTPS",
    "URL uses a suspicious top-level domain (.xyz)",
    "URL contains phishing-related keywords (e.g. login, verify, account)",
    "Domain contains look-alike characters often used in typosquatting (e.g. 0 instead of o)",
    "Domain contains many hyphens",
    "URL contains a redirect parameter that may forward the user to another site",
    "URL is unusually long"
  ]
}
```

An empty or too long URL (over 2048 characters) returns `400 Bad Request` with an error message.

## Design decisions

- **Parse first, then check.** The URL is parsed with `java.net.URI`, and each rule looks only at the relevant part. An earlier version searched the whole string, which caused false positives, for example `microsoft.com` matching the shortener `t.co`, or `/page1` being flagged as typosquatting.
- **Explainability over a single number.** Every point added to the score comes with a human-readable reason.

## Limitations

- Rule-based only: it does not check the URL against threat intelligence sources or visit the website.
- Legitimate login pages (e.g. `accounts.google.com/signin`) still get points for the keyword rule.
- Typosquatting detection is a simple heuristic and does not compare against a list of known brands.
- CORS allows all origins so the local frontend can call the API. In production this should be restricted.

## Possible improvements

- Check domains against threat intelligence feeds (e.g. PhishTank, VirusTotal)
- Domain age lookup (WHOIS) and TLS certificate checks
- Compare domains to known brands with an edit-distance algorithm

---

Developed by Anastasiia Maltseva, cybersecurity student.
