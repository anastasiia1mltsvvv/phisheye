# PhishEye

PhishEye is a rule-based phishing and suspicious URL detection platform built with Java Spring Boot and a custom frontend interface.
The system analyzes URLs for common phishing indicators and calculates a dynamic risk score based on suspicious patterns.


## Features

Detects : 
suspicious phishing-related keywords
dangerous top-level domains
typosquatting and character substitutions
suspicious redirect parameters
excessive query parameters
unusually long URLs
suspicious IP-based URLs

Calculates phishing risk levels dynamically
Modern futuristic frontend UI


## Technologies Used

Java
Spring Boot
HTML
CSS
JavaScript


## Example Suspicious URL

```
http://g00gle-account-security-login.xyz/redirect?user=anna&token=938482&session=999999&target=paypal.com
```

---

## Detection Techniques

PhishEye currently uses rule-based analysis techniques including:

HTTP vs HTTPS analysis
Keyword detection
Typosquatting detection
Redirect analysis
Query parameter analysis
Suspicious domain analysis
URL length analysis



Developed by Anastasiia Maltseva
Cybersecurity student 
