package com.phisheye.backend.controller;

import com.phisheye.backend.model.UrlAnalysisResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin(origins = "*")
@RestController
public class AnalysisController {

    @GetMapping("/")
    public String home() {
        return "PhishEye backend is running!";
    }

    @GetMapping("/analyze")
    public UrlAnalysisResponse analyzeUrl(@RequestParam String url) {
        int riskScore = 0;
        List<String> reasons = new ArrayList<>();

        if (url.startsWith("http://")) {
            riskScore += 20;
            reasons.add("URL uses HTTP instead of HTTPS");
        }

        if (url.contains("login") || url.contains("verify") || url.contains("security")) {
            riskScore += 25;
            reasons.add("URL contains suspicious phishing-related keywords");
        }

        if (url.contains(".xyz") || url.contains(".top") || url.contains(".click")) {
            riskScore += 20;
            reasons.add("URL uses a suspicious top-level domain");
        }

        if (url.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            riskScore += 30;
            reasons.add("URL contains an IP address instead of a normal domain name");
        }

        if (url.length() > 75) {
            riskScore += 15;
            reasons.add("URL is unusually long");
        }

    String normalizedUrl = url
        .toLowerCase()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("@", "a");

        if (!normalizedUrl.equals(url.toLowerCase())) {
        riskScore += 20;
        reasons.add("URL contains character substitutions that are often used in typosquatting");
        }

    long dashCount = url.chars()
        .filter(ch -> ch == '-')
        .count();

        if (dashCount >= 3) {
        riskScore += 15;
        reasons.add("URL contains many hyphens, which can be suspicious");
        }

    long dotCount = url.chars()
        .filter(ch -> ch == '.')
        .count();

        if (dotCount >= 4) {
        riskScore += 15;
        reasons.add("URL contains many subdomains or dots, which can be suspicious");
        }

    String lowerUrl = url.toLowerCase();
    
        if (lowerUrl.contains("bit.ly") ||
        lowerUrl.contains("tinyurl.com") ||
        lowerUrl.contains("t.co") ||
        lowerUrl.contains("goo.gl") ||
        lowerUrl.contains("ow.ly") ||
        lowerUrl.contains("is.gd")) {

        riskScore += 25;
        reasons.add("URL uses a link shortener, which can hide the real destination");
        }

    if (lowerUrl.contains("redirect") ||
        lowerUrl.contains("return") ||
        lowerUrl.contains("callback") ||
        lowerUrl.contains("next") ||
        lowerUrl.contains("continue") ||
        lowerUrl.contains("target=")) {

    riskScore += 15;
    reasons.add("URL contains redirect-related keywords that may hide the final destination");
    }

    if (url.contains("?")) {

    String[] parts = url.split("\\?");

    if (parts.length > 1) {

        String queryPart = parts[1];

        String[] parameters = queryPart.split("&");

        if (parameters.length >= 3) {
            riskScore += 15;
            reasons.add("URL contains many query parameters, which can be suspicious");
        }
    }
}

    String riskLevel;

        if (riskScore >= 60) {
            riskLevel = "HIGH";
        } else if (riskScore >= 30) {
            riskLevel = "MEDIUM";
        } else {
            riskLevel = "LOW";
        }

        return new UrlAnalysisResponse(url, riskScore, riskLevel, reasons);
    }
}