package com.phisheye.backend.service;

import com.phisheye.backend.model.UrlAnalysisResponse;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Rule-based phishing URL analysis.
 *
 * Each rule inspects a specific part of the URL (scheme, host, path or query)
 * instead of searching the whole string. This avoids false positives such as
 * "microsoft.com" matching the link shortener "t.co".
 */
@Service
public class UrlAnalysisService {

    public static final int MAX_URL_LENGTH = 2048;
    static final int LONG_URL_THRESHOLD = 75;
    static final int HIGH_THRESHOLD = 60;
    static final int MEDIUM_THRESHOLD = 30;

    private static final Set<String> SUSPICIOUS_TLDS =
            Set.of("xyz", "top", "click", "zip", "tk", "ml", "ga", "cf", "gq");

    private static final Set<String> URL_SHORTENERS =
            Set.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd");

    private static final List<String> PHISHING_KEYWORDS =
            List.of("login", "signin", "verify", "security", "account", "password", "update", "confirm");

    private static final Set<String> REDIRECT_PARAMETERS =
            Set.of("redirect", "redirect_uri", "redirect_url", "url", "return", "returnurl",
                    "return_to", "next", "continue", "target", "dest", "destination", "callback");

    private static final Pattern IPV4_HOST = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    /** A letter, then digits/@ that look like letters (0=o, 1=l, 3=e, 5=s, @=a), then a letter, e.g. "g00gle". */
    private static final Pattern LOOKALIKE_CHARACTERS = Pattern.compile("[a-z][0135@]+[a-z]");

    public UrlAnalysisResponse analyze(String rawUrl) {
        String url = validate(rawUrl);
        boolean hasScheme = url.contains("://");
        URI uri = parse(hasScheme ? url : "http://" + url);

        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        String path = uri.getRawPath() == null ? "" : uri.getRawPath().toLowerCase(Locale.ROOT);
        String query = uri.getRawQuery() == null ? "" : uri.getRawQuery().toLowerCase(Locale.ROOT);

        int riskScore = 0;
        List<String> reasons = new ArrayList<>();

        if (hasScheme && "http".equalsIgnoreCase(uri.getScheme())) {
            riskScore += 20;
            reasons.add("URL uses HTTP instead of HTTPS");
        }

        if (uri.getRawUserInfo() != null) {
            riskScore += 30;
            reasons.add("URL contains an '@' before the domain, which can disguise the real destination");
        }

        boolean isIpAddress = IPV4_HOST.matcher(host).matches();
        if (isIpAddress) {
            riskScore += 30;
            reasons.add("URL uses an IP address instead of a domain name");
        }

        if (!isIpAddress && SUSPICIOUS_TLDS.contains(topLevelDomain(host))) {
            riskScore += 20;
            reasons.add("URL uses a suspicious top-level domain (." + topLevelDomain(host) + ")");
        }

        if (isUrlShortener(host)) {
            riskScore += 25;
            reasons.add("URL uses a link shortener, which can hide the real destination");
        }

        if (containsPhishingKeyword(host + path)) {
            riskScore += 25;
            reasons.add("URL contains phishing-related keywords (e.g. login, verify, account)");
        }

        if (!isIpAddress && LOOKALIKE_CHARACTERS.matcher(host).find()) {
            riskScore += 20;
            reasons.add("Domain contains look-alike characters often used in typosquatting (e.g. 0 instead of o)");
        }

        if (count(host, '-') >= 3) {
            riskScore += 15;
            reasons.add("Domain contains many hyphens");
        }

        if (!isIpAddress && count(host, '.') >= 4) {
            riskScore += 15;
            reasons.add("Domain contains many subdomains");
        }

        String[] parameters = query.isEmpty() ? new String[0] : query.split("&");

        if (hasRedirectParameter(parameters)) {
            riskScore += 15;
            reasons.add("URL contains a redirect parameter that may forward the user to another site");
        }

        if (parameters.length >= 3) {
            riskScore += 15;
            reasons.add("URL contains many query parameters");
        }

        if (url.length() > LONG_URL_THRESHOLD) {
            riskScore += 15;
            reasons.add("URL is unusually long");
        }

        riskScore = Math.min(riskScore, 100);
        return new UrlAnalysisResponse(url, riskScore, riskLevel(riskScore), reasons);
    }

    private String validate(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new IllegalArgumentException("URL must not be empty");
        }
        String url = rawUrl.trim();
        if (url.length() > MAX_URL_LENGTH) {
            throw new IllegalArgumentException("URL is too long (max " + MAX_URL_LENGTH + " characters)");
        }
        return url;
    }

    private URI parse(String url) {
        try {
            URI uri = new URI(url);
            if (uri.getHost() == null) {
                throw new IllegalArgumentException("Could not find a domain in the URL");
            }
            return uri;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("URL is not valid");
        }
    }

    private static String topLevelDomain(String host) {
        int lastDot = host.lastIndexOf('.');
        return lastDot == -1 ? "" : host.substring(lastDot + 1);
    }

    private static boolean isUrlShortener(String host) {
        return URL_SHORTENERS.stream()
                .anyMatch(shortener -> host.equals(shortener) || host.endsWith("." + shortener));
    }

    private static boolean containsPhishingKeyword(String text) {
        return PHISHING_KEYWORDS.stream().anyMatch(text::contains);
    }

    private static boolean hasRedirectParameter(String[] parameters) {
        for (String parameter : parameters) {
            String[] keyValue = parameter.split("=", 2);
            String key = keyValue[0];
            String value = keyValue.length > 1 ? keyValue[1] : "";
            if (REDIRECT_PARAMETERS.contains(key) || value.startsWith("http")) {
                return true;
            }
        }
        return false;
    }

    private static long count(String text, char character) {
        return text.chars().filter(ch -> ch == character).count();
    }

    private static String riskLevel(int riskScore) {
        if (riskScore >= HIGH_THRESHOLD) {
            return "HIGH";
        }
        if (riskScore >= MEDIUM_THRESHOLD) {
            return "MEDIUM";
        }
        return "LOW";
    }
}
