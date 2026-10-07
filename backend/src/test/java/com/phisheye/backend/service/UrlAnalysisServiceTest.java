package com.phisheye.backend.service;

import com.phisheye.backend.model.UrlAnalysisResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlAnalysisServiceTest {

    private final UrlAnalysisService service = new UrlAnalysisService();

    @Test
    void legitimateHttpsUrlIsLowRisk() {
        UrlAnalysisResponse result = service.analyze("https://www.microsoft.com");
        assertEquals("LOW", result.riskLevel());
        assertTrue(result.reasons().isEmpty(), "microsoft.com must not match the shortener t.co");
    }

    @Test
    void digitsInPathAreNotTreatedAsTyposquatting() {
        UrlAnalysisResponse result = service.analyze("https://github.com/user/project1/releases/2025");
        assertEquals("LOW", result.riskLevel());
    }

    @Test
    void typicalPhishingUrlIsHighRisk() {
        UrlAnalysisResponse result = service.analyze(
                "http://g00gle-account-security-login.xyz/redirect?user=anna&token=938482&session=999999&target=paypal.com");
        assertEquals("HIGH", result.riskLevel());
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("typosquatting")));
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("top-level domain")));
    }

    @Test
    void ipAddressHostIsDetected() {
        UrlAnalysisResponse result = service.analyze("http://192.168.10.5/login");
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("IP address")));
        assertEquals("HIGH", result.riskLevel());
    }

    @Test
    void linkShortenerIsMatchedOnExactDomain() {
        UrlAnalysisResponse result = service.analyze("https://bit.ly/3abcDEF");
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("link shortener")));
    }

    @Test
    void atSignTrickIsDetected() {
        UrlAnalysisResponse result = service.analyze("https://paypal.com@evil.example/login");
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("'@'")));
    }

    @Test
    void emptyUrlIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> service.analyze("   "));
    }

    @Test
    void tooLongUrlIsRejected() {
        String longUrl = "https://example.com/" + "a".repeat(UrlAnalysisService.MAX_URL_LENGTH);
        assertThrows(IllegalArgumentException.class, () -> service.analyze(longUrl));
    }

    @Test
    void scoreNeverExceeds100() {
        UrlAnalysisResponse result = service.analyze(
                "http://admin@l0gin-secure-verify-account.update.paypal.co.xyz/login?url=http://x&next=a&b=c");
        assertTrue(result.riskScore() <= 100);
    }
}
