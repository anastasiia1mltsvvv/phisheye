package com.phisheye.backend.model;

import java.util.List;

/**
 * Result of a URL analysis, returned as JSON by the /analyze endpoint.
 */
public record UrlAnalysisResponse(String url, int riskScore, String riskLevel, List<String> reasons) {
}
