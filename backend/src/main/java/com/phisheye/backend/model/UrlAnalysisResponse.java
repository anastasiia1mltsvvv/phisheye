package com.phisheye.backend.model;

import java.util.List;

public class UrlAnalysisResponse {
    private String url;
    private int riskScore;
    private String riskLevel;
    private List<String> reasons;

    public UrlAnalysisResponse(String url, int riskScore, String riskLevel, List<String> reasons) {
        this.url = url;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.reasons = reasons;
    }

    public String getUrl() {
        return url;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public List<String> getReasons() {
        return reasons;
    }
}