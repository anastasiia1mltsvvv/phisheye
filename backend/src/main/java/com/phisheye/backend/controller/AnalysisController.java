package com.phisheye.backend.controller;

import com.phisheye.backend.model.UrlAnalysisResponse;
import com.phisheye.backend.service.UrlAnalysisService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

// "*" lets the local frontend (opened as a file) call the API.
// In production this should be restricted to the frontend's real origin.
@CrossOrigin(origins = "*")
@RestController
public class AnalysisController {

    private final UrlAnalysisService analysisService;

    public AnalysisController(UrlAnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    @GetMapping("/")
    public String home() {
        return "PhishEye backend is running!";
    }

    @GetMapping("/analyze")
    public UrlAnalysisResponse analyzeUrl(@RequestParam String url) {
        return analysisService.analyze(url);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleInvalidUrl(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
