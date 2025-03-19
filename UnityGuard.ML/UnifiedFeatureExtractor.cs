using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using Microsoft.ML;
using Microsoft.ML.Data;
using RetroDev.UnityGuard.UnityGuard.Analysis;
using RetroDev.UnityGuard.UnityGuard.Features;

namespace RetroDev.UnityGuard.UnityGuard.ML
{
    /// <summary>
    /// Combines all analyzers to create rich feature vectors for ML training
    /// </summary>
    public class UnifiedFeatureExtractor
    {
        private readonly APIUsageAnalyzer _apiAnalyzer;
        private readonly ContextAnalyzer _contextAnalyzer;
        private readonly CredentialAnalyzer _credentialAnalyzer;
        private readonly DataFlowAnalyzer _dataFlowAnalyzer;
        private readonly CodeComplexityAnalyzer _complexityAnalyzer;
        private readonly SecurityPatternAnalyzer _patternAnalyzer;

        public UnifiedFeatureExtractor(SyntaxTree syntaxTree, string code)
        {
            _apiAnalyzer = new APIUsageAnalyzer(syntaxTree, code);
            _contextAnalyzer = new ContextAnalyzer(syntaxTree, code);
            _credentialAnalyzer = new CredentialAnalyzer(syntaxTree, code);
            _dataFlowAnalyzer = new DataFlowAnalyzer(syntaxTree, code);
            _complexityAnalyzer = new CodeComplexityAnalyzer(syntaxTree, code);
            _patternAnalyzer = new SecurityPatternAnalyzer(syntaxTree, code);
        }

        public class UnifiedFeatureVector
        {
            // API Usage Features
            [VectorType(20)]
            public float[] ApiUsageMetrics { get; set; }

            // Context Features
            [VectorType(20)]
            public float[] ContextMetrics { get; set; }

            // Credential Features
            [VectorType(20)]
            public float[] CredentialMetrics { get; set; }

            // Data Flow Features
            [VectorType(10)]
            public float[] DataFlowMetrics { get; set; }

            // Code Complexity Features
            [VectorType(10)]
            public float[] ComplexityMetrics { get; set; }

            // Security Pattern Features
            [VectorType(10)]
            public float[] SecurityPatternMetrics { get; set; }

            // Aggregated Risk Score
            public float RiskScore { get; set; }

            // Enhanced Features
            public bool ContainsHardcodedCredentials { get; set; }
            public bool ContainsUnsafeCode { get; set; }
            public bool ContainsNetworkCalls { get; set; }
            public bool ContainsInsecureCrypto { get; set; }
            public bool ContainsDataLeaks { get; set; }

            // Context Classifications
            public string SecurityContext { get; set; }
            public string RiskLevel { get; set; }
            public float ConfidenceScore { get; set; }
        }

        public UnifiedFeatureVector ExtractFeatures()
        {
            var features = new UnifiedFeatureVector
            {
                ApiUsageMetrics = _apiAnalyzer.AnalyzeAPIUsage(),
                ContextMetrics = _contextAnalyzer.AnalyzeContextMetrics(),
                CredentialMetrics = _credentialAnalyzer.AnalyzeCredentialMetrics(),  // Fixed method name
                DataFlowMetrics = _dataFlowAnalyzer.CalculateDataFlowMetrics(),
                ComplexityMetrics = _complexityAnalyzer.CalculateComplexityMetrics(),
                SecurityPatternMetrics = _patternAnalyzer.CalculateSecurityMetrics()
            };

            // Enhanced feature extraction
            features.ContainsHardcodedCredentials = DetectHardcodedCredentials();
            features.ContainsUnsafeCode = DetectUnsafeCode();
            features.ContainsNetworkCalls = DetectNetworkCalls();
            features.ContainsInsecureCrypto = DetectInsecureCrypto();
            features.ContainsDataLeaks = DetectDataLeaks();

            // Calculate aggregated risk score
            features.RiskScore = CalculateAggregatedRiskScore(features);

            // Determine security context and risk level
            (features.SecurityContext, features.RiskLevel) = DetermineSecurityContext(features);
            features.ConfidenceScore = CalculateConfidenceScore(features);

            return features;
        }

        private bool DetectHardcodedCredentials()
        {
            var credMetrics = _credentialAnalyzer.AnalyzeCredentialMetrics();  // Fixed method name
            // Look at the credential metrics array - typically high values in first few indices
            // indicate presence of hardcoded credentials
            return credMetrics.Take(5).Any(m => m > 0.7f);
        }

        private bool DetectUnsafeCode()
        {
            var apiMetrics = _apiAnalyzer.AnalyzeAPIUsage();
            return apiMetrics[8] > 0.5f; // Memory API usage threshold
        }

        private bool DetectNetworkCalls()
        {
            var apiMetrics = _apiAnalyzer.AnalyzeAPIUsage();
            return apiMetrics[0] > 0.3f; // Network API usage threshold
        }

        private bool DetectInsecureCrypto()
        {
            var securityMetrics = _patternAnalyzer.CalculateSecurityMetrics();
            // Check crypto-related metrics (usually in the first few indices)
            return securityMetrics.Take(3).Any(m => m > 0.6f);
        }

        private bool DetectDataLeaks()
        {
            var dataFlowMetrics = _dataFlowAnalyzer.CalculateDataFlowMetrics();
            return dataFlowMetrics[9] > 0.6f; // Data flow risk threshold
        }

        private float CalculateAggregatedRiskScore(UnifiedFeatureVector features)
        {
            float score = 0f;

            // Weight different components
            score += features.ApiUsageMetrics.Average() * 0.2f;
            score += features.ContextMetrics.Average() * 0.15f;
            score += features.CredentialMetrics.Average() * 0.25f;
            score += features.DataFlowMetrics.Average() * 0.2f;
            score += features.ComplexityMetrics.Average() * 0.1f;
            score += features.SecurityPatternMetrics.Average() * 0.1f;

            // Add penalties for critical issues
            if (features.ContainsHardcodedCredentials) score += 0.2f;
            if (features.ContainsUnsafeCode) score += 0.15f;
            if (features.ContainsInsecureCrypto) score += 0.25f;
            if (features.ContainsDataLeaks) score += 0.2f;

            return Math.Min(score, 1.0f);
        }

        private (string context, string level) DetermineSecurityContext(UnifiedFeatureVector features)
        {
            var contexts = new List<string>();
            var riskLevel = "Low";

            if (features.ContainsHardcodedCredentials)
                contexts.Add("Credential Security");
            if (features.ContainsUnsafeCode)
                contexts.Add("Memory Safety");
            if (features.ContainsNetworkCalls)
                contexts.Add("Network Security");
            if (features.ContainsInsecureCrypto)
                contexts.Add("Cryptographic Security");
            if (features.ContainsDataLeaks)
                contexts.Add("Data Privacy");

            // Determine risk level
            if (features.RiskScore > 0.8f)
                riskLevel = "Critical";
            else if (features.RiskScore > 0.6f)
                riskLevel = "High";
            else if (features.RiskScore > 0.4f)
                riskLevel = "Medium";

            return (string.Join(", ", contexts), riskLevel);
        }

        private float CalculateConfidenceScore(UnifiedFeatureVector features)
        {
            // Base confidence on metric consistency and feature presence
            float confidence = 0.5f;

            // Increase confidence based on strong signals
            if (features.ContainsHardcodedCredentials) confidence += 0.1f;
            if (features.ContainsUnsafeCode) confidence += 0.1f;
            if (features.ContainsInsecureCrypto) confidence += 0.1f;

            // Adjust based on metric agreement
            var metricAgreement = CalculateMetricAgreement(features);
            confidence += metricAgreement * 0.2f;

            return Math.Min(confidence, 1.0f);
        }

        private float CalculateMetricAgreement(UnifiedFeatureVector features)
        {
            var allMetrics = new List<float[]>
            {
                features.ApiUsageMetrics,
                features.ContextMetrics,
                features.CredentialMetrics,
                features.DataFlowMetrics,
                features.ComplexityMetrics,
                features.SecurityPatternMetrics
            };

            // Calculate average deviation between metric sets
            float totalDeviation = 0;
            int comparisons = 0;

            for (int i = 0; i < allMetrics.Count; i++)
            {
                for (int j = i + 1; j < allMetrics.Count; j++)
                {
                    var avgDiff = Math.Abs(allMetrics[i].Average() - allMetrics[j].Average());
                    totalDeviation += avgDiff;
                    comparisons++;
                }
            }

            return 1.0f - (totalDeviation / comparisons);
        }
    }
}