using RetroDev.UnityGuard.UnityGuard.ML;
using UnitySecurityScanner;

public static class SecurityIssueExtensions
{
    public static List<SecurityScanner.SecurityIssue> EnhanceWithML(
        this List<SecurityScanner.SecurityIssue> issues,
        MLSecurityAnalyzer mlAnalyzer,
        bool updateModel = false) 
    {
        foreach (var issue in issues)
        {
            var prediction = mlAnalyzer.AnalyzeIssue(issue);

            // Enhance the issue with ML predictions
            issue.Severity = prediction.PredictedSeverity;
            issue.CvssScore = prediction.RiskScore;

            if (issue.AdditionalInfo == null)
                issue.AdditionalInfo = new Dictionary<string, string>();

            issue.AdditionalInfo["ML_Confidence"] = $"{prediction.Confidence:P1}";
            issue.AdditionalInfo["Priority"] = prediction.RecommendedPriority;
            issue.AdditionalInfo["FalsePositive"] = prediction.IsFalsePositive.ToString();
        }

        // Only update the model if explicitly requested
        if (updateModel)
        {
            mlAnalyzer.UpdateModelWithScanResults(issues, true);
        }

        return issues;
    }
}