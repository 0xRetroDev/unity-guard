using Microsoft.ML.Data;

namespace RetroDev.UnityGuard.UnityGuard.ML
{
    public class SecurityIssuePrediction
    {
        [ColumnName("PredictedSeverity")]
        public string PredictedSeverity { get; set; }

        [ColumnName("Score")]
        public float[] Score { get; set; }

        public bool IsFalsePositive { get; set; }
        public float RiskScore { get; set; }
        public string RecommendedPriority { get; set; }

        public float Confidence => Score?.Max() ?? 0f;
    }
}