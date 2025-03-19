using Microsoft.ML.Data;

public class SecurityIssueInput
{
    [LoadColumn(0), ColumnName("IssueType")]
    public string IssueType { get; set; }

    [LoadColumn(1), ColumnName("Description")]
    public string Description { get; set; }

    [LoadColumn(2), ColumnName("Context")]
    public string Context { get; set; }

    [LoadColumn(3), ColumnName("FoundValue")]
    public string FoundValue { get; set; }

    [LoadColumn(4), ColumnName("CvssScore")]
    public float CvssScore { get; set; }

    [LoadColumn(5), ColumnName("Location")]
    public string Location { get; set; }

    [LoadColumn(6), ColumnName("ContainsHardcodedCredentials")]
    public bool ContainsHardcodedCredentials { get; set; }

    [LoadColumn(7), ColumnName("ContainsUnsafeCode")]
    public bool ContainsUnsafeCode { get; set; }

    [LoadColumn(8), ColumnName("ContainsNetworkCalls")]
    public bool ContainsNetworkCalls { get; set; }

    [LoadColumn(9), ColumnName("IsInTestCode")]
    public bool IsInTestCode { get; set; }

    [LoadColumn(10), ColumnName("Severity")]
    public string Severity { get; set; }
}