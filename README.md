
_Please download the latest built release to use Unity Guard_

![image](https://github.com/user-attachments/assets/bed3178e-0a61-4540-87e5-6d309229361d)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Advanced Security Scanner for Unity Games & .NET Assemblies

Unity Guard is a powerful security scanner for Unity games and .NET assemblies that uses machine learning to identify security vulnerabilities with increasing accuracy over time. The tool automatically analyzes code, generates detailed security reports, and provides actionable recommendations to help developers secure their applications.

![Unity Guard Scanner](assets/scanner-demo.gif)

## Key Features

- **ML-Powered Security Analysis**: Leverages machine learning models that improve over time as they process more games and assemblies
- **ONNX Export Support**: Export trained models for use in other applications and environments
- **Comprehensive Vulnerability Detection**:
  - API key and credential exposure
  - Insecure serialization
  - Unsafe code usage
  - Insecure network calls
  - Path traversal vulnerabilities
  - Cryptographic weaknesses
  - And many more...
- **Detailed HTML Reports**: Beautiful, comprehensive reports with severity ratings, CVSS scores, and actionable recommendations
- **Intuitive Console Interface**: Easy-to-use command-line interface with real-time analysis feedback
- **Continuous Learning**: The more games you scan, the smarter it gets at detecting security issues

## 🚀 Getting Started

### Prerequisites

- Windows, macOS, or Linux
- .NET 6.0 or higher
- At least 4GB of available RAM
- 2GB of available storage

### Installation

#### Download the Latest Release

1. Download the [latest release](https://github.com/0xRetroDev/unity-guard/releases) for your platform
2. Extract the archive to your preferred location
3. Run `UnityGuard.exe` (Windows) or `UnityGuard` (macOS/Linux)

## 📖 Usage Guide

### Scanning a Unity Game

1. Launch Unity Guard
2. Drop your Unity game folder into the watch folder (shown in the console interface)
3. Press `S` to start scanning
4. View the results in the generated HTML report in the Reports folder

![image](https://github.com/user-attachments/assets/6edc9fa6-a2b8-4036-8b3f-24822b753c82)

### Scanning Individual DLLs

1. Launch Mizuki.UnityGuard
2. Drop your DLL files into the watch folder
3. Press `S` to start scanning
4. View the results in the generated HTML report

### Available Commands

- `S` - Start scanning all pending items
- `L` - List current pending items
- `C` - Clear screen and show instructions
- `Q` - Quit the application

### Scan in Progress
![image](https://github.com/user-attachments/assets/64ebc9ee-f85f-4be8-be87-9dc4810659d3)

### Security Report
![image](https://github.com/user-attachments/assets/cde85a8d-9151-4351-9675-adc7f8623e51)

## 🧠 Machine Learning Integration

Unity Guard uses machine learning to continuously improve its detection capabilities. The more you use it, the better it gets at finding security vulnerabilities.

### ML Features (Heavily Experimental) (WIP)

- **Automatic Training**: The model learns from each scan to improve future detection
- **False Positive Reduction**: Smart identification of potential false positives
- **ONNX Export**: Export your trained model for use in other applications or environments
- **Training Metrics**: View detailed metrics about your model's learning progress


## 🔍 Security Issues Detected

Unity Guard can detect a wide range of security vulnerabilities, including:

| Category | Examples |
|----------|----------|
| **Credential Exposure** | API keys, passwords, connection strings |
| **Unsafe Code** | Unsafe code blocks, memory operations, P/Invoke |
| **Insecure Networking** | HTTP instead of HTTPS, certificate validation disabled |
| **Serialization** | BinaryFormatter usage, unsafe JSON deserialization |
| **Cryptography** | Weak hashing (MD5/SHA1), insecure random numbers |
| **File Operations** | Path traversal, unsafe file access |
| **Input Validation** | SQL injection, command injection risks |
| **Unity-Specific** | Insecure PlayerPrefs, unsafe SendMessage usage |

## 📊 Report Structure

Each generated report includes:

- **Executive Summary**: Overall risk assessment
- **Severity Breakdown**: Issues categorized by severity
- **Detailed Issue Reports**: For each vulnerability:
  - Issue type and location
  - Severity and CVSS score
  - Detailed description
  - Code context and line number
  - Specific recommendations for remediation

## 🔄 ML Model Training Details

The ML system in Unity Guard uses a multi-layered approach:

1. **Feature Extraction**: Analyzes code for security patterns
2. **Classification**: Determines severity and risk level
3. **False Positive Reduction**: Uses contextual analysis to reduce false positives
4. **Continuous Learning**: Updates model weights based on scan results

## 🧪 Advanced Usage

### Command Line Arguments

Unity Guard supports the following command line arguments:

```
UnityGuard.exe [watchFolder] [outputFolder]
```

- `watchFolder`: Custom directory to watch for games/DLLs (default: ScannerInput)
- `outputFolder`: Custom directory for reports (default: Reports)

## 📄 License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [ICSharpCode.Decompiler](https://github.com/icsharpcode/ILSpy) for decompilation capabilities
- [ML.NET](https://github.com/dotnet/machinelearning) for machine learning framework
- [Microsoft ONNX Runtime](https://github.com/microsoft/onnxruntime) for ONNX integration

## 📧 Contact

For questions, feedback, or issues, please:

- [Open an Issue](https://github.com/0xRetroDev/unity-guard/issues)
- Follow me on GitHub [@0xRetroDev](https://github.com/0xRetroDev)

## ⚠️ Disclaimer
Unity Guard is provided "as is" without warranty of any kind, express or implied. The developers and contributors are not responsible for any damage, data loss, or other liability resulting from the use or inability to use this software.
This tool is intended for security research and educational purposes only. 

Always ensure you have appropriate permissions before scanning any games or applications you do not own. The developers are not responsible for any misuse of this software or for any illegal activities conducted with it.

By using Unity Guard, you agree to use it responsibly and in accordance with all applicable laws and regulations.

---

<p align="center">
  <i>Developed with ❤️ by 0xRetroDev</i>
</p>
