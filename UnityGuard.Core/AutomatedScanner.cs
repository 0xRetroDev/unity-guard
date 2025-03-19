using System;
using System.IO;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using static UnitySecurityScanner.SecurityScanner;
using RetroDev.UnityGuard.UnityGuard.ML;

namespace UnitySecurityScanner
{
    public class AutomatedScanner
    {
        private readonly string _watchFolder;
        private readonly string _outputFolder;
        private readonly FileSystemWatcher _watcher;
        private readonly HashSet<string> _processedPaths;
        private readonly HashSet<string> _processedFiles;
        private List<string> _pendingScans;
        private bool _isRunning;
        private readonly MLSecurityAnalyzer _mlAnalyzer;

        public AutomatedScanner(string watchFolder, string outputFolder, MLSecurityAnalyzer mlAnalyzer)
        {
            Console.WriteLine("\nInitializing Automated Scanner...");
            Console.WriteLine("\n");

            _watchFolder = watchFolder;
            _outputFolder = outputFolder;
            _mlAnalyzer = mlAnalyzer;
            _processedPaths = new HashSet<string>();
            _processedFiles = new HashSet<string>();
            _pendingScans = new List<string>();
            _isRunning = true;

            Console.WriteLine($"Creating watch folder: {watchFolder}");
            Directory.CreateDirectory(watchFolder);
            Console.WriteLine("\n");

            Console.WriteLine($"Creating output folder: {outputFolder}");
            Directory.CreateDirectory(outputFolder);
            Console.WriteLine("\n");
            

            Console.WriteLine("Setting up file system watcher...");
            _watcher = new FileSystemWatcher(watchFolder);
            SetupWatcher();

            Console.WriteLine("Scanner initialization complete!");
            Console.WriteLine("\nPress Enter to show the main interface...");
            Console.ReadLine();

            Console.Clear();
            DisplayInstructions();
        }

        private void SetupWatcher()
        {
            _watcher.NotifyFilter = NotifyFilters.DirectoryName
                                | NotifyFilters.FileName
                                | NotifyFilters.LastWrite;

            _watcher.Created += OnCreated;
            _watcher.EnableRaisingEvents = true;
        }

        private void OnCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Wait a moment for any file operations to complete
                Task.Delay(1000).Wait();

                if (Directory.Exists(e.FullPath))
                {
                    DetectNewDirectory(e.FullPath, e.Name);
                }
                else if (File.Exists(e.FullPath) && e.FullPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    DetectNewDll(e.FullPath, e.Name);
                }

                DisplayPendingScans();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError processing {e.Name}: {ex.Message}");
            }
        }

        private void DisplayInstructions()
        {
            // Actually clear the console
            Console.Clear();

            // Title Section (single header)
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
╔══════════════════════════════════════════════════════════════════════════╗");
            Console.Write("║                        ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("     Unity Guard");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                  ║");
            Console.Write("║                         ");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Write("Unity & DLL Analyzer");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                             ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════════════════════════╣");

            // Instructions Section
            Console.WriteLine("║                                                                          ║");
            Console.Write("║  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("Drop files into the watch folder to begin:");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                              ║");
            Console.WriteLine("║                                                                          ║");
            Console.Write("║    ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("- Unity Game Folders");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                                  ║");
            Console.Write("║    ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("- Individual DLL Files");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                                ║");
            Console.Write("║    ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("- Folders Containing DLLs");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                             ║");

            // Folder Locations Section
            Console.WriteLine("║                                                                          ║");
            Console.Write("║  ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Watch Folder Location:");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                                  ║");

            // Handle long paths by splitting them across multiple lines if needed
            string watchFolderPath = "ScannerInput";
            const int maxPathLength = 60;  // Maximum length for path display
            while (watchFolderPath.Length > maxPathLength)
            {
                string currentLine = watchFolderPath.Substring(0, maxPathLength);
                Console.Write("║    ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(currentLine);
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("                                        ║");
                watchFolderPath = watchFolderPath.Substring(maxPathLength);
            }

            Console.Write("║    ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(watchFolderPath);
            Console.ForegroundColor = ConsoleColor.Cyan;
            // Calculate remaining space for padding
            int remainingSpace = maxPathLength - watchFolderPath.Length;
            Console.WriteLine($"                                                          ║");

            // Output Folder Location
            Console.WriteLine("║                                                                          ║");
            Console.Write("║  ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Reports Output Location:");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                                ║");

            // Handle output folder path similarly
            string outputFolderPath = "Reports";
            while (outputFolderPath.Length > maxPathLength)
            {
                Console.Write("║    ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("   ║");
                outputFolderPath = outputFolderPath.Substring(maxPathLength);
            }

            Console.Write("║    ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(outputFolderPath);
            Console.ForegroundColor = ConsoleColor.Cyan;
            remainingSpace = maxPathLength - outputFolderPath.Length;
            Console.WriteLine($"                                                               ║");

            // Commands Section
            Console.WriteLine("║                                                                          ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════════════════════════╣");
            Console.WriteLine("║                                                                          ║");
            Console.Write("║  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("Available Commands:");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("                                                     ║");
            Console.WriteLine("║                                                                          ║");

            // Command List
            WriteCommandLine("S", "Start scanning all pending items", "Green");
            WriteCommandLine("L", "List current pending items", "Cyan");
            WriteCommandLine("C", "Clear screen and show these instructions", "Yellow");
            WriteCommandLine("Q", "Quit the application", "Red");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("║                                                                          ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();
        }

        private void WriteCommandLine(string key, string description, string color)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("║    [");

            // Set the color for the key
            Console.ForegroundColor = (ConsoleColor)Enum.Parse(typeof(ConsoleColor), color);
            Console.Write(key);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("] ");

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(description);

            Console.ForegroundColor = ConsoleColor.Cyan;

            // Calculate padding needed for perfect alignment
            int totalWidth = key.Length + description.Length + 4; // 4 for "[]" and spaces
            int paddingNeeded = 53 - totalWidth;
            if (paddingNeeded < 0) paddingNeeded = 0;

            Console.WriteLine($"{new string(' ', paddingNeeded)}                  ║");
        }

        private void DisplayPendingScans()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("┌─ PENDING SCANS ──────────────────────────────────────────────────────┐");
            Console.ResetColor();

            if (_pendingScans.Count == 0)
            {
                Console.WriteLine("│                                                                     │");
                Console.WriteLine("│  No items waiting to be scanned.                                    │");
                Console.WriteLine("│                                                                     │");
            }
            else
            {
                Console.WriteLine("│                                                                     │");
                for (int i = 0; i < _pendingScans.Count; i++)
                {
                    var item = _pendingScans[i];
                    var itemName = Path.GetFileName(item);
                    var itemType = Directory.Exists(item) ? "Unity Game" : "DLL";
                    var listItem = $"  {i + 1}. [{itemType}] {itemName}";
                    Console.WriteLine($"│  {listItem.PadRight(67)}│");
                }
                Console.WriteLine("│                                                                     │");
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("└─────────────────────────────────────────────────────────────────────┘");
            Console.ResetColor();

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("Commands: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("S");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("]can  ");

            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("L");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("]ist  ");

            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("C");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("]lear  ");

            Console.Write("[");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("Q");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("]uit");
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine();
        }

        private void DetectNewDirectory(string fullPath, string name)
        {
            if (GameScanner.IsUnityGame(fullPath) && !_processedPaths.Contains(fullPath))
            {
                ShowDetectionMessage("Unity Game", name);
                _pendingScans.Add(fullPath);
            }
            else
            {
                // Scan directory for DLLs
                foreach (var dllFile in Directory.GetFiles(fullPath, "*.dll", SearchOption.AllDirectories))
                {
                    if (!_processedFiles.Contains(dllFile))
                    {
                        DetectNewDll(dllFile, Path.GetFileName(dllFile));
                    }
                }
            }
        }

        private void ShowDetectionMessage(string type, string name)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("╔═ NEW DETECTION ═════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                                                                         ║");

            string message = $" {type}: {name}";
            Console.Write("║  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+]");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Write($"{message.PadRight(68)}║");

            Console.WriteLine("\n║                                                                         ║");
            Console.WriteLine("╚═════════════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();

            DisplayPendingScans();
        }

        private void DetectNewDll(string fullPath, string name)
        {
            if (!_processedFiles.Contains(fullPath) && !_pendingScans.Contains(fullPath))
            {
                Console.WriteLine($"\n[+] New DLL detected: {name}");
                _pendingScans.Add(fullPath);
            }
        }

        public void ProcessGame(string gamePath)
        {
            try
            {
                Console.WriteLine($"\nScanning game at: {gamePath}");
                var result = GameScanner.ScanGame(gamePath);

                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║        Analyzing Security Findings       ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                // Use ML to enhance scan results
                result.Issues = result.Issues.EnhanceWithML(_mlAnalyzer);

                GenerateReport(result);
                _processedPaths.Add(gamePath);
                _pendingScans.Remove(gamePath);

                // Show ML training progress
                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║         Updating Security Model          ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                Console.WriteLine("\nℹ️ Using scan results to improve security detection...");
                _mlAnalyzer.UpdateModelWithScanResults(result.Issues, true);

                var stats = _mlAnalyzer.GetTrainingStats();
                Console.WriteLine($"\n📊 Model Statistics:");
                Console.WriteLine($"Total examples: {stats.totalExamples}");
                Console.WriteLine($"Model accuracy: {stats.accuracy:P2}");
                Console.WriteLine($"Last training: {stats.lastTraining:g}");

                Console.WriteLine("\n✨ Model update complete!");
                Console.WriteLine("\nPress any key to continue...");
                Console.ReadKey(true);
                DisplayInstructions();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning game at {gamePath}: {ex.Message}");
            }
        }


        private void ProcessDll(string dllPath)
        {
            try
            {
                var scanner = new SecurityScanner(dllPath);
                var issues = scanner.ScanForVulnerabilities();

                issues = issues.EnhanceWithML(_mlAnalyzer);

                var result = new GameScanner.ScanResult
                {
                    GameName = Path.GetFileNameWithoutExtension(dllPath),
                    AssemblyPath = dllPath,
                    Issues = issues
                };

                GenerateReport(result);
                _processedFiles.Add(dllPath);
                _pendingScans.Remove(dllPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning DLL {dllPath}: {ex.Message}");
            }
        }

        private void ProcessNewDll(string dllPath)
        {
            try
            {
                var scanner = new SecurityScanner(dllPath);
                var issues = scanner.ScanForVulnerabilities();

                var result = new GameScanner.ScanResult
                {
                    GameName = Path.GetFileNameWithoutExtension(dllPath),
                    AssemblyPath = dllPath,
                    Issues = issues
                };

                GenerateReport(result);
                _processedFiles.Add(dllPath);
                _pendingScans.Remove(dllPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning DLL {dllPath}: {ex.Message}");
            }
        }

        private void ProcessNewDll(string fullPath, string name)
        {
            if (_processedFiles.Contains(fullPath))
                return;

            Console.WriteLine($"New DLL detected: {name}");
            try
            {
                var scanner = new SecurityScanner(fullPath);
                var issues = scanner.ScanForVulnerabilities();

                var result = new GameScanner.ScanResult
                {
                    GameName = Path.GetFileNameWithoutExtension(name),
                    AssemblyPath = fullPath,
                    Issues = issues
                };

                GenerateReport(result);
                _processedFiles.Add(fullPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning DLL {name}: {ex.Message}");
            }
        }

        private string CreateReportHeader(string gameName)
        {
            return $@"<!DOCTYPE html>
<html data-theme='dark'>
<head>

<script>
    function toggleAssemblyList() {{
        var list = document.getElementById('assemblyList');
        var btn = document.querySelector('.toggle-btn');
        if (list.style.display === 'none') {{
            list.style.display = 'block';
            btn.textContent = 'Hide List';
        }} else {{
            list.style.display = 'none';
            btn.textContent = 'View List';
        }}
    }}
</script>

    <title>Security Report - {gameName}</title>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <style>
        :root {{
            --critical-color: #ff4444;
            --high-color: #ff8800;
            --medium-color: #ffbb33;
            --low-color: #00C851;
            
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #333333;
            --bg-highlight: #3a3a3a;
            
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --text-muted: #999999;
            
            --border-color: #404040;

            --chart-accent: #3498db;
            --chart-bg: #2c3e50;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: var(--bg-secondary);
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}

        .banner {{
            background-color: var(--bg-highlight);
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 8px;
            text-align: center;
            font-family: monospace;
            white-space: pre;
            overflow-x: auto;
            color: #3498db;
        }}

        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--border-color);
        }}

        .scan-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .meta-card {{
            background-color: var(--bg-tertiary);
            padding: 15px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}

        .meta-card h3 {{
            color: var(--chart-accent);
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .meta-value {{
            font-size: 1.2em;
            font-weight: bold;
        }}

        .issues-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .summary-card {{
            background-color: var(--bg-tertiary);
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            text-align: center;
        }}

        .summary-card.critical {{ border-top: 3px solid var(--critical-color); }}
        .summary-card.high {{ border-top: 3px solid var(--high-color); }}
        .summary-card.medium {{ border-top: 3px solid var(--medium-color); }}
        .summary-card.low {{ border-top: 3px solid var(--low-color); }}

        .issue {{
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            background-color: var(--bg-tertiary);
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}

        .issue.critical {{ border-left: 5px solid var(--critical-color); }}
        .issue.high {{ border-left: 5px solid var(--high-color); }}
        .issue.medium {{ border-left: 5px solid var(--medium-color); }}
        .issue.low {{ border-left: 5px solid var(--low-color); }}

        .issue-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .issue-title {{
            flex: 1;
            min-width: 300px;
        }}

        .issue-title h3 {{
            margin: 0;
            color: var(--text-primary);
        }}

        .issue-meta {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .badge {{
            font-size: 0.8em;
            padding: 4px 12px;
            border-radius: 4px;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }}

        .severity-badge {{
            color: var(--text-primary);
            font-weight: 500;
        }}

        .severity-badge.critical {{ background-color: var(--critical-color); }}
        .severity-badge.high {{ background-color: var(--high-color); }}
        .severity-badge.medium {{ background-color: var(--medium-color); }}
        .severity-badge.low {{ background-color: var(--low-color); }}

        .confidence-badge {{
            background-color: var(--bg-highlight);
            color: var(--text-secondary);
        }}

        .cvss-badge {{
            background-color: var(--chart-accent);
            color: var(--text-primary);
        }}

        .issue-content {{
            margin-top: 15px;
        }}

        .found-value {{
            background-color: var(--bg-primary);
            padding: 12px 15px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            border: 1px solid var(--border-color);
            margin: 8px 0;
            word-break: break-all;
            color: #7cb7ff;
        }}

        .context {{
            background-color: var(--bg-primary);
            padding: 15px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            border: 1px solid var(--border-color);
            margin: 8px 0;
            white-space: pre-wrap;
            font-size: 14px;
            line-height: 1.6;
            overflow-x: auto;
            color: #c5d1eb;
        }}

        .recommendation {{
            background-color: #1a2634;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
            border-left: 4px solid #3498db;
        }}

        .additional-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
            padding: 15px;
            background-color: var(--bg-primary);
            border-radius: 4px;
        }}

        .info-item {{
            padding: 10px;
        }}

        .info-item strong {{
            color: var(--chart-accent);
            display: block;
            margin-bottom: 5px;
            font-size: 0.9em;
        }}

        .line-number {{
            color: var(--text-muted);
            user-select: none;
            margin-right: 1em;
            font-size: 0.9em;
        }}

        .toggle-btn {{
            background-color: var(--bg-highlight);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s;
        }}

        .toggle-btn:hover {{
            background-color: var(--border-color);
        }}

        .table-container {{
            overflow-x: auto;
            margin: 20px 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            background-color: var(--bg-tertiary);
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background-color: var(--bg-highlight);
            font-weight: 500;
        }}

        tr:hover {{
            background-color: var(--bg-highlight);
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 15px;
            }}
            
            .issue-header {{
                flex-direction: column;
            }}
            
            .issue-meta {{
                justify-content: flex-start;
            }}
        }}

        /* Collapsible sections */
        .collapsible {{
            cursor: pointer;
            padding: 10px;
            width: 100%;
            text-align: left;
            background-color: var(--bg-highlight);
            border: none;
            border-radius: 4px;
            color: var(--text-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .content {{
            padding: 0 10px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: var(--bg-tertiary);
        }}

        .active {{
            max-height: none;
        }}

        .arrow {{
            border: solid var(--text-primary);
            border-width: 0 2px 2px 0;
            display: inline-block;
            padding: 3px;
            transform: rotate(45deg);
            transition: transform 0.2s;
        }}

        .active .arrow {{
            transform: rotate(-135deg);
        }}
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            // Initialize collapsible sections
            var coll = document.getElementsByClassName('collapsible');
            for (var i = 0; i < coll.length; i++) {{
                coll[i].addEventListener('click', function() {{
                    this.classList.toggle('active');
                    var content = this.nextElementSibling;
                    if (content.style.maxHeight) {{
                        content.style.maxHeight = null;
                    }} else {{
                        content.style.maxHeight = content.scrollHeight + 'px';
                    }}
                }});
            }}
        }});
    </script>
</head>
<body>
    <div class='container'>
        <div class='banner'>
██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╔╝██║ ╚████║██║   ██║      ██║       ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
======================================================================
              [CREATED BY 0XRETRODEV]  [BUILD: 0.1.14] 
======================================================================"";
        </div>

        <div class='header'>
            <h1>Security Scan Report</h1>
            <p>{gameName}</p>
            <p class='timestamp'>Generated on {DateTime.Now}</p>
        </div>";
        }

        public void GenerateReport(GameScanner.ScanResult result)
        {
            var reportPath = Path.Combine(_outputFolder, $"{result.GameName}_security_report.html");

            // Count issues by severity
            var criticalCount = result.Issues.Count(i => i.Severity.ToLower() == "critical");
            var highCount = result.Issues.Count(i => i.Severity.ToLower() == "high");
            var mediumCount = result.Issues.Count(i => i.Severity.ToLower() == "medium");
            var lowCount = result.Issues.Count(i => i.Severity.ToLower() == "low");

            // Calculate statistics
            var averageCvss = result.Issues.Any() ? result.Issues.Average(i => i.CvssScore) : 0;
            var averageConfidence = result.Issues.Any() ? result.Issues.Average(i => i.FalsePositiveConfidence) : 0;

            var reportContent = CreateReportHeader(result.GameName);
            reportContent += $@"
        <div class='scan-meta'>
            <div class='meta-card'>
                <h3>Scan Time</h3>
                <div class='meta-value'>{DateTime.Now:g}</div>
            </div>
            <div class='meta-card'>
                <h3>Average CVSS Score</h3>
                <div class='meta-value'>{averageCvss:F1}</div>
            </div>
            <div class='meta-card'>
                <h3>Detection Confidence</h3>
                <div class='meta-value'>{averageConfidence:P0}</div>
            </div>
            <div class='meta-card'>
                <h3>Assemblies Scanned</h3>
                <div class='meta-value'>{result.AssemblyPath.Split(',').Length}</div>
                <button class='toggle-btn' onclick='toggleAssemblyList()'>View List</button>
                <div id='assemblyList' style='display: none; margin-top: 10px; font-size: 0.8em;'>
                    {string.Join("<br>", result.AssemblyPath.Split(',').Select(a => a.Trim()))}
                </div>
            </div>
        </div>

        <div class='issues-summary'>
            <div class='summary-card critical'>
                <h3>{criticalCount}</h3>
                <p>Critical Issues</p>
            </div>
            <div class='summary-card high'>
                <h3>{highCount}</h3>
                <p>High Issues</p>
            </div>
            <div class='summary-card medium'>
                <h3>{mediumCount}</h3>
                <p>Medium Issues</p>
            </div>
            <div class='summary-card low'>
                <h3>{lowCount}</h3>
                <p>Low Issues</p>
            </div>
        </div>

        <button class='collapsible'>Scan Overview <span class='arrow'></span></button>
        <div class='content'>
            <div class='table-container'>
                <table>
                    <tr>
                        <th>Category</th>
                        <th>Count</th>
                        <th>Average CVSS</th>
                        <th>Confidence</th>
                    </tr>
                    {GenerateCategoryBreakdown(result.Issues)}
                </table>
            </div>
        </div>

        <h2 style='margin: 30px 0 20px 0;'>Detected Issues</h2>";

            // Group issues by severity for sorting
            var severityOrder = new Dictionary<string, int>
    {
        {"critical", 0},
        {"high", 1},
        {"medium", 2},
        {"low", 3}
    };

            var sortedIssues = result.Issues
                .OrderBy(i => severityOrder[i.Severity.ToLower()])
                .ThenByDescending(i => i.CvssScore);

            foreach (var issue in sortedIssues)
            {
                // Get ML confidence from AdditionalInfo
                var confidenceDisplay = "N/A";
                if (issue.AdditionalInfo != null && issue.AdditionalInfo.TryGetValue("ML_Confidence", out var confidence))
                {
                    confidenceDisplay = confidence;
                    // If the confidence is already in percentage format, use it as is
                    // Otherwise, try to parse and format it
                    if (!confidence.EndsWith("%"))
                    {
                        if (double.TryParse(confidence, out var confidenceValue))
                        {
                            confidenceDisplay = $"{confidenceValue:P1}";
                        }
                    }
                }

                reportContent += $@"
        <div class='issue {issue.Severity.ToLower()}'>
            <div class='issue-header'>
                <div class='issue-title'>
                    <h3>{issue.IssueType}</h3>
                    <small style='color: var(--text-muted);'>{issue.Location}</small>
                </div>
                <div class='issue-meta'>
                    <span class='badge severity-badge {issue.Severity.ToLower()}'>{issue.Severity}</span>
                    <span class='badge cvss-badge'>CVSS: {issue.CvssScore:F1}</span>
                    <span class='badge confidence-badge'>Confidence: {confidenceDisplay}</span>
                </div>
            </div>
            
            <div class='issue-content'>
                <p>{issue.Description}</p>
                
                <div style='margin-top: 15px;'>
                    <strong style='color: var(--chart-accent);'>Found Value:</strong>
                    <div class='found-value'>{issue.FoundValue}</div>
                </div>
                
                <div style='margin-top: 15px;'>
                    <strong style='color: var(--chart-accent);'>Context:</strong>
                    <div class='context'><span class='line-number'>{issue.LineNumber}</span>{issue.Context}</div>
                </div>
                
                <div class='recommendation'>
                    <strong style='color: var(--chart-accent);'>Recommendation:</strong><br>
                    {issue.Recommendation}
                </div>";
                if (issue.AdditionalInfo != null && issue.AdditionalInfo.Any())
                {
                    reportContent += @"
                <div class='additional-info'>";
                    // Skip ML_Confidence in additional info since we're showing it at the top
                    foreach (var info in issue.AdditionalInfo.Where(x => x.Key != "ML_Confidence"))
                    {
                        reportContent += $@"
                    <div class='info-item'>
                        <strong>{info.Key}</strong>
                        <span>{info.Value}</span>
                    </div>";
                    }
                    reportContent += @"
                </div>";
                }
                reportContent += @"
            </div>
        </div>";
            }
            reportContent += @"
    </div>
</body>
</html>";
            File.WriteAllText(reportPath, reportContent);
            Console.WriteLine($"Report generated: {reportPath}");
        }

        private string GenerateCategoryBreakdown(List<SecurityIssue> issues)
        {
            var categories = issues
                .GroupBy(i => i.AdditionalInfo != null && i.AdditionalInfo.ContainsKey("Category")
                    ? i.AdditionalInfo["Category"]
                    : "Other")
                .Select(g => new
                {
                    Category = g.Key,
                    Count = g.Count(),
                    AvgCvss = g.Average(i => i.CvssScore),
                    AvgConfidence = g.Average(i => i.FalsePositiveConfidence)
                });

            var breakdown = "";
            foreach (var cat in categories.OrderByDescending(c => c.Count))
            {
                breakdown += $@"
        <tr>
            <td>{cat.Category}</td>
            <td>{cat.Count}</td>
            <td>{cat.AvgCvss:F1}</td>
            <td>{cat.AvgConfidence:P0}</td>
        </tr>";
            }
            return breakdown;
        }

        public void StartMonitoring()
        {
            DisplayInstructions();

            // Process any existing Unity games and DLLs
            foreach (var directory in Directory.GetDirectories(_watchFolder))
            {
                DetectNewDirectory(directory, Path.GetFileName(directory));
            }

            foreach (var file in Directory.GetFiles(_watchFolder, "*.dll"))
            {
                DetectNewDll(file, Path.GetFileName(file));
            }

            if (_pendingScans.Any())
            {
                DisplayPendingScans();
            }

            // Interactive command loop
            while (_isRunning)
            {
                var key = Console.ReadKey(true);
                switch (char.ToUpper(key.KeyChar))
                {
                    case 'S':
                        ProcessAllPendingScans();
                        Console.WriteLine("\nScan complete. Press 'L' to view any remaining items.");
                        break;

                    case 'L':
                        DisplayPendingScans();
                        break;

                    case 'C':
                        Console.Clear();
                        DisplayInstructions();
                        if (_pendingScans.Any())
                        {
                            DisplayPendingScans();
                        }
                        break;

                    case 'Q':
                        _isRunning = false;
                        break;
                }
            }

            Console.WriteLine("\nShutting down scanner...");
        }

        private void ProcessAllPendingScans()
        {
            if (!_pendingScans.Any())
            {
                Console.WriteLine("\nNo items to scan.");
                return;
            }

            Console.WriteLine("\nStarting scan of all pending items...");

            var allResults = new List<SecurityScanner.SecurityIssue>();
            var scannedItems = new List<string>();

            // First, scan all pending items and collect results
            foreach (var item in _pendingScans.ToList())
            {
                try
                {
                    if (Directory.Exists(item))
                    {
                        var result = GameScanner.ScanGame(item);
                        allResults.AddRange(result.Issues);
                        _processedPaths.Add(item);
                        scannedItems.Add(item);
                        // Generate report for this game
                        GenerateReport(result);
                    }
                    else if (File.Exists(item))
                    {
                        var scanner = new SecurityScanner(item);
                        var issues = scanner.ScanForVulnerabilities();
                        allResults.AddRange(issues);
                        _processedFiles.Add(item);
                        scannedItems.Add(item);
                        // Generate report for this DLL
                        var result = new GameScanner.ScanResult
                        {
                            GameName = Path.GetFileNameWithoutExtension(item),
                            AssemblyPath = item,
                            Issues = issues
                        };
                        GenerateReport(result);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\nError scanning {item}: {ex.Message}");
                }
            }

            // Remove all successfully scanned items from pending list
            foreach (var item in scannedItems)
            {
                _pendingScans.Remove(item);
            }

            // If we have results, process them with the ML analyzer
            if (allResults.Any())
            {
                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║        Analyzing Security Findings       ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                // First enhance results with current model
                allResults = allResults.EnhanceWithML(_mlAnalyzer, false);

                // Update model with new examples
                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║         Updating Security Model          ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                Console.WriteLine("\nℹ️ Using scan results to improve security detection...");
                _mlAnalyzer.UpdateModelWithScanResults(allResults, true);

                // Get and display current metrics
                var currentMetrics = _mlAnalyzer.GetCurrentModelMetrics();
                if (currentMetrics != null)
                {
                    Console.WriteLine("\n╔══════════════════════════════════════════╗");
                    Console.WriteLine("║         Current Model Metrics           ║");
                    Console.WriteLine("╚══════════════════════════════════════════╝");
                    Console.WriteLine($"\nVersion: {currentMetrics.Version}");
                    Console.WriteLine($"Training Date: {currentMetrics.TrainingDate}");
                    Console.WriteLine($"Total Examples: {currentMetrics.TotalExamples}");
                    Console.WriteLine($"Accuracy: {currentMetrics.Accuracy:P2}");

                    Console.WriteLine("\nSeverity Distribution:");
                    foreach (var sev in currentMetrics.SeverityDistribution)
                    {
                        Console.WriteLine($"  {sev.Key}: {sev.Value}");
                    }
                }

                // Get latest training stats
                var stats = _mlAnalyzer.GetTrainingStats();
                Console.WriteLine($"\n📊 Latest Training Statistics:");
                Console.WriteLine($"Total examples: {stats.totalExamples}");
                Console.WriteLine($"Model accuracy: {stats.accuracy:P2}");
                Console.WriteLine($"Last training: {stats.lastTraining:g}");

                Console.WriteLine("\n✨ Model update complete!");
            }

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey(true);
            DisplayInstructions();
        }
    }
}