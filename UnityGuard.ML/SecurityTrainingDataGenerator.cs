using RetroDev.UnityGuard.UnityGuard.ML;

public class SecurityTrainingDataGenerator
{
    public List<SecurityIssueInput> GenerateComprehensiveTrainingData()
    {
        var trainingData = new List<SecurityIssueInput>();

        // Add Credential Security Examples
        trainingData.AddRange(new[]
        {
            CreateTrainingExample(
                issueType: "Hardcoded API Key",
                description: "Production API key directly embedded in source code",
                context: "private const string apiKey = \"AIzaSyA8B2DK3F9Xj2Q4K\"",
                foundValue: "AIzaSyA8B2DK3F9Xj2Q4K",
                cvssScore: 9.1f,
                severity: "Critical",
                location: "Assets/Scripts/NetworkManager.cs",
                containsHardcodedCreds: true,
                containsUnsafeCode: false,
                containsNetworkCalls: true,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "Hardcoded Database Credentials",
                description: "Database connection string with credentials in code",
                context: "connectionString = \"Server=prod.db;User=admin;Password=secretpass123\"",
                foundValue: "secretpass123",
                cvssScore: 8.9f,
                severity: "Critical",
                location: "Assets/Scripts/DatabaseService.cs",
                containsHardcodedCreds: true,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "Test API Key",
                description: "Test API key in test configuration",
                context: "const string testApiKey = \"test_key_12345\"",
                foundValue: "test_key_12345",
                cvssScore: 2.0f,
                severity: "Low",
                location: "Assets/Tests/NetworkTests.cs",
                containsHardcodedCreds: true,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: true
            )
        });

        // Add Code Security Examples
        trainingData.AddRange(new[]
        {
            CreateTrainingExample(
                issueType: "Unsafe Code Block",
                description: "Direct memory manipulation in unsafe code block",
                context: "unsafe { fixed (byte* ptr = &data[0]) { *ptr = 0xFF; } }",
                foundValue: "unsafe code block with pointer manipulation",
                cvssScore: 7.5f,
                severity: "High",
                location: "Assets/Scripts/MemoryManager.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: true,
                containsNetworkCalls: false,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "SQL Injection Risk",
                description: "Direct string concatenation in SQL query",
                context: "string query = \"SELECT * FROM Users WHERE id = '\" + userId + \"'\"",
                foundValue: "Unparameterized SQL query",
                cvssScore: 8.5f,
                severity: "Critical",
                location: "Assets/Scripts/UserDatabase.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: true,
                containsNetworkCalls: false,
                isInTestCode: false
            )
        });

        // Add Network Security Examples
        trainingData.AddRange(new[]
        {
            CreateTrainingExample(
                issueType: "Insecure HTTP Usage",
                description: "Using unencrypted HTTP for API communication",
                context: "var request = UnityWebRequest.Get(\"http://api.example.com/data\");",
                foundValue: "http://api.example.com",
                cvssScore: 7.2f,
                severity: "High",
                location: "Assets/Scripts/ApiClient.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: false,
                containsNetworkCalls: true,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "Certificate Validation Disabled",
                description: "SSL/TLS certificate validation explicitly disabled",
                context: "ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true;",
                foundValue: "ServerCertificateValidationCallback = true",
                cvssScore: 8.1f,
                severity: "Critical",
                location: "Assets/Scripts/NetworkConfig.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: false,
                containsNetworkCalls: true,
                isInTestCode: false
            )
        });

        // Add Data Security Examples
        trainingData.AddRange(new[]
        {
            CreateTrainingExample(
                issueType: "Insecure Serialization",
                description: "Usage of BinaryFormatter for serialization",
                context: "BinaryFormatter formatter = new BinaryFormatter(); formatter.Deserialize(stream);",
                foundValue: "BinaryFormatter usage",
                cvssScore: 7.8f,
                severity: "High",
                location: "Assets/Scripts/SaveSystem.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: true,
                containsNetworkCalls: false,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "Unencrypted Data Storage",
                description: "Sensitive data stored without encryption in PlayerPrefs",
                context: "PlayerPrefs.SetString(\"userToken\", authToken);",
                foundValue: "Unencrypted PlayerPrefs",
                cvssScore: 6.5f,
                severity: "Medium",
                location: "Assets/Scripts/UserData.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: false
            )
        });

        // Add Cryptographic Security Examples
        trainingData.AddRange(new[]
        {
            CreateTrainingExample(
                issueType: "Weak Hash Algorithm",
                description: "Usage of cryptographically broken MD5 hash",
                context: "using (MD5 md5 = MD5.Create()) { byte[] hash = md5.ComputeHash(data); }",
                foundValue: "MD5 usage",
                cvssScore: 6.8f,
                severity: "High",
                location: "Assets/Scripts/Crypto/HashGenerator.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "Hardcoded Encryption Key",
                description: "Static encryption key embedded in code",
                context: "private static readonly byte[] key = new byte[] { 0x01, 0x02, 0x03, 0x04 };",
                foundValue: "Static encryption key",
                cvssScore: 8.2f,
                severity: "Critical",
                location: "Assets/Scripts/Crypto/Encryptor.cs",
                containsHardcodedCreds: true,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: false
            )
        });

        // Add examples for other common Unity-specific security issues
        trainingData.AddRange(new[]
        {
            CreateTrainingExample(
                issueType: "Exposed Unity Event",
                description: "Security-sensitive Unity event exposed to Unity Editor",
                context: "public UnityEvent onUserAuthenticated;",
                foundValue: "Public UnityEvent",
                cvssScore: 4.2f,
                severity: "Medium",
                location: "Assets/Scripts/Authentication/AuthEvents.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: false
            ),
            CreateTrainingExample(
                issueType: "Debug Mode Check",
                description: "Missing debug mode check in production build",
                context: "if(Debug.isDebugBuild) { ShowDebugMenu(); }",
                foundValue: "Debug.isDebugBuild",
                cvssScore: 3.5f,
                severity: "Low",
                location: "Assets/Scripts/UI/DebugMenu.cs",
                containsHardcodedCreds: false,
                containsUnsafeCode: false,
                containsNetworkCalls: false,
                isInTestCode: false
            )
        });

        // Common C# Security Issues
        trainingData.AddRange(new[] {
                CreateTrainingExample(
                    issueType: "LINQ Injection Risk",
                    description: "Dynamic LINQ query with unvalidated input",
                    context: "database.Users.Where(\"Username = '\" + userInput + \"'\");",
                    foundValue: "Unparameterized LINQ query",
                    cvssScore: 7.8f,
                    severity: "High",
                    location: "DataAccess.dll/UserRepository.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: false,
                    containsNetworkCalls: false,
                    isInTestCode: false
                ),
                CreateTrainingExample(
                    issueType: "Insecure Serialization",
                    description: "Usage of BinaryFormatter for network data",
                    context: "BinaryFormatter formatter = new BinaryFormatter(); formatter.Deserialize(networkStream);",
                    foundValue: "BinaryFormatter usage",
                    cvssScore: 8.0f,
                    severity: "High",
                    location: "NetworkLib.dll/PacketHandler.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: false,
                    containsNetworkCalls: true,
                    isInTestCode: false
                )
            });

        // DLL Security Issues
        trainingData.AddRange(new[] {
                CreateTrainingExample(
                    issueType: "Reflection Security Risk",
                    description: "Unsafe use of reflection to access private members",
                    context: "typeof(TargetClass).GetField(\"privateField\", BindingFlags.NonPublic | BindingFlags.Instance)",
                    foundValue: "Reflection usage to bypass access controls",
                    cvssScore: 7.2f,
                    severity: "High",
                    location: "GameLogic.dll/SecurityBypass.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: true,
                    containsNetworkCalls: false,
                    isInTestCode: false
                ),
                CreateTrainingExample(
                    issueType: "Assembly Load Without Verification",
                    description: "Loading assemblies without proper verification",
                    context: "Assembly.Load(assemblyBytes);",
                    foundValue: "Unverified assembly loading",
                    cvssScore: 8.4f,
                    severity: "Critical",
                    location: "ModLoader.dll/AssemblyLoader.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: true,
                    containsNetworkCalls: false,
                    isInTestCode: false
                )
            });

        // Unity-Specific Security Issues
        trainingData.AddRange(new[] {
                CreateTrainingExample(
                    issueType: "Insecure PlayerPrefs Usage",
                    description: "Storing sensitive data in PlayerPrefs without encryption",
                    context: "PlayerPrefs.SetString(\"userToken\", authenticationToken);",
                    foundValue: "Unencrypted authentication token storage",
                    cvssScore: 7.5f,
                    severity: "High",
                    location: "Assets/Scripts/AuthManager.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: false,
                    containsNetworkCalls: false,
                    isInTestCode: false
                ),
                CreateTrainingExample(
                    issueType: "Unity WebRequest Without Certificate Validation",
                    description: "SSL/TLS certificate validation disabled in Unity web requests",
                    context: "UnityWebRequest.CertificateHandler = new BypassCertificateHandler();",
                    foundValue: "Certificate validation bypass",
                    cvssScore: 8.1f,
                    severity: "Critical",
                    location: "Assets/Scripts/NetworkManager.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: false,
                    containsNetworkCalls: true,
                    isInTestCode: false
                )
            });

        // Mobile Game Security Issues
        trainingData.AddRange(new[] {
                CreateTrainingExample(
                    issueType: "Insufficient Anti-Cheat Protection",
                    description: "Game variables exposed without memory protection",
                    context: "public int playerGold = 1000;",
                    foundValue: "Unprotected game variable",
                    cvssScore: 6.5f,
                    severity: "Medium",
                    location: "Assets/Scripts/PlayerStats.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: true,
                    containsNetworkCalls: false,
                    isInTestCode: false
                ),
                CreateTrainingExample(
                    issueType: "Insecure Random Number Generation",
                    description: "Using predictable random number generation for game mechanics",
                    context: "Random.Range(1, 100)",
                    foundValue: "Non-cryptographic RNG",
                    cvssScore: 5.2f,
                    severity: "Medium",
                    location: "Assets/Scripts/LootSystem.cs",
                    containsHardcodedCreds: false,
                    containsUnsafeCode: false,
                    containsNetworkCalls: false,
                    isInTestCode: false
                )
            });

        // Add these examples to your existing GenerateComprehensiveTrainingData() method

        // Multiplayer Game Security Issues
        trainingData.AddRange(new[] {
        CreateTrainingExample(
            issueType: "Client Authority Abuse Risk",
            description: "Client has authority over critical game state that should be server-authoritative",
            context: @"[ClientRpc]
                public void UpdatePlayerStats(int health, int armor, int damage) {
                    playerHealth = health;
                    playerArmor = armor;
                    playerDamage = damage;
                }",
            foundValue: "Client-authoritative player stats",
            cvssScore: 8.7f,
            severity: "Critical",
            location: "Assets/Scripts/Networking/PlayerSync.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Unsanitized Network Input",
            description: "Network input processed without validation, allowing potential exploitation",
            context: @"void OnReceiveMovement(Vector3 newPosition, Quaternion newRotation) {
                transform.position = newPosition;
                transform.rotation = newRotation;
            }",
            foundValue: "Unvalidated position and rotation updates",
            cvssScore: 7.5f,
            severity: "High",
            location: "Assets/Scripts/Networking/PlayerMovement.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Network Message Flooding Risk",
            description: "No rate limiting on network message processing",
            context: @"[Command]
                void CmdFireWeapon() {
                    SpawnProjectile();
                    ApplyDamage();
                }",
            foundValue: "Unchecked command spam potential",
            cvssScore: 6.8f,
            severity: "Medium",
            location: "Assets/Scripts/Weapons/WeaponController.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Insecure Room Configuration",
            description: "Room settings can be manipulated by clients",
            context: @"public class GameRoom {
                public bool friendlyFire;
                public int maxPlayers;
                public float gameSpeed;
                
                [PunRPC]
                public void UpdateRoomSettings(bool ff, int players, float speed) {
                    friendlyFire = ff;
                    maxPlayers = players;
                    gameSpeed = speed;
                }
            }",
            foundValue: "Client-modifiable room settings",
            cvssScore: 7.2f,
            severity: "High",
            location: "Assets/Scripts/Multiplayer/GameRoom.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        )
    });

        // Game State Manipulation Issues
        trainingData.AddRange(new[] {
        CreateTrainingExample(
            issueType: "Memory Value Exposure",
            description: "Critical game values stored without protection against memory editing",
            context: @"public class PlayerInventory : MonoBehaviour {
                public int goldAmount;
                public List<string> items;
                public Dictionary<string, int> resources;
                
                void UpdateInventory() {
                    goldAmount += earnedGold;
                    items.AddRange(newItems);
                }
            }",
            foundValue: "Unprotected inventory values",
            cvssScore: 8.1f,
            severity: "High",
            location: "Assets/Scripts/Player/Inventory.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Save Game Tampering Risk",
            description: "Save game data stored without integrity checking",
            context: @"void SaveGameState() {
                PlayerPrefs.SetInt(""PlayerLevel"", currentLevel);
                PlayerPrefs.SetInt(""PlayerGold"", goldAmount);
                PlayerPrefs.SetString(""Inventory"", JsonUtility.ToJson(inventory));
                PlayerPrefs.Save();
            }",
            foundValue: "Unprotected save game data",
            cvssScore: 7.4f,
            severity: "High",
            location: "Assets/Scripts/SaveSystem/GameSaver.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Time Manipulation Vulnerability",
            description: "Game logic relies on client-side time without server validation",
            context: @"void UpdateResourceGeneration() {
                float timeSinceLastUpdate = Time.time - lastUpdateTime;
                resources += resourcePerSecond * timeSinceLastUpdate;
                lastUpdateTime = Time.time;
            }",
            foundValue: "Client-side time-based calculation",
            cvssScore: 6.9f,
            severity: "Medium",
            location: "Assets/Scripts/Resources/ResourceGenerator.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        )
    });

        // In-App Purchase Security Issues
        trainingData.AddRange(new[] {
        CreateTrainingExample(
            issueType: "Receipt Validation Bypass",
            description: "Insufficient validation of in-app purchase receipts",
            context: @"public void OnPurchaseComplete(Product product) {
                if(product.hasReceipt) {
                    GivePlayerCoins(product.definition.id);
                    UnlockContent(product.definition.id);
                }
            }",
            foundValue: "Basic receipt check only",
            cvssScore: 9.2f,
            severity: "Critical",
            location: "Assets/Scripts/IAP/PurchaseManager.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Local IAP Validation",
            description: "In-app purchase validation performed client-side only",
            context: @"public void ValidatePurchase(string productId, string receipt) {
                var receiptData = JsonUtility.FromJson<ReceiptData>(receipt);
                if(receiptData.signedData.Equals(ComputeExpectedSignature())) {
                    GrantPurchaseRewards(productId);
                }
            }",
            foundValue: "Client-side receipt validation",
            cvssScore: 8.8f,
            severity: "Critical",
            location: "Assets/Scripts/Store/PurchaseValidator.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Premium Currency Manipulation",
            description: "Premium currency stored locally without server verification",
            context: @"public class PremiumCurrency : MonoBehaviour {
                public int gems;
                public void AddGems(int amount) {
                    gems += amount;
                    PlayerPrefs.SetInt(""PremiumGems"", gems);
                    PlayerPrefs.Save();
                }
            }",
            foundValue: "Locally stored premium currency",
            cvssScore: 8.5f,
            severity: "Critical",
            location: "Assets/Scripts/Currency/PremiumCurrency.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Purchase Event Replay Risk",
            description: "Purchase completion events can be replayed",
            context: @"[PunRPC]
            public void CompletePurchase(string productId, int amount) {
                inventory.AddItem(productId, amount);
                currency.AddCoins(bonusCoins);
                UpdatePlayerStatus();
            }",
            foundValue: "Replayable purchase completion",
            cvssScore: 8.3f,
            severity: "High",
            location: "Assets/Scripts/Store/StoreManager.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Store Price Manipulation",
            description: "Store prices defined and validated client-side",
            context: @"public class StoreItem {
                public string itemId;
                public int price;
                
                public bool CanPurchase(PlayerData player) {
                    return player.coins >= price;
                }
                
                public void Purchase(PlayerData player) {
                    if(CanPurchase(player)) {
                        player.coins -= price;
                        player.inventory.AddItem(itemId);
                    }
                }
            }",
            foundValue: "Client-side price checking",
            cvssScore: 7.8f,
            severity: "High",
            location: "Assets/Scripts/Store/StoreItem.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        )
    });

        // Anti-Cheat and Memory Protection Examples
        trainingData.AddRange(new[] {
        CreateTrainingExample(
            issueType: "Exposed Memory Variable",
            description: "Critical game variable exposed to memory editing tools",
            context: @"public class PlayerStats : MonoBehaviour {
                public int health = 100;
                public float moveSpeed = 5f;
                public int ammunition = 30;
                
                void Update() {
                    if(health <= 0) {
                        Die();
                    }
                }
            }",
            foundValue: "Public variables vulnerable to memory editing",
            cvssScore: 8.4f,
            severity: "Critical",
            location: "Assets/Scripts/Player/PlayerStats.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Unprotected Critical Function",
            description: "Game-critical function without memory integrity checking",
            context: @"public class WeaponSystem : MonoBehaviour {
                private int _ammo = 30;
                
                public void Fire() {
                    if(_ammo > 0) {
                        _ammo--;
                        FireProjectile();
                    }
                }
                
                public void AddAmmo(int amount) {
                    _ammo += amount;
                }
            }",
            foundValue: "Direct memory-modifiable ammo system",
            cvssScore: 7.8f,
            severity: "High",
            location: "Assets/Scripts/Weapons/WeaponSystem.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Speed Hack Vulnerability",
            description: "Time-based mechanics vulnerable to speed manipulation",
            context: @"public class MovementController : MonoBehaviour {
                public float moveSpeed = 5f;
                
                void Update() {
                    float horizontalInput = Input.GetAxis(""Horizontal"");
                    float verticalInput = Input.GetAxis(""Vertical"");
                    
                    transform.position += new Vector3(
                        horizontalInput * moveSpeed * Time.deltaTime,
                        0,
                        verticalInput * moveSpeed * Time.deltaTime
                    );
                }
            }",
            foundValue: "Unprotected time-based movement",
            cvssScore: 7.2f,
            severity: "High",
            location: "Assets/Scripts/Player/MovementController.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Wall Hack Risk",
            description: "Renderer settings vulnerable to wall hack cheats",
            context: @"public class WallSystem : MonoBehaviour {
                void Start() {
                    foreach(var wall in GameObject.FindGameObjectsWithTag(""Wall"")) {
                        wall.GetComponent<MeshRenderer>().enabled = true;
                        wall.GetComponent<Collider>().enabled = true;
                    }
                }
            }",
            foundValue: "Separate renderer and collider controls",
            cvssScore: 6.5f,
            severity: "Medium",
            location: "Assets/Scripts/Environment/WallSystem.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Memory Integrity Check Bypass",
            description: "Insufficient memory integrity checking mechanism",
            context: @"public class AntiCheatSystem : MonoBehaviour {
                private Dictionary<string, int> _memoryChecksums = new Dictionary<string, int>();
                
                void CalculateChecksum(string variableName, int value) {
                    _memoryChecksums[variableName] = value.GetHashCode();
                }
                
                bool ValidateChecksum(string variableName, int value) {
                    return _memoryChecksums[variableName] == value.GetHashCode();
                }
            }",
            foundValue: "Simple hashcode-based integrity check",
            cvssScore: 8.1f,
            severity: "High",
            location: "Assets/Scripts/Security/AntiCheatSystem.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Direct Memory Write Risk",
            description: "Critical game values stored in directly writable memory",
            context: @"public class PlayerInventory : MonoBehaviour {
                public struct InventoryData {
                    public int gold;
                    public int gems;
                    public List<string> items;
                }
                
                public InventoryData playerInventory;
                
                public void AddGold(int amount) {
                    playerInventory.gold += amount;
                }
            }",
            foundValue: "Directly modifiable inventory structure",
            cvssScore: 8.7f,
            severity: "Critical",
            location: "Assets/Scripts/Player/PlayerInventory.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Aim Bot Vulnerability",
            description: "Player aim mechanics vulnerable to automation",
            context: @"public class WeaponAiming : MonoBehaviour {
                public float aimSensitivity = 2f;
                
                void Update() {
                    float mouseX = Input.GetAxis(""Mouse X"") * aimSensitivity;
                    float mouseY = Input.GetAxis(""Mouse Y"") * aimSensitivity;
                    
                    transform.Rotate(Vector3.up * mouseX);
                    Camera.main.transform.Rotate(Vector3.left * mouseY);
                }
            }",
            foundValue: "Unprotected aiming mechanics",
            cvssScore: 7.4f,
            severity: "High",
            location: "Assets/Scripts/Weapons/WeaponAiming.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Debug Mode Exploit",
            description: "Debug features accessible in release builds",
            context: @"public class DebugController : MonoBehaviour {
                void Update() {
                    if(Input.GetKeyDown(KeyCode.F1)) {
                        PlayerStats.GodMode = !PlayerStats.GodMode;
                    }
                    if(Input.GetKeyDown(KeyCode.F2)) {
                        Inventory.UnlockAllItems();
                    }
                }
            }",
            foundValue: "Accessible debug cheats",
            cvssScore: 8.2f,
            severity: "Critical",
            location: "Assets/Scripts/Debug/DebugController.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Physics Manipulation Risk",
            description: "Physics parameters vulnerable to memory editing",
            context: @"public class CharacterPhysics : MonoBehaviour {
                public float jumpForce = 10f;
                public float gravity = -9.81f;
                
                void Update() {
                    if(Input.GetButtonDown(""Jump"")) {
                        GetComponent<Rigidbody>().AddForce(Vector3.up * jumpForce, ForceMode.Impulse);
                    }
                    
                    Physics.gravity = new Vector3(0, gravity, 0);
                }
            }",
            foundValue: "Modifiable physics values",
            cvssScore: 6.8f,
            severity: "Medium",
            location: "Assets/Scripts/Physics/CharacterPhysics.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "State Manipulation Vulnerability",
            description: "Game state values stored without encryption or validation",
            context: @"[System.Serializable]
            public class GameState {
                public int score;
                public int level;
                public float playTime;
                public Dictionary<string, int> achievements;
                
                public void SaveState() {
                    string jsonState = JsonUtility.ToJson(this);
                    PlayerPrefs.SetString(""GameState"", jsonState);
                }
                
                public void LoadState() {
                    string jsonState = PlayerPrefs.GetString(""GameState"");
                    JsonUtility.FromJsonOverwrite(jsonState, this);
                }
            }",
            foundValue: "Unencrypted game state storage",
            cvssScore: 7.9f,
            severity: "High",
            location: "Assets/Scripts/Core/GameState.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        )
    });

        // DLL and SDK Security Examples
        trainingData.AddRange(new[] {
        CreateTrainingExample(
            issueType: "Unsafe Native Method Import",
            description: "DLL import without proper security checks or bounds validation",
            context: @"public class NativeLibrary {
                [DllImport(""external.dll"", CallingConvention = CallingConvention.Cdecl)]
                public static extern void ProcessData(byte[] data, int length);
                
                public static void HandleData(byte[] input) {
                    ProcessData(input, input.Length);
                }
            }",
            foundValue: "Unvalidated DLL import call",
            cvssScore: 8.5f,
            severity: "Critical",
            location: "ExternalLibrary.dll/NativeImports.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Insecure Configuration Loading",
            description: "SDK configuration loaded without validation or encryption",
            context: @"public class SdkConfiguration {
                public string apiEndpoint;
                public string clientSecret;
                public Dictionary<string, string> settings;
                
                public static SdkConfiguration LoadConfig(string path) {
                    var json = File.ReadAllText(path);
                    return JsonConvert.DeserializeObject<SdkConfiguration>(json);
                }
            }",
            foundValue: "Unencrypted configuration loading",
            cvssScore: 7.2f,
            severity: "High",
            location: "SDK.dll/Configuration/ConfigLoader.cs",
            containsHardcodedCreds: true,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Unprotected SDK Initialization",
            description: "SDK initialization without license or integrity verification",
            context: @"public class SdkInitializer {
                public static void Initialize(string licenseKey) {
                    if(!string.IsNullOrEmpty(licenseKey)) {
                        InitializeComponents();
                        StartServices();
                    }
                }
            }",
            foundValue: "Basic license check only",
            cvssScore: 6.8f,
            severity: "Medium",
            location: "SDK.dll/Core/Initializer.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Unsafe Reflection Usage",
            description: "Dynamic type loading without proper validation",
            context: @"public class PluginLoader {
                public static object LoadPlugin(string assemblyPath, string typeName) {
                    Assembly assembly = Assembly.LoadFrom(assemblyPath);
                    Type type = assembly.GetType(typeName);
                    return Activator.CreateInstance(type);
                }
            }",
            foundValue: "Unvalidated assembly loading",
            cvssScore: 8.7f,
            severity: "Critical",
            location: "Framework.dll/Plugin/PluginLoader.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Exposed Internal API",
            description: "Internal API methods exposed through public interface",
            context: @"public class ApiClient {
                internal void ProcessInternalData(byte[] data) {
                    // Internal processing
                }
                
                [EditorBrowsable(EditorBrowsableState.Never)]
                public void ProcessData(byte[] data) {
                    ProcessInternalData(data);
                }
            }",
            foundValue: "Public exposure of internal method",
            cvssScore: 5.5f,
            severity: "Medium",
            location: "ApiClient.dll/Client/ApiClient.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Unprotected Sensitive Method",
            description: "Security-sensitive method without access control",
            context: @"public class LicenseManager {
                public static bool ValidateLicense(string key) {
                    return ComputeLicenseHash(key) == storedHash;
                }
                
                public static string ComputeLicenseHash(string input) {
                    using (var md5 = MD5.Create()) {
                        byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                        return BitConverter.ToString(hash).Replace(""-"", """");
                    }
                }
            }",
            foundValue: "Exposed license validation logic",
            cvssScore: 7.8f,
            severity: "High",
            location: "Licensing.dll/Manager/LicenseManager.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Insecure Temporary File Handling",
            description: "Temporary files created without proper security measures",
            context: @"public class TempFileHandler {
                public static string CreateTempFile(byte[] data) {
                    string path = Path.GetTempFileName();
                    File.WriteAllBytes(path, data);
                    return path;
                }
            }",
            foundValue: "Unsecured temporary file creation",
            cvssScore: 6.5f,
            severity: "Medium",
            location: "Utils.dll/IO/TempFileHandler.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Database Connection String Exposure",
            description: "Hard-coded database connection strings in SDK",
            context: @"public class DatabaseProvider {
                private static readonly string ConnectionString = 
                    ""Server=database.server.com;Database=ProductionDB;User=admin;Password=SecurePass123!"";
                
                public static SqlConnection GetConnection() {
                    return new SqlConnection(ConnectionString);
                }
            }",
            foundValue: "Hardcoded production database credentials",
            cvssScore: 9.1f,
            severity: "Critical",
            location: "DataAccess.dll/Providers/DatabaseProvider.cs",
            containsHardcodedCreds: true,
            containsUnsafeCode: false,
            containsNetworkCalls: true,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Weak Cryptographic Implementation",
            description: "Usage of deprecated cryptographic methods in SDK",
            context: @"public class Encryptor {
                public static string EncryptData(string data) {
                    using (var des = new DESCryptoServiceProvider()) {
                        byte[] input = Encoding.UTF8.GetBytes(data);
                        return Convert.ToBase64String(
                            des.CreateEncryptor().TransformFinalBlock(input, 0, input.Length)
                        );
                    }
                }
            }",
            foundValue: "DES encryption usage",
            cvssScore: 7.4f,
            severity: "High",
            location: "Security.dll/Crypto/Encryptor.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: false,
            containsNetworkCalls: false,
            isInTestCode: false
        ),
        CreateTrainingExample(
            issueType: "Memory Leak in Native Interop",
            description: "Unmanaged resources not properly disposed",
            context: @"public class NativeInterop {
                [DllImport(""native.dll"")]
                private static extern IntPtr AllocateResource();
                
                public static void ProcessResource() {
                    IntPtr handle = AllocateResource();
                    // Resource never freed
                    UseResource(handle);
                }
            }",
            foundValue: "Unmanaged resource leak",
            cvssScore: 6.2f,
            severity: "Medium",
            location: "Interop.dll/Native/NativeInterop.cs",
            containsHardcodedCreds: false,
            containsUnsafeCode: true,
            containsNetworkCalls: false,
            isInTestCode: false
        )
    });

        return trainingData;
    }

    private SecurityIssueInput CreateTrainingExample(
        string issueType,
        string description,
        string context,
        string foundValue,
        float cvssScore,
        string severity,
        string location,
        bool containsHardcodedCreds,
        bool containsUnsafeCode,
        bool containsNetworkCalls,
        bool isInTestCode)
    {
        return new SecurityIssueInput
        {
            IssueType = issueType,
            Description = description,
            Context = context,
            FoundValue = foundValue,
            CvssScore = cvssScore,
            Location = location,
            ContainsHardcodedCredentials = containsHardcodedCreds,
            ContainsUnsafeCode = containsUnsafeCode,
            ContainsNetworkCalls = containsNetworkCalls,
            IsInTestCode = isInTestCode,
            Severity = severity
        };
    }
}