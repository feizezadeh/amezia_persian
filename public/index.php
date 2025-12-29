<?php
/**
 * Amnezia VPN Web Panel
 * Main entry point
 */

session_name(getenv('SESSION_NAME') ?: 'amnezia_panel_session');
session_start();

// Load dependencies
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/Auth.php';
require_once __DIR__ . '/../inc/Router.php';
require_once __DIR__ . '/../inc/View.php';
require_once __DIR__ . '/../inc/VpnServer.php';
require_once __DIR__ . '/../inc/VpnClient.php';
require_once __DIR__ . '/../inc/Translator.php';
require_once __DIR__ . '/../inc/JWT.php';
require_once __DIR__ . '/../inc/PanelImporter.php';
require_once __DIR__ . '/../inc/ServerMonitoring.php';
require_once __DIR__ . '/../inc/LdapSync.php';

// Load environment configuration
Config::load(__DIR__ . '/../.env');

// Test database connection
try {
    DB::conn();
} catch (Throwable $e) {
    die('Database connection error: ' . $e->getMessage());
}

// Seed admin user if not exists
try {
    $adminEmail = Config::get('ADMIN_EMAIL');
    $adminPass = Config::get('ADMIN_PASSWORD');
    if ($adminEmail && $adminPass) {
        Auth::seedAdmin($adminEmail, $adminPass);
    }
} catch (Throwable $e) {
    // Ignore errors
}

// Initialize translator
Translator::init();

// Initialize template engine
$user = Auth::user();
$appName = Config::get('APP_NAME', 'Amnezia VPN Panel');

/**
 * Helper function to authenticate user from JWT or session
 * Returns user array or null if unauthorized
 */
function authenticateRequest(): ?array {
    // Check JWT token in Authorization header
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        $token = $matches[1];
        $user = JWT::verify($token);
        if ($user) {
            return $user;
        }
    }
    
    // Fallback to session
    if (isset($_SESSION['user_id'])) {
        return Auth::user();
    }
    
    return null;
}

View::init(__DIR__ . '/../templates', [
    'app_name' => $appName,
    'user' => $user,
    'current_language' => Translator::getCurrentLanguage(),
    'languages' => Translator::getSupportedLanguages(),
    'current_uri' => $_SERVER['REQUEST_URI'] ?? '/dashboard',
    't' => function($key, $params = []) {
        return Translator::t($key, $params);
    }
]);

// Helper function for redirects
function redirect(string $to): void {
    header('Location: ' . $to);
    exit;
}

function renderReactApp(): void {
    $path = __DIR__ . '/app/index.html';
    if (!file_exists($path)) {
        http_response_code(404);
        echo 'App not built. Run npm run build in frontend/';
        return;
    }
    header('Content-Type: text/html; charset=utf-8');
    readfile($path);
}

function isJsonRequest(): bool {
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    $requestedWith = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

    if ($requestedWith !== '' && stripos($requestedWith, 'xmlhttprequest') !== false) {
        return true;
    }
    if ($accept !== '' && stripos($accept, 'application/json') !== false) {
        return true;
    }
    if ($contentType !== '' && stripos($contentType, 'application/json') !== false) {
        return true;
    }
    return false;
}

// Helper function to require authentication
function requireAuth(): void {
    if (!Auth::check()) {
        if (isJsonRequest()) {
            http_response_code(401);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        redirect('/login');
    }
}

// Helper function to require admin
function requireAdmin(): void {
    requireAuth();
    if (!Auth::isAdmin()) {
        http_response_code(403);
        echo 'Forbidden: Admin access required';
        exit;
    }
}

// Helper function to get authenticated user (JWT or session)
function getAuthUser(): ?array {
    // Try JWT first
    $token = JWT::getTokenFromHeader();
    if ($token !== null) {
        $user = JWT::verify($token);
        if ($user !== null) {
            return $user;
        }
    }
    
    // Fall back to session
    if (Auth::check()) {
        return Auth::user();
    }
    
    return null;
}

// Helper function to require authentication (JWT or session) for API
function requireApiAuth(): ?array {
    $user = getAuthUser();
    
    if ($user === null) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Authentication required']);
        return null;
    }
    
    return $user;
}

function buildShareUrl(string $token): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $path = '/share/' . rawurlencode($token);
    if ($host === '') {
        return $path;
    }
    return $scheme . '://' . $host . $path;
}

function buildProtocolGroupsFromClient(array $clientData): array {
    $protocolGroups = [];
    $decoded = json_decode($clientData['protocols'] ?? '[]', true);
    if (!is_array($decoded)) {
        return $protocolGroups;
    }

    foreach ($decoded as $containerConfig) {
        $containerName = $containerConfig['container'] ?? '';
        if ($containerName === 'amnezia-awg' && !empty($containerConfig['awg']['last_config'])) {
            $protocolGroups[] = [
                'title_key' => 'protocols.awg',
                'items' => [
                    ['label_key' => 'protocols.awg', 'protocol' => 'awg', 'container' => $containerName],
                ],
            ];
        } elseif ($containerName === 'amnezia-wireguard' && !empty($containerConfig['wireguard']['last_config'])) {
            $protocolGroups[] = [
                'title_key' => 'protocols.wireguard',
                'items' => [
                    ['label_key' => 'protocols.wireguard', 'protocol' => 'wireguard', 'container' => $containerName],
                ],
            ];
        } elseif ($containerName === 'amnezia-openvpn' && !empty($containerConfig['openvpn']['last_config'])) {
            $protocolGroups[] = [
                'title_key' => 'protocols.openvpn',
                'items' => [
                    ['label_key' => 'protocols.openvpn', 'protocol' => 'openvpn', 'container' => $containerName],
                ],
            ];
        } elseif ($containerName === 'amnezia-shadowsocks') {
            $items = [];
            if (!empty($containerConfig['openvpn']['last_config'])) {
                $items[] = ['label_key' => 'protocols.openvpn', 'protocol' => 'openvpn', 'container' => $containerName];
            }
            if (!empty($containerConfig['shadowsocks']['last_config'])) {
                $items[] = ['label_key' => 'protocols.shadowsocks', 'protocol' => 'shadowsocks', 'container' => $containerName];
            }
            if ($items) {
                $protocolGroups[] = [
                    'title_key' => 'protocols.openvpn_shadowsocks',
                    'items' => $items,
                ];
            }
        } elseif ($containerName === 'amnezia-openvpn-cloak') {
            $items = [];
            if (!empty($containerConfig['openvpn']['last_config'])) {
                $items[] = ['label_key' => 'protocols.openvpn', 'protocol' => 'openvpn', 'container' => $containerName];
            }
            if (!empty($containerConfig['shadowsocks']['last_config'])) {
                $items[] = ['label_key' => 'protocols.shadowsocks', 'protocol' => 'shadowsocks', 'container' => $containerName];
            }
            if (!empty($containerConfig['cloak']['last_config'])) {
                $items[] = ['label_key' => 'protocols.cloak', 'protocol' => 'cloak', 'container' => $containerName];
            }
            if ($items) {
                $protocolGroups[] = [
                    'title_key' => 'protocols.openvpn_cloak',
                    'items' => $items,
                ];
            }
        } elseif ($containerName === 'amnezia-ipsec' && !empty($containerConfig['ikev2']['last_config'])) {
            $protocolGroups[] = [
                'title_key' => 'protocols.ikev2',
                'items' => [
                    ['label_key' => 'protocols.ikev2', 'protocol' => 'ikev2', 'container' => $containerName],
                ],
            ];
        }
    }

    return $protocolGroups;
}

function buildQrCodesFromClient(array $clientData): array {
    $qrCodes = [];
    $qrRaw = $clientData['qr_code'] ?? '';
    if ($qrRaw === '') {
        return $qrCodes;
    }

    $decoded = json_decode($qrRaw, true);
    if (is_array($decoded) && isset($decoded['items']) && is_array($decoded['items'])) {
        return $decoded['items'];
    }

    $qrCodes[] = [
        'label_key' => 'clients.qr_code',
        'qr' => $qrRaw,
    ];
    return $qrCodes;
}

function parseProtocolOverridesInput(array $input): array {
    $errors = [];
    $overrides = [];
    $validatePort = function (int $port): bool {
        return $port > 0 && $port <= 65535;
    };
    $validateRange = function (string $range): bool {
        if (!preg_match('/^\d{1,5}-\d{1,5}$/', $range)) {
            return false;
        }
        [$start, $end] = array_map('intval', explode('-', $range, 2));
        return $start > 0 && $end >= $start && $end <= 65535;
    };

    $awgPort = (int)($input['awg_port'] ?? 0);
    if ($awgPort > 0) {
        if (!$validatePort($awgPort)) {
            $errors[] = 'Invalid AWG port';
        } else {
            $overrides['awg']['port'] = $awgPort;
        }
    }

    $wgPort = (int)($input['wireguard_port'] ?? 0);
    if ($wgPort > 0) {
        if (!$validatePort($wgPort)) {
            $errors[] = 'Invalid WireGuard port';
        } else {
            $overrides['wireguard']['port'] = $wgPort;
        }
    }

    $openvpnPort = (int)($input['openvpn_port'] ?? 0);
    if ($openvpnPort > 0) {
        if (!$validatePort($openvpnPort)) {
            $errors[] = 'Invalid OpenVPN port';
        } else {
            $overrides['openvpn']['port'] = $openvpnPort;
        }
    }
    $openvpnProto = strtolower(trim($input['openvpn_proto'] ?? ''));
    if (in_array($openvpnProto, ['udp', 'tcp'], true)) {
        $overrides['openvpn']['transport_proto'] = $openvpnProto;
    }

    $ssPort = (int)($input['shadowsocks_port'] ?? 0);
    if ($ssPort > 0) {
        if (!$validatePort($ssPort)) {
            $errors[] = 'Invalid Shadowsocks port';
        } else {
            $overrides['shadowsocks']['port'] = $ssPort;
        }
    }
    $ssPortRange = trim($input['shadowsocks_port_range'] ?? '');
    if ($ssPortRange !== '') {
        if (!$validateRange($ssPortRange)) {
            $errors[] = 'Invalid Shadowsocks port range';
        } else {
            $overrides['shadowsocks']['port_range'] = $ssPortRange;
        }
    }

    $cloakPort = (int)($input['cloak_port'] ?? 0);
    if ($cloakPort > 0) {
        if (!$validatePort($cloakPort)) {
            $errors[] = 'Invalid Cloak port';
        } else {
            $overrides['cloak']['port'] = $cloakPort;
        }
    }
    $cloakSite = trim($input['cloak_site'] ?? '');
    if ($cloakSite !== '') {
        $overrides['cloak']['site'] = $cloakSite;
    }
    $cloakSsPortRange = trim($input['cloak_shadowsocks_port_range'] ?? '');
    if ($cloakSsPortRange !== '') {
        if (!$validateRange($cloakSsPortRange)) {
            $errors[] = 'Invalid Cloak Shadowsocks port range';
        } else {
            $overrides['cloak_shadowsocks']['port_range'] = $cloakSsPortRange;
        }
    }

    return [$overrides, $errors];
}

function getTranslationStatsSnapshot(PDO $pdo): array {
    $languages = $pdo->query("SELECT * FROM languages ORDER BY code")->fetchAll();
    $stmt = $pdo->query("SELECT COUNT(DISTINCT CONCAT(category, '.', key_name)) as count FROM translations WHERE locale = 'en'");
    $total = $stmt->fetch();
    $totalCount = (int)($total['count'] ?? 0);

    $stats = [];
    foreach ($languages as $lang) {
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM translations WHERE locale = ? AND translation IS NOT NULL AND translation != ''");
        $stmt->execute([$lang['code']]);
        $translated = $stmt->fetch();
        $stats[] = [
            'code' => $lang['code'],
            'name' => $lang['name'],
            'native_name' => $lang['native_name'],
            'total_count' => $totalCount,
            'translated_count' => (int)($translated['count'] ?? 0),
        ];
    }

    return $stats;
}

function testOpenRouterKey(string $apiKey): array {
    $url = 'https://openrouter.ai/api/v1/chat/completions';
    $data = [
        'model' => 'openai/gpt-4o-mini',
        'messages' => [
            ['role' => 'user', 'content' => 'Reply with: OK']
        ],
        'max_tokens' => 5
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $apiKey,
        'HTTP-Referer: https://amnez.ia',
        'X-Title: Amnezia VPN Panel'
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        return [
            'success' => false,
            'error' => 'Network error: ' . $curlError
        ];
    }

    $result = json_decode($response, true);

    if ($httpCode === 200 && isset($result['choices'][0]['message'])) {
        return ['success' => true];
    }

    $errorMsg = 'Unknown error';
    if (isset($result['error'])) {
        if (is_string($result['error'])) {
            $errorMsg = $result['error'];
        } elseif (isset($result['error']['message'])) {
            $errorMsg = $result['error']['message'];
        } elseif (isset($result['error']['code'])) {
            $errorMsg = 'Error code: ' . $result['error']['code'];
        }
    }

    if ($httpCode !== 200) {
        $errorMsg .= ' (HTTP ' . $httpCode . ')';
    }

    if (strpos($errorMsg, 'No auth credentials') !== false || $httpCode === 401) {
        $errorMsg = 'Invalid API key or authentication failed';
    } elseif (strpos($errorMsg, 'insufficient_quota') !== false || strpos($errorMsg, 'quota') !== false) {
        $errorMsg = 'API quota exceeded or no credits available';
    } elseif (strpos($errorMsg, 'rate_limit') !== false) {
        $errorMsg = 'Rate limit exceeded, try again later';
    }

    return [
        'success' => false,
        'error' => $errorMsg
    ];
}

/**
 * PUBLIC ROUTES
 */

// React app entry (built to public/app)
Router::get('/app', function () {
    renderReactApp();
});

// Home page
Router::get('/', function () {
    renderReactApp();
});

// Login page
Router::get('/login', function () {
    redirect('/app#/login');
});

Router::post('/login', function () {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (Auth::login($email, $password)) {
        redirect('/dashboard');
    }
    
    View::render('login.twig', ['error' => 'Invalid credentials']);
});

// Register page
Router::get('/register', function () {
    redirect('/app#/login');
});

Router::post('/register', function () {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        View::render('register.twig', ['error' => 'Invalid email address']);
        return;
    }
    
    if (strlen($password) < 6) {
        View::render('register.twig', ['error' => 'Password must be at least 6 characters']);
        return;
    }
    
    try {
        $success = Auth::register($name, $email, $password);
        if ($success) {
            Auth::login($email, $password);
            redirect('/dashboard');
        }
    } catch (Throwable $e) {
        // Email already exists or other error
    }
    
    View::render('register.twig', ['error' => 'Registration failed. Email may already be in use.']);
});

// Logout
Router::get('/logout', function () {
    Auth::logout();
    redirect('/login');
});

// Share client page (public)
Router::get('/share/{token}', function ($params) {
    $token = trim($params['token'] ?? '');
    if ($token === '') {
        http_response_code(404);
        echo 'Not found';
        return;
    }

    $clientData = VpnClient::findByShareToken($token);
    if (!$clientData) {
        http_response_code(404);
        echo 'Not found';
        return;
    }

    $client = new VpnClient((int)$clientData['id']);
    if (empty($clientData['qr_code'])) {
        if ($client->regenerateQrFromProtocols()) {
            $clientData = $client->getData() ?? $clientData;
        }
    }

    $protocolGroups = buildProtocolGroupsFromClient($clientData);
    $qrCodes = buildQrCodesFromClient($clientData);
    $shareUrl = buildShareUrl($token);

    View::render('clients/share.twig', [
        'client' => $clientData,
        'protocol_groups' => $protocolGroups,
        'qr_codes' => $qrCodes,
        'share_url' => $shareUrl,
    ]);
});

// Share page config download (public)
Router::get('/share/{token}/download', function ($params) {
    $token = trim($params['token'] ?? '');
    if ($token === '') {
        http_response_code(404);
        echo 'Not found';
        return;
    }

    $clientData = VpnClient::findByShareToken($token);
    if (!$clientData) {
        http_response_code(404);
        echo 'Not found';
        return;
    }

    $client = new VpnClient((int)$clientData['id']);
    $protocol = trim($_GET['protocol'] ?? '');
    $container = trim($_GET['container'] ?? '');
    $config = $protocol !== '' ? $client->getProtocolConfig($protocol, $container !== '' ? $container : null) : $client->getConfig();
    if ($config === '') {
        http_response_code(404);
        echo 'Config not found';
        return;
    }

    $hasNonLatin = preg_match('/[^a-zA-Z0-9_-]/', $clientData['name']);
    $extension = 'conf';
    if ($protocol === 'openvpn') {
        $extension = 'ovpn';
    } elseif (in_array($protocol, ['shadowsocks', 'cloak', 'ikev2'], true)) {
        $extension = 'json';
    }

    if ($hasNonLatin) {
        $filename = 'user_' . $clientData['id'] . '_s' . $clientData['server_id'] . '.' . $extension;
    } else {
        $filename = $clientData['name'] . '.' . $extension;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($config));
    echo $config;
});

/**
 * AUTHENTICATED ROUTES
 */

// Dashboard
Router::get('/dashboard', function () {
    redirect('/app#/dashboard');
});

// Servers list
Router::get('/servers', function () {
    redirect('/app#/servers');
});

// Create server page
Router::get('/servers/create', function () {
    redirect('/app#/servers/new');
});

// Create server action
Router::post('/servers/create', function () {
    requireAuth();
    $user = Auth::user();
    
    $name = trim($_POST['name'] ?? '');
    $host = trim($_POST['host'] ?? '');
    $port = (int)($_POST['port'] ?? 22);
    $username = trim($_POST['username'] ?? 'root');
    $password = $_POST['password'] ?? '';
    
    if (empty($name) || empty($host) || empty($password)) {
        View::render('servers/create.twig', ['error' => 'All fields are required']);
        return;
    }
    
    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'password' => $password,
        ]);
        
        // Handle import if enabled
        if (!empty($_POST['enable_import']) && !empty($_POST['panel_type']) && isset($_FILES['backup_file'])) {
            $panelType = $_POST['panel_type'];
            
            if (in_array($panelType, ['wg-easy', '3x-ui']) && $_FILES['backup_file']['error'] === UPLOAD_ERR_OK) {
                // Store import info in session for processing after deployment
                $_SESSION['pending_import'] = [
                    'server_id' => $serverId,
                    'panel_type' => $panelType,
                    'backup_file' => $_FILES['backup_file']['tmp_name'],
                    'backup_name' => $_FILES['backup_file']['name']
                ];
            }
        }
        
        redirect('/servers/' . $serverId . '/deploy');
    } catch (Exception $e) {
        View::render('servers/create.twig', ['error' => $e->getMessage()]);
    }
});

// Delete server action
Router::post('/servers/{id}/delete', function ($params) {
    requireAuth();
    $user = Auth::user();
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $server->delete();
        $_SESSION['success_message'] = 'Server deleted successfully';
        redirect('/servers');
    } catch (Exception $e) {
        $_SESSION['error_message'] = $e->getMessage();
        redirect('/servers');
    }
});

// Deploy server page
Router::get('/servers/{id}/deploy', function ($params) {
    redirect('/app#/servers/' . $params['id'] . '/deploy');
});

// Deploy server action (AJAX)
Router::post('/servers/{id}/deploy', function ($params) {
    requireAuth();
    header('Content-Type: application/json');
    
    $serverId = (int)$params['id'];
    ini_set('display_errors', '0');
    ob_start();
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $result = $server->deploy();
        $buffer = trim((string)ob_get_clean());
        if ($buffer !== '') {
            error_log('Unexpected deploy output: ' . $buffer);
        }
        echo json_encode($result);
    } catch (Exception $e) {
        $buffer = trim((string)ob_get_clean());
        if ($buffer !== '') {
            error_log('Deploy error output: ' . $buffer);
        }
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// View server
Router::get('/servers/{id}', function ($params) {
    redirect('/app#/servers/' . $params['id']);
});

// Update server protocol ports
Router::post('/servers/{id}/protocols/update', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    $user = Auth::user();

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }

        $protocolOverrides = [];
        $errors = [];

        $validatePort = function (int $port): bool {
            return $port > 0 && $port <= 65535;
        };
        $validateRange = function (string $range): bool {
            if (!preg_match('/^\d{1,5}-\d{1,5}$/', $range)) {
                return false;
            }
            [$start, $end] = array_map('intval', explode('-', $range, 2));
            return $start > 0 && $end >= $start && $end <= 65535;
        };

        $awgPort = (int)($_POST['awg_port'] ?? 0);
        if ($awgPort > 0) {
            if (!$validatePort($awgPort)) {
                $errors[] = 'Invalid AWG port';
            } else {
                $protocolOverrides['awg']['port'] = $awgPort;
            }
        }

        $wgPort = (int)($_POST['wireguard_port'] ?? 0);
        if ($wgPort > 0) {
            if (!$validatePort($wgPort)) {
                $errors[] = 'Invalid WireGuard port';
            } else {
                $protocolOverrides['wireguard']['port'] = $wgPort;
            }
        }

        $openvpnPort = (int)($_POST['openvpn_port'] ?? 0);
        if ($openvpnPort > 0) {
            if (!$validatePort($openvpnPort)) {
                $errors[] = 'Invalid OpenVPN port';
            } else {
                $protocolOverrides['openvpn']['port'] = $openvpnPort;
            }
        }
        $openvpnProto = strtolower(trim($_POST['openvpn_proto'] ?? ''));
        if (in_array($openvpnProto, ['udp', 'tcp'], true)) {
            $protocolOverrides['openvpn']['transport_proto'] = $openvpnProto;
        }

        $ssPort = (int)($_POST['shadowsocks_port'] ?? 0);
        if ($ssPort > 0) {
            if (!$validatePort($ssPort)) {
                $errors[] = 'Invalid Shadowsocks port';
            } else {
                $protocolOverrides['shadowsocks']['port'] = $ssPort;
            }
        }
        $ssPortRange = trim($_POST['shadowsocks_port_range'] ?? '');
        if ($ssPortRange !== '') {
            if (!$validateRange($ssPortRange)) {
                $errors[] = 'Invalid Shadowsocks port range';
            } else {
                $protocolOverrides['shadowsocks']['port_range'] = $ssPortRange;
            }
        }

        $cloakPort = (int)($_POST['cloak_port'] ?? 0);
        if ($cloakPort > 0) {
            if (!$validatePort($cloakPort)) {
                $errors[] = 'Invalid Cloak port';
            } else {
                $protocolOverrides['cloak']['port'] = $cloakPort;
            }
        }
        $cloakSsPortRange = trim($_POST['cloak_shadowsocks_port_range'] ?? '');
        if ($cloakSsPortRange !== '') {
            if (!$validateRange($cloakSsPortRange)) {
                $errors[] = 'Invalid Cloak Shadowsocks port range';
            } else {
                $protocolOverrides['cloak_shadowsocks']['port_range'] = $cloakSsPortRange;
            }
        }

        if ($errors) {
            $_SESSION['protocol_message'] = [
                'type' => 'error',
                'text' => implode('. ', $errors),
            ];
            redirect('/servers/' . $serverId);
        }

        $server->updateProtocolOverrides($protocolOverrides);
        $_SESSION['protocol_message'] = [
            'type' => 'success',
            'text' => 'Protocol settings saved. Redeploy the server to apply changes.',
        ];
        redirect('/servers/' . $serverId);
    } catch (Exception $e) {
        $_SESSION['protocol_message'] = [
            'type' => 'error',
            'text' => $e->getMessage(),
        ];
        redirect('/servers/' . $serverId);
    }
});

// Server monitoring page
Router::get('/servers/{id}/monitoring', function ($params) {
    redirect('/app#/servers/' . $params['id'] . '/monitoring');
});

// Delete server
Router::post('/servers/{id}/delete', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $server->delete();
        redirect('/servers');
    } catch (Exception $e) {
        redirect('/servers');
    }
});

// Create client for server
Router::post('/servers/{id}/clients/create', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    $clientName = trim($_POST['name'] ?? '');
    
    // Handle expiration: either from dropdown (days) or custom input (seconds)
    $expiresInDays = null;
    if (!empty($_POST['expires_in_seconds'])) {
        // Convert seconds to days (round up)
        $expiresInDays = (int)ceil((int)$_POST['expires_in_seconds'] / 86400);
    } elseif (!empty($_POST['expires_in_days']) && $_POST['expires_in_days'] !== 'custom') {
        $expiresInDays = (int)$_POST['expires_in_days'];
    }
    
    // Handle traffic limit: either from dropdown (GB) or custom input (MB)
    $trafficLimitBytes = null;
    if (!empty($_POST['traffic_limit_mb'])) {
        // Convert MB to bytes
        $trafficLimitBytes = (int)((float)$_POST['traffic_limit_mb'] * 1048576);
    } elseif (!empty($_POST['traffic_limit_gb']) && $_POST['traffic_limit_gb'] !== 'custom') {
        // Convert GB to bytes
        $trafficLimitBytes = (int)((float)$_POST['traffic_limit_gb'] * 1073741824);
    }
    
    if (empty($clientName)) {
        redirect('/servers/' . $serverId . '?error=Client+name+is+required');
        return;
    }
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $clientId = VpnClient::create($serverId, $user['id'], $clientName, $expiresInDays);
        
        // Set traffic limit if specified
        if ($trafficLimitBytes !== null && $trafficLimitBytes > 0) {
            $client = new VpnClient($clientId);
            $client->setTrafficLimit($trafficLimitBytes);
        }
        
        redirect('/clients/' . $clientId);
    } catch (Exception $e) {
        redirect('/servers/' . $serverId . '?error=' . urlencode($e->getMessage()));
    }
});

// View client
Router::get('/clients/{id}', function ($params) {
    redirect('/app#/clients/' . $params['id']);
});

// Download client config
Router::get('/clients/{id}/download', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $protocol = trim($_GET['protocol'] ?? '');
        $container = trim($_GET['container'] ?? '');
        $config = $protocol !== '' ? $client->getProtocolConfig($protocol, $container !== '' ? $container : null) : $client->getConfig();
        if ($config === '') {
            http_response_code(404);
            echo 'Config not found';
            return;
        }
        
        // Check if name contains non-Latin characters
        $hasNonLatin = preg_match('/[^a-zA-Z0-9_-]/', $clientData['name']);
        $extension = 'conf';
        if ($protocol === 'openvpn') {
            $extension = 'ovpn';
        } elseif (in_array($protocol, ['shadowsocks', 'cloak', 'ikev2'], true)) {
            $extension = 'json';
        }

        if ($hasNonLatin) {
            // Use user_(client_id)_s(server_id).conf format for non-Latin names
            $filename = 'user_' . $clientData['id'] . '_s' . $clientData['server_id'] . '.' . $extension;
        } else {
            // Use client name for Latin characters
            $filename = $clientData['name'] . '.' . $extension;
        }
        
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($config));
        echo $config;
    } catch (Exception $e) {
        http_response_code(404);
        echo 'Client not found';
    }
});

// Revoke client access
Router::post('/clients/{id}/revoke', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        if ($client->revoke()) {
            redirect('/servers/' . $clientData['server_id'] . '?success=Client+revoked');
        } else {
            redirect('/servers/' . $clientData['server_id'] . '?error=Failed+to+revoke+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Restore client access
Router::post('/clients/{id}/restore', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        if ($client->restore()) {
            redirect('/servers/' . $clientData['server_id'] . '?success=Client+restored');
        } else {
            redirect('/servers/' . $clientData['server_id'] . '?error=Failed+to+restore+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Delete client
Router::post('/clients/{id}/delete', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo 'Forbidden';
            return;
        }
        
        $serverId = $clientData['server_id'];
        
        if ($client->delete()) {
            redirect('/servers/' . $serverId . '?success=Client+deleted');
        } else {
            redirect('/servers/' . $serverId . '?error=Failed+to+delete+client');
        }
    } catch (Exception $e) {
        redirect('/dashboard?error=' . urlencode($e->getMessage()));
    }
});

// Sync client stats
Router::post('/clients/{id}/sync-stats', function ($params) {
    requireAuth();
    $clientId = (int)$params['id'];
    
    header('Content-Type: application/json');
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($clientData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        if ($client->syncStats()) {
            // Reload client data
            $client = new VpnClient($clientId);
            $stats = $client->getFormattedStats();
            echo json_encode(['success' => true, 'stats' => $stats]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to sync stats']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Sync all stats for server
Router::post('/servers/{id}/sync-stats', function ($params) {
    requireAuth();
    $serverId = (int)$params['id'];
    
    header('Content-Type: application/json');
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        $user = Auth::user();
        if ($serverData['user_id'] != $user['id'] && !Auth::isAdmin()) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $synced = VpnClient::syncAllStatsForServer($serverId);
        echo json_encode(['success' => true, 'synced' => $synced]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

/**
 * API ROUTES (for Telegram bot integration)
 */

// API: Generate JWT token
Router::post('/api/auth/token', function () {
    header('Content-Type: application/json');
    
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($email) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password are required']);
        return;
    }
    
    $user = Auth::getUserByEmail($email);
    if (!$user || !password_verify($password, $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid credentials']);
        return;
    }
    
    try {
        $token = JWT::generate($user['id']);
        echo json_encode([
            'success' => true,
            'token' => $token,
            'type' => 'Bearer',
            'expires_in' => 30 * 24 * 3600 // 30 days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Token generation failed']);
    }
});

// API: Create persistent API token
Router::post('/api/tokens', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $name = $_POST['name'] ?? 'API Token';
    $expiresIn = isset($_POST['expires_in']) ? (int)$_POST['expires_in'] : 2592000; // 30 days default
    
    try {
        $tokenData = JWT::createApiToken($user['id'], $name, $expiresIn);
        echo json_encode([
            'success' => true,
            'token' => $tokenData
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List user's API tokens
Router::get('/api/tokens', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $stmt = DB::get()->prepare("
        SELECT id, name, token, expires_at, created_at, last_used_at
        FROM api_tokens
        WHERE user_id = ? AND revoked_at IS NULL
        ORDER BY created_at DESC
    ");
    $stmt->execute([$user['id']]);
    $tokens = $stmt->fetchAll();
    
    // Don't expose full token in list
    foreach ($tokens as &$token) {
        $token['token'] = substr($token['token'], 0, 10) . '...';
    }
    
    echo json_encode(['tokens' => $tokens]);
});

// API: Revoke API token
Router::delete('/api/tokens/{id}', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    try {
        JWT::revokeApiToken($params['id'], $user['id']);
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List servers
Router::get('/api/servers', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $servers = VpnServer::listByUser($user['id']);
    echo json_encode(['servers' => $servers]);
});

// API: List servers with latest health metrics
Router::get('/api/servers/health', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $servers = $user['role'] === 'admin'
        ? VpnServer::listAll()
        : VpnServer::listByUser($user['id']);

    if (!$servers) {
        echo json_encode(['servers' => []]);
        return;
    }

    $serverIds = array_map(static fn($server) => (int)$server['id'], $servers);
    $placeholders = implode(',', array_fill(0, count($serverIds), '?'));

    $pdo = DB::conn();
    $stmt = $pdo->prepare("
        SELECT sm.*
        FROM server_metrics sm
        INNER JOIN (
            SELECT server_id, MAX(collected_at) AS max_collected
            FROM server_metrics
            WHERE server_id IN ({$placeholders})
            GROUP BY server_id
        ) latest
        ON sm.server_id = latest.server_id AND sm.collected_at = latest.max_collected
    ");
    $stmt->execute($serverIds);
    $metricsRows = $stmt->fetchAll();

    $metricsByServer = [];
    foreach ($metricsRows as $row) {
        $metricsByServer[(int)$row['server_id']] = $row;
    }

    $result = [];
    foreach ($servers as $server) {
        $serverId = (int)$server['id'];
        $server['metrics'] = $metricsByServer[$serverId] ?? null;
        $result[] = $server;
    }

    echo json_encode(['servers' => $result]);
});

// API: Create server
Router::post('/api/servers/create', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $name = trim($input['name'] ?? '');
    $host = trim($input['host'] ?? '');
    $port = (int)($input['port'] ?? 22);
    $username = trim($input['username'] ?? 'root');
    $password = $input['password'] ?? '';
    $vpnSubnet = trim($input['vpn_subnet'] ?? '');
    $defaultContainer = trim($input['default_container'] ?? '');
    [$protocolOverrides, $protocolErrors] = parseProtocolOverridesInput($input);
    
    if (empty($name) || empty($host) || empty($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields: name, host, password']);
        return;
    }
    if ($protocolErrors) {
        http_response_code(400);
        echo json_encode(['error' => implode('. ', $protocolErrors)]);
        return;
    }
    
    try {
        $serverId = VpnServer::create([
            'user_id' => $user['id'],
            'name' => $name,
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'password' => $password,
            'protocol_overrides' => $protocolOverrides,
            'vpn_subnet' => $vpnSubnet !== '' ? $vpnSubnet : null,
            'default_container' => $defaultContainer !== '' ? $defaultContainer : null,
        ]);
        
        http_response_code(201);
        echo json_encode([
            'success' => true,
            'server_id' => $serverId,
            'message' => 'Server created successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Deploy server
Router::post('/api/servers/{id}/deploy', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $serverId = (int)$params['id'];
    ini_set('display_errors', '0');
    ob_start();

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $result = $server->deploy();
        $buffer = trim((string)ob_get_clean());
        if ($buffer !== '') {
            error_log('Unexpected deploy output: ' . $buffer);
        }
        echo json_encode($result);
    } catch (Exception $e) {
        $buffer = trim((string)ob_get_clean());
        if ($buffer !== '') {
            error_log('Deploy error output: ' . $buffer);
        }
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Update server protocol overrides
Router::post('/api/servers/{id}/protocols/update', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $serverId = (int)$params['id'];
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    [$protocolOverrides, $protocolErrors] = parseProtocolOverridesInput($input);

    if ($protocolErrors) {
        http_response_code(400);
        echo json_encode(['error' => implode('. ', $protocolErrors)]);
        return;
    }

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($protocolOverrides) {
            $server->updateProtocolOverrides($protocolOverrides);
        }

        echo json_encode([
            'success' => true,
            'message' => 'Protocol settings saved. Redeploy the server to apply changes.'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Sync all client stats for server
Router::post('/api/servers/{id}/sync-stats', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $serverId = (int)$params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $synced = VpnClient::syncAllStatsForServer($serverId);
        echo json_encode(['success' => true, 'synced' => $synced]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete server
Router::delete('/api/servers/{id}/delete', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $server->delete();
        echo json_encode([
            'success' => true,
            'message' => 'Server deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Import from existing panel
Router::post('/api/servers/{id}/import', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    // Validate server ownership
    $server = VpnServer::getById($serverId);
    if (!$server || ($server['user_id'] != $user['id'] && $user['role'] !== 'admin')) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found']);
        return;
    }
    
    $panelType = $_POST['panel_type'] ?? '';
    
    if (!in_array($panelType, ['wg-easy', '3x-ui'], true)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid panel type. Supported: wg-easy, 3x-ui']);
        return;
    }
    
    // Handle file upload
    if (!isset($_FILES['backup_file']) || $_FILES['backup_file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(['error' => 'No backup file uploaded']);
        return;
    }
    
    $backupContent = file_get_contents($_FILES['backup_file']['tmp_name']);
    
    try {
        $importer = new PanelImporter($serverId, $user['id'], $panelType);
        
        if (!$importer->parseBackupFile($backupContent)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid backup file format']);
            return;
        }
        
        $result = $importer->import();
        
        echo json_encode($result);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    }
});

// API: Get import history
Router::get('/api/servers/{id}/imports', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    // Validate server ownership
    $server = VpnServer::getById($serverId);
    if (!$server || ($server['user_id'] != $user['id'] && $user['role'] !== 'admin')) {
        http_response_code(404);
        echo json_encode(['error' => 'Server not found']);
        return;
    }
    
    $imports = PanelImporter::getImportHistory($serverId);
    
    echo json_encode([
        'success' => true,
        'imports' => $imports
    ]);
});

// API: Create backup
Router::post('/api/servers/{id}/backup', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $backupId = $server->createBackup($user['id'], 'manual');
        $backup = VpnServer::getBackup($backupId);
        
        echo json_encode([
            'success' => true,
            'backup' => $backup
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List backups
Router::get('/api/servers/{id}/backups', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $backups = $server->listBackups();
        
        echo json_encode([
            'success' => true,
            'backups' => $backups,
            'count' => count($backups)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore backup
Router::post('/api/servers/{id}/restore', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $serverId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $backupId = (int)($data['backup_id'] ?? 0);
    
    if ($backupId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'backup_id is required']);
        return;
    }
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $result = $server->restoreBackup($backupId);
        
        // Log the result for debugging
        error_log('Restore backup result: ' . json_encode($result));
        
        // Always return the result, even if success is false
        echo json_encode($result);
    } catch (Exception $e) {
        error_log('Restore backup exception: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage(), 'success' => false]);
    }
});

// API: Delete backup
Router::delete('/api/backups/{id}', function ($params) {
    header('Content-Type: application/json');
    
    $user = requireApiAuth();
    if (!$user) return;
    
    $backupId = (int)$params['id'];
    
    try {
        $backup = VpnServer::getBackup($backupId);
        
        if (!$backup) {
            http_response_code(404);
            echo json_encode(['error' => 'Backup not found']);
            return;
        }
        
        // Get server to check ownership
        $server = new VpnServer($backup['server_id']);
        $serverData = $server->getData();
        
        // Check ownership or admin
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        VpnServer::deleteBackup($backupId);
        
        echo json_encode([
            'success' => true,
            'message' => 'Backup deleted successfully'
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: List clients
Router::get('/api/clients', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clients = VpnClient::listByUser($user['id']);
    echo json_encode(['clients' => $clients]);
});

// API: Get client details with stats
Router::get('/api/clients/{id}/details', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        // Sync stats before returning
        $client->syncStats();
        
        // Reload data
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if (empty($clientData['qr_code']) && !empty($clientData['protocols'])) {
            if ($client->regenerateQrFromProtocols()) {
                $clientData = $client->getData() ?? $clientData;
            }
        }

        $protocolGroups = buildProtocolGroupsFromClient($clientData);
        $qrCodes = buildQrCodesFromClient($clientData);
        $token = $client->ensureShareToken();
        $shareUrl = $token !== '' ? buildShareUrl($token) : null;
        $stats = $client->getFormattedStats();
        
        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'expires_at' => $clientData['expires_at'],
                'traffic_limit' => $clientData['traffic_limit'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ],
            'protocol_groups' => $protocolGroups,
            'qr_codes' => $qrCodes,
            'share_url' => $shareUrl,
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Sync client stats
Router::post('/api/clients/{id}/sync-stats', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $clientId = (int)$params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->syncStats()) {
            $client = new VpnClient($clientId);
            $stats = $client->getFormattedStats();
            echo json_encode(['success' => true, 'stats' => $stats]);
            return;
        }

        echo json_encode(['success' => false, 'error' => 'Failed to sync stats']);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get client QR code
Router::get('/api/clients/{id}/qr', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        echo json_encode([
            'success' => true,
            'qr_code' => $clientData['qr_code'],
            'client_name' => $clientData['name']
        ]);
    } catch (Exception $e) {
        http_response_code(404);
        echo json_encode(['error' => 'Client not found']);
    }
});

// API: Revoke client
Router::post('/api/clients/{id}/revoke', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        if ($client->revoke()) {
            echo json_encode(['success' => true, 'message' => 'Client revoked']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to revoke client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Restore client
Router::post('/api/clients/{id}/restore', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id']) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        if ($client->restore()) {
            echo json_encode(['success' => true, 'message' => 'Client restored']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to restore client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete client
Router::delete('/api/clients/{id}/delete', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $clientId = (int)$params['id'];

    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();

        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        if ($client->delete()) {
            echo json_encode(['success' => true]);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to delete client']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get server metrics
Router::get('/api/servers/{id}/metrics', function ($params) {
    header('Content-Type: application/json');
    
    // Check authentication - either JWT or session
    $user = null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        // JWT authentication
        $token = $matches[1];
        $user = JWT::verify($token);
    } else if (isset($_SESSION['user_id'])) {
        // Session authentication
        $user = Auth::user();
    }
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $serverId = (int)$params['id'];
    $hours = isset($_GET['hours']) ? (float)$_GET['hours'] : 24;
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $metrics = ServerMonitoring::getServerMetrics($serverId, $hours);
        
        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get latest client speeds for server
Router::get('/api/servers/{id}/client-speeds', function ($params) {
    header('Content-Type: application/json');

    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $serverId = (int)$params['id'];

    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();

        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }

        $pdo = DB::conn();
        $clients = VpnClient::listByServer($serverId);
        $speeds = [];

        $stmt = $pdo->prepare('
            SELECT speed_up_kbps, speed_down_kbps, collected_at
            FROM client_metrics
            WHERE client_id = ?
            ORDER BY collected_at DESC
            LIMIT 1
        ');

        foreach ($clients as $client) {
            $stmt->execute([$client['id']]);
            $latest = $stmt->fetch();
            $speeds[] = [
                'client_id' => $client['id'],
                'client_name' => $client['name'],
                'status' => $client['status'],
                'speed_up_kbps' => $latest['speed_up_kbps'] ?? null,
                'speed_down_kbps' => $latest['speed_down_kbps'] ?? null,
                'collected_at' => $latest['collected_at'] ?? null,
            ];
        }

        echo json_encode(['success' => true, 'clients' => $speeds]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get client metrics
Router::get('/api/clients/{id}/metrics', function ($params) {
    header('Content-Type: application/json');
    
    // Check authentication - either JWT or session
    $user = null;
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        // JWT authentication
        $token = $matches[1];
        $user = JWT::verify($token);
    } else if (isset($_SESSION['user_id'])) {
        // Session authentication
        $user = Auth::user();
    }
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $clientId = (int)$params['id'];
    $hours = isset($_GET['hours']) ? (float)$_GET['hours'] : 24;
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Get server to check ownership
        $server = new VpnServer($clientData['server_id']);
        $serverData = $server->getData();
        
        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $metrics = ServerMonitoring::getClientMetrics($clientId, $hours);
        
        echo json_encode(['success' => true, 'metrics' => $metrics]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get server clients
Router::get('/api/servers/{id}/clients', function ($params) {
    header('Content-Type: application/json');
    
    $user = authenticateRequest();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $serverId = (int)$params['id'];
    
    try {
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        // Check ownership
        if ($serverData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        // Sync all stats first
        VpnClient::syncAllStatsForServer($serverId);
        
        $clients = VpnClient::listByServer($serverId);
        $clientsData = [];
        
        foreach ($clients as $clientData) {
            $client = new VpnClient($clientData['id']);
            $stats = $client->getFormattedStats();
            
            $clientsData[] = [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'created_at' => $clientData['created_at'],
                'expires_at' => $clientData['expires_at'],
                'traffic_limit' => $clientData['traffic_limit'],
                'stats' => $stats,
                'bytes_sent' => $clientData['bytes_sent'],
                'bytes_received' => $clientData['bytes_received'],
                'last_handshake' => $clientData['last_handshake'],
            ];
        }
        
        echo json_encode(['success' => true, 'clients' => $clientsData]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Create client
Router::post('/api/clients/create', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $serverId = (int)($data['server_id'] ?? 0);
    $name = trim($data['name'] ?? '');
    $expiresInDays = isset($data['expires_in_days']) ? (int)$data['expires_in_days'] : null;
    
    if ($serverId <= 0 || empty($name)) {
        http_response_code(400);
        echo json_encode(['error' => 'server_id and name are required']);
        return;
    }
    
    try {
        $clientId = VpnClient::create($serverId, $user['id'], $name, $expiresInDays);
        
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Return client data with config and QR code
        echo json_encode([
            'success' => true,
            'client' => [
                'id' => $clientData['id'],
                'name' => $clientData['name'],
                'server_id' => $clientData['server_id'],
                'client_ip' => $clientData['client_ip'],
                'status' => $clientData['status'],
                'expires_at' => $clientData['expires_at'],
                'created_at' => $clientData['created_at'],
                'config' => $clientData['config'],
                'qr_code' => $clientData['qr_code'],
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client expiration
Router::post('/api/clients/{id}/set-expiration', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $expiresAt = $data['expires_at'] ?? null; // Y-m-d H:i:s format or null
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        VpnClient::setExpiration($clientId, $expiresAt);
        
        echo json_encode([
            'success' => true,
            'expires_at' => $expiresAt
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Extend client expiration
Router::post('/api/clients/{id}/extend', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $days = (int)($data['days'] ?? 30);
    
    if ($days <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'days must be positive']);
        return;
    }
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        VpnClient::extendExpiration($clientId, $days);
        
        // Get updated expiration
        $client = new VpnClient($clientId);
        $updated = $client->getData();
        
        echo json_encode([
            'success' => true,
            'expires_at' => $updated['expires_at'],
            'extended_days' => $days
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get expiring clients
Router::get('/api/clients/expiring', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $days = (int)($_GET['days'] ?? 7);
    
    try {
        $clients = VpnClient::getExpiringClients($days);
        
        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }
        
        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Set client traffic limit
Router::post('/api/clients/{id}/set-traffic-limit', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    // limit_bytes can be null (unlimited) or positive integer
    $limitBytes = isset($data['limit_bytes']) ? (int)$data['limit_bytes'] : null;
    
    if ($limitBytes !== null && $limitBytes < 0) {
        http_response_code(400);
        echo json_encode(['error' => 'limit_bytes must be positive or null for unlimited']);
        return;
    }
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $client->setTrafficLimit($limitBytes);
        
        echo json_encode([
            'success' => true,
            'limit_bytes' => $limitBytes,
            'limit_gb' => $limitBytes ? round($limitBytes / 1073741824, 2) : null
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Check client traffic limit status
Router::get('/api/clients/{id}/traffic-limit-status', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $clientId = (int)$params['id'];
    
    try {
        $client = new VpnClient($clientId);
        $clientData = $client->getData();
        
        // Check ownership
        if ($clientData['user_id'] != $user['id'] && $user['role'] !== 'admin') {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            return;
        }
        
        $status = $client->getTrafficLimitStatus();
        
        echo json_encode([
            'success' => true,
            'status' => $status
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Get clients over traffic limit
Router::get('/api/clients/overlimit', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    try {
        $clients = VpnClient::getClientsOverLimit();
        
        // Filter by user if not admin
        if ($user['role'] !== 'admin') {
            $clients = array_filter($clients, function($c) use ($user) {
                return $c['user_id'] == $user['id'];
            });
        }
        
        echo json_encode([
            'success' => true,
            'clients' => array_values($clients),
            'count' => count($clients)
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Settings overview
Router::get('/api/settings', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    try {
        $pdo = DB::conn();
        $openrouterKey = Translator::getApiKey('openrouter');
        $stats = getTranslationStatsSnapshot($pdo);
        $users = $user['role'] === 'admin' ? Auth::listUsers() : [];

        echo json_encode([
            'success' => true,
            'user' => $user,
            'openrouter_key' => $openrouterKey,
            'translation_stats' => $stats,
            'users' => $users,
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Change password
Router::post('/api/settings/change-password', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    $data = json_decode(file_get_contents('php://input'), true) ?? [];
    $currentPassword = $data['current_password'] ?? '';
    $newPassword = $data['new_password'] ?? '';
    $confirmPassword = $data['confirm_password'] ?? '';

    if ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
        http_response_code(400);
        echo json_encode(['error' => 'All fields are required']);
        return;
    }
    if ($newPassword !== $confirmPassword) {
        http_response_code(400);
        echo json_encode(['error' => 'New passwords do not match']);
        return;
    }
    if (strlen($newPassword) < 6) {
        http_response_code(400);
        echo json_encode(['error' => 'Password must be at least 6 characters']);
        return;
    }

    try {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT password_hash FROM users WHERE id = ?');
        $stmt->execute([$user['id']]);
        $hash = $stmt->fetchColumn();

        if (!$hash || !password_verify($currentPassword, $hash)) {
            http_response_code(400);
            echo json_encode(['error' => 'Current password is incorrect']);
            return;
        }

        $newHash = password_hash($newPassword, PASSWORD_BCRYPT);
        $stmt = $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([$newHash, $user['id']]);

        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Save API key
Router::post('/api/settings/api-key', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true) ?? [];
    $service = trim($data['service'] ?? '');
    $apiKey = trim($data['api_key'] ?? '');
    $skipTest = !empty($data['skip_test']);

    if ($service === '' || $apiKey === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Service and api_key are required']);
        return;
    }

    if ($service === 'openrouter' && !$skipTest) {
        $testResult = testOpenRouterKey($apiKey);
        if (empty($testResult['success'])) {
            http_response_code(400);
            echo json_encode(['error' => $testResult['error'] ?? 'API key validation failed']);
            return;
        }
    }

    if (!Translator::saveApiKey($service, $apiKey)) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to save API key']);
        return;
    }

    echo json_encode(['success' => true]);
});

// API: Add user
Router::post('/api/settings/users', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true) ?? [];
    $name = trim($data['name'] ?? '');
    $email = trim($data['email'] ?? '');
    $password = $data['password'] ?? '';
    $role = $data['role'] ?? 'user';

    if ($name === '' || $email === '' || $password === '') {
        http_response_code(400);
        echo json_encode(['error' => 'All fields are required']);
        return;
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid email address']);
        return;
    }
    if (strlen($password) < 6) {
        http_response_code(400);
        echo json_encode(['error' => 'Password must be at least 6 characters']);
        return;
    }
    if (!in_array($role, ['admin', 'user'], true)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid role']);
        return;
    }

    try {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            http_response_code(400);
            echo json_encode(['error' => 'Email already exists']);
            return;
        }

        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $pdo->prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)');
        $stmt->execute([$name, $email, $hash, $role]);

        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Delete user
Router::delete('/api/settings/users/{id}', function ($params) {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $userId = (int)$params['id'];
    if ($userId === (int)$user['id']) {
        http_response_code(400);
        echo json_encode(['error' => 'Cannot delete yourself']);
        return;
    }

    try {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Get LDAP settings
Router::get('/api/settings/ldap', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    try {
        $pdo = DB::conn();
        $config = [];
        $mappings = [];

        $stmt = $pdo->query("SHOW TABLES LIKE 'ldap_configs'");
        if ($stmt->fetch()) {
            $stmt = $pdo->query("SELECT * FROM ldap_configs WHERE id = 1");
            $config = $stmt->fetch() ?: [];
        }

        $stmt = $pdo->query("SHOW TABLES LIKE 'ldap_group_mappings'");
        if ($stmt->fetch()) {
            $stmt = $pdo->query("SELECT * FROM ldap_group_mappings ORDER BY ldap_group");
            $mappings = $stmt->fetchAll();
        }

        echo json_encode([
            'success' => true,
            'config' => $config,
            'mappings' => $mappings,
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Save LDAP settings
Router::post('/api/settings/ldap/save', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true) ?? [];
    $enabled = !empty($data['enabled']) ? 1 : 0;
    $host = trim($data['host'] ?? '');
    $port = (int)($data['port'] ?? 389);
    $useTls = !empty($data['use_tls']) ? 1 : 0;
    $baseDn = trim($data['base_dn'] ?? '');
    $bindDn = trim($data['bind_dn'] ?? '');
    $bindPassword = $data['bind_password'] ?? '';
    $userSearchFilter = trim($data['user_search_filter'] ?? '(uid=%s)');
    $groupSearchFilter = trim($data['group_search_filter'] ?? '(memberUid=%s)');
    $syncInterval = (int)($data['sync_interval'] ?? 30);

    if ($host === '' || $baseDn === '' || $bindDn === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Host, Base DN, and Bind DN are required']);
        return;
    }

    try {
        $pdo = DB::conn();
        $stmt = $pdo->prepare("
            INSERT INTO ldap_configs
            (id, enabled, host, port, use_tls, base_dn, bind_dn, bind_password, user_search_filter, group_search_filter, sync_interval)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
            enabled = VALUES(enabled),
            host = VALUES(host),
            port = VALUES(port),
            use_tls = VALUES(use_tls),
            base_dn = VALUES(base_dn),
            bind_dn = VALUES(bind_dn),
            bind_password = VALUES(bind_password),
            user_search_filter = VALUES(user_search_filter),
            group_search_filter = VALUES(group_search_filter),
            sync_interval = VALUES(sync_interval)
        ");
        $stmt->execute([
            $enabled,
            $host,
            $port,
            $useTls,
            $baseDn,
            $bindDn,
            $bindPassword,
            $userSearchFilter,
            $groupSearchFilter,
            $syncInterval,
        ]);

        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Test LDAP connection
Router::post('/api/settings/ldap/test', function () {
    header('Content-Type: application/json');

    $user = JWT::requireAuth();
    if (!$user) return;

    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    try {
        $ldap = new LdapSync();
        if (!$ldap->isEnabled()) {
            echo json_encode([
                'success' => false,
                'message' => 'LDAP is not enabled. Please save configuration first.'
            ]);
            return;
        }

        $result = $ldap->testConnection();
        echo json_encode($result);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
});

/**
 * SETTINGS ROUTES
 */

// Settings page
Router::get('/settings', function () {
    redirect('/app#/settings');
});

// Save API key
Router::post('/settings/api-key', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->saveApiKey();
});

// Change password
Router::post('/settings/change-password', function () {
    requireAuth();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->changePassword();
});

// Add user
Router::post('/settings/add-user', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->addUser();
});

// Delete user
Router::post('/settings/delete-user/{id}', function ($params) {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    $controller = new SettingsController();
    $controller->deleteUser($params['id']);
});

// LDAP settings page
Router::get('/settings/ldap', function () {
    redirect('/app#/settings/ldap');
});

// Save LDAP settings
Router::post('/settings/ldap/save', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->saveLdapSettings();
});

// Test LDAP connection
Router::post('/settings/ldap/test', function () {
    requireAdmin();
    
    require_once __DIR__ . '/../controllers/SettingsController.php';
    require_once __DIR__ . '/../inc/LdapSync.php';
    $controller = new SettingsController();
    $controller->testLdapConnection();
});

/**
 * LANGUAGE ROUTES
 */

// Change language
Router::post('/language/change', function () {
    $lang = $_POST['language'] ?? '';
    
    if (Translator::setLanguage($lang)) {
        $_SESSION['success'] = 'Language changed successfully';
    } else {
        $_SESSION['error'] = 'Invalid language';
    }
    
    $redirect = $_POST['redirect'] ?? '/dashboard';
    redirect($redirect);
});

Router::get('/language/change', function () {
    redirect('/dashboard');
});

// API: Get translation statistics
Router::get('/api/translations/stats', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $stats = Translator::getStatistics();
    echo json_encode(['stats' => $stats]);
});

// API: Auto-translate missing keys
Router::post('/api/translations/auto-translate', function () {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    $targetLang = $data['language'] ?? '';
    
    if (empty($targetLang)) {
        http_response_code(400);
        echo json_encode(['error' => 'Language is required']);
        return;
    }
    
    try {
        $stats = Translator::translateMissingKeys($targetLang);
        echo json_encode([
            'success' => true,
            'stats' => $stats
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// API: Export translations
Router::get('/api/translations/export/{lang}', function ($params) {
    header('Content-Type: application/json');
    
    $user = JWT::requireAuth();
    if (!$user) return;
    
    $lang = $params['lang'];
    
    try {
        $json = Translator::exportToJson($lang);
        header('Content-Disposition: attachment; filename="translations_' . $lang . '.json"');
        echo $json;
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
});

// Dispatch router
Router::dispatch($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);
