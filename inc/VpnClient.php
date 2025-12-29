<?php
/**
 * VPN Client Management Class
 * Handles creation and management of VPN client configurations
 * Based on amnezia_client_config_v2.php
 */
class VpnClient {
    private $clientId;
    private $data;
    private static array $cachedUsedPorts = [];

    private const SCRIPT_ROOT = __DIR__ . '/../assets/amnezia_scripts';
    private const DEFAULT_DNS1 = '1.1.1.1';
    private const DEFAULT_DNS2 = '1.0.0.1';

    private static function hasShareTokenColumn(PDO $pdo): bool {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }

        try {
            $stmt = $pdo->query("SHOW COLUMNS FROM vpn_clients LIKE 'share_token'");
            $cached = (bool)$stmt->fetch();
        } catch (Throwable $e) {
            $cached = false;
        }

        return $cached;
    }

    private static function generateUniqueShareToken(PDO $pdo): string {
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $token = bin2hex(random_bytes(16));
            $stmt = $pdo->prepare('SELECT 1 FROM vpn_clients WHERE share_token = ? LIMIT 1');
            $stmt->execute([$token]);
            if (!$stmt->fetchColumn()) {
                return $token;
            }
        }

        throw new Exception('Failed to generate share token');
    }
    
    public function __construct(?int $clientId = null) {
        $this->clientId = $clientId;
        if ($clientId) {
            $this->load();
        }
    }
    
    /**
     * Load client data from database
     */
    private function load(): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE id = ?');
        $stmt->execute([$this->clientId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Client not found');
        }
    }
    
    /**
     * Create new VPN client
     * 
     * @param int $serverId Server ID
     * @param int $userId User ID
     * @param string $name Client name
     * @param int|null $expiresInDays Days until expiration (null = never expires)
     * @return int Client ID
     */
    public static function create(int $serverId, int $userId, string $name, ?int $expiresInDays = null): int {
        $pdo = DB::conn();
        $useShareToken = self::hasShareTokenColumn($pdo);
        $shareToken = $useShareToken ? self::generateUniqueShareToken($pdo) : '';
        
        // Sanitize client name (replace only spaces with underscores, allow any other characters including Cyrillic)
        $name = trim($name);
        $name = str_replace(' ', '_', $name);
        
        // Get server data
        $server = new VpnServer($serverId);
        $serverData = $server->getData();
        
        if (!$serverData || $serverData['status'] !== 'active') {
            throw new Exception('Server is not active');
        }

        $containers = [];
        if (!empty($serverData['containers'])) {
            $decoded = json_decode($serverData['containers'], true);
            if (is_array($decoded)) {
                $containers = $decoded;
            }
        }

        if (empty($containers)) {
            // Legacy AWG-only flow
            $keys = self::generateClientKeys($serverData, $serverData['container_name'], $name);
            $clientIP = self::getNextClientIP($serverData);
            $awgParams = json_decode($serverData['awg_params'], true) ?: [];

            $config = self::buildClientConfig(
                $keys['private'],
                $clientIP,
                $serverData['server_public_key'],
                $serverData['preshared_key'],
                $serverData['host'],
                (int)$serverData['vpn_port'],
                $awgParams
            );

            self::addClientToServer($serverData, $keys['public'], $clientIP);

            $lastConfig = [
                'config' => $config,
                'hostName' => $serverData['host'],
                'port' => (int)$serverData['vpn_port'],
                'client_priv_key' => $keys['private'],
                'client_ip' => $clientIP,
                'client_pub_key' => $keys['public'],
                'psk_key' => $serverData['preshared_key'],
                'server_pub_key' => $serverData['server_public_key'],
            ];
            foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'] as $paramKey) {
                if (isset($awgParams[$paramKey])) {
                    $lastConfig[$paramKey] = (string)$awgParams[$paramKey];
                }
            }

            $payload = self::buildAmneziaConfigPayload($serverData, [
                [
                    'container' => $serverData['container_name'] ?? 'amnezia-awg',
                    'awg' => [
                        'port' => (int)$serverData['vpn_port'],
                        'last_config' => json_encode($lastConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
                    ],
                ]
            ]);
            $qrCode = self::buildQrCode($serverData, [
                [
                    'container' => $serverData['container_name'] ?? 'amnezia-awg',
                    'awg' => [
                        'port' => (int)$serverData['vpn_port'],
                        'last_config' => json_encode($lastConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
                    ],
                ]
            ]);
            $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;

            if ($useShareToken) {
                $stmt = $pdo->prepare('
                    INSERT INTO vpn_clients 
                    (server_id, user_id, name, client_ip, client_ips, public_key, private_key, preshared_key, config, protocols, qr_code, share_token, status, expires_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ');
                $stmt->execute([
                    $serverId,
                    $userId,
                    $name,
                    $clientIP,
                    json_encode(['awg' => $clientIP]),
                    $keys['public'],
                    $keys['private'],
                    $serverData['preshared_key'],
                    $config,
                    json_encode([]),
                    $qrCode,
                    $shareToken,
                    'active',
                    $expiresAt
                ]);
            } else {
                $stmt = $pdo->prepare('
                    INSERT INTO vpn_clients 
                    (server_id, user_id, name, client_ip, client_ips, public_key, private_key, preshared_key, config, protocols, qr_code, status, expires_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ');
                $stmt->execute([
                    $serverId,
                    $userId,
                    $name,
                    $clientIP,
                    json_encode(['awg' => $clientIP]),
                    $keys['public'],
                    $keys['private'],
                    $serverData['preshared_key'],
                    $config,
                    json_encode([]),
                    $qrCode,
                    'active',
                    $expiresAt
                ]);
            }

            return (int)$pdo->lastInsertId();
        }

        $built = self::buildMultiProtocolClientData($serverData, $containers, $name);
        $clientContainers = $built['client_containers'];
        $clientIps = $built['client_ips'];
        $defaultConfig = $built['default_config'];
        $awgKeys = $built['awg_keys'];
        $awgClientIp = $built['awg_client_ip'];
        $qrCode = $built['qr_code'];
        $expiresAt = $expiresInDays ? date('Y-m-d H:i:s', strtotime("+{$expiresInDays} days")) : null;

        if ($useShareToken) {
            $stmt = $pdo->prepare('
                INSERT INTO vpn_clients 
                (server_id, user_id, name, client_ip, client_ips, public_key, private_key, preshared_key, config, protocols, qr_code, share_token, status, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');
            $stmt->execute([
                $serverId,
                $userId,
                $name,
                $awgClientIp !== '' ? $awgClientIp : ($clientIps['awg'] ?? ''),
                json_encode($clientIps),
                $awgKeys['public'],
                $awgKeys['private'],
                $awgKeys['preshared'],
                $defaultConfig,
                json_encode($clientContainers),
                $qrCode,
                $shareToken,
                'active',
                $expiresAt
            ]);
        } else {
            $stmt = $pdo->prepare('
                INSERT INTO vpn_clients 
                (server_id, user_id, name, client_ip, client_ips, public_key, private_key, preshared_key, config, protocols, qr_code, status, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ');
            $stmt->execute([
                $serverId,
                $userId,
                $name,
                $awgClientIp !== '' ? $awgClientIp : ($clientIps['awg'] ?? ''),
                json_encode($clientIps),
                $awgKeys['public'],
                $awgKeys['private'],
                $awgKeys['preshared'],
                $defaultConfig,
                json_encode($clientContainers),
                $qrCode,
                'active',
                $expiresAt
            ]);
        }

        return (int)$pdo->lastInsertId();
    }

    private static function buildMultiProtocolClientData(array $serverData, array $containers, string $clientName): array {
        $clientContainers = [];
        $clientIps = [];
        $defaultConfig = '';
        $awgKeys = [
            'public' => '',
            'private' => '',
            'preshared' => $serverData['preshared_key'] ?? '',
        ];
        $awgClientIp = '';

        foreach ($containers as $containerConfig) {
            $result = self::generateContainerClientConfig($serverData, $containerConfig, $clientName);
            $clientContainers[] = $result['container'];
            if (!empty($result['client_ips'])) {
                $clientIps = array_merge($clientIps, $result['client_ips']);
            }
            if ($defaultConfig === '' && !empty($result['default_config'])) {
                $defaultConfig = $result['default_config'];
            }
            if (!empty($result['awg_keys'])) {
                $awgKeys = $result['awg_keys'];
                $awgClientIp = $result['awg_client_ip'] ?? $awgClientIp;
            }
        }

        $payload = self::buildAmneziaConfigPayload($serverData, $clientContainers);
        $qrCode = self::buildQrCode($serverData, $clientContainers);

        return [
            'client_containers' => $clientContainers,
            'client_ips' => $clientIps,
            'default_config' => $defaultConfig,
            'awg_keys' => $awgKeys,
            'awg_client_ip' => $awgClientIp,
            'payload' => $payload,
            'qr_code' => $qrCode,
        ];
    }

    private static function readScript(string $relativePath): string {
        $path = self::SCRIPT_ROOT . '/' . ltrim($relativePath, '/');
        if (!file_exists($path)) {
            throw new Exception('Script not found: ' . $relativePath);
        }
        return file_get_contents($path) ?: '';
    }

    private static function replaceVars(string $text, array $vars): string {
        return str_replace(array_keys($vars), array_values($vars), $text);
    }

    private static function buildAmneziaConfigPayload(array $serverData, array $containers, ?string $defaultContainer = null): string {
        $payload = [
            'containers' => $containers,
            'defaultContainer' => $defaultContainer ?? ($serverData['default_container'] ?? ($containers[0]['container'] ?? '')),
            'description' => $serverData['name'] ?? ($serverData['host'] ?? ''),
            'dns1' => self::DEFAULT_DNS1,
            'dns2' => self::DEFAULT_DNS2,
            'hostName' => $serverData['host'] ?? '',
        ];

        return json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    }

    private static function buildQrCode(array $serverData, array $clientContainers): string {
        $payload = self::buildAmneziaConfigPayload($serverData, $clientContainers);
        $qrCode = self::generateQRCode($payload);
        if ($qrCode !== '') {
            return $qrCode;
        }

        $items = [];
        foreach ($clientContainers as $containerConfig) {
            $containerName = $containerConfig['container'] ?? '';
            if ($containerName === '') {
                continue;
            }
            $itemPayload = self::buildAmneziaConfigPayload($serverData, [$containerConfig], $containerName);
            $itemQr = self::generateQRCode($itemPayload);
            if ($itemQr === '') {
                continue;
            }
            $items[] = [
                'container' => $containerName,
                'label_key' => self::qrLabelKeyForContainer($containerName),
                'qr' => $itemQr,
            ];
        }

        if (!$items) {
            return '';
        }

        return json_encode(['mode' => 'multi', 'items' => $items], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private static function qrLabelKeyForContainer(string $containerName): string {
        return match ($containerName) {
            'amnezia-awg' => 'protocols.awg',
            'amnezia-wireguard' => 'protocols.wireguard',
            'amnezia-openvpn' => 'protocols.openvpn',
            'amnezia-shadowsocks' => 'protocols.openvpn_shadowsocks',
            'amnezia-openvpn-cloak' => 'protocols.openvpn_cloak',
            'amnezia-ipsec' => 'protocols.ikev2',
            default => 'clients.qr_code',
        };
    }

    private static function generateContainerClientConfig(array $serverData, array $containerConfig, string $clientName): array {
        $containerName = $containerConfig['container'] ?? '';
        $clientIps = [];
        $defaultConfig = '';
        $awgKeys = [];
        $awgClientIp = '';

        if ($containerName === 'amnezia-awg') {
            $result = self::generateWireguardClientConfig($serverData, $containerName, $containerConfig['awg'] ?? [], true, $clientName);
            $containerConfig['awg']['last_config'] = json_encode($result['last_config'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            $clientIps['awg'] = $result['client_ip'];
            $defaultConfig = $result['config'];
            $awgKeys = [
                'public' => $result['public_key'],
                'private' => $result['private_key'],
                'preshared' => $result['preshared_key'],
            ];
            $awgClientIp = $result['client_ip'];
        } elseif ($containerName === 'amnezia-wireguard') {
            $result = self::generateWireguardClientConfig($serverData, $containerName, $containerConfig['wireguard'] ?? [], false, $clientName);
            $containerConfig['wireguard']['last_config'] = json_encode($result['last_config'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            $clientIps['wireguard'] = $result['client_ip'];
        } elseif ($containerName === 'amnezia-openvpn') {
            $openvpnResult = self::generateOpenVpnConfig($serverData, $containerName, $containerConfig['openvpn'] ?? [], 'openvpn/template.ovpn');
            $containerConfig['openvpn']['last_config'] = json_encode($openvpnResult, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        } elseif ($containerName === 'amnezia-shadowsocks') {
            $openvpnResult = self::generateOpenVpnConfig($serverData, $containerName, $containerConfig['openvpn'] ?? [], 'openvpn_shadowsocks/template.ovpn', $containerConfig['shadowsocks'] ?? []);
            $containerConfig['openvpn']['last_config'] = json_encode($openvpnResult, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            $ssConfig = self::generateShadowSocksConfig($serverData, $containerName, $containerConfig['shadowsocks'] ?? []);
            $containerConfig['shadowsocks']['last_config'] = json_encode($ssConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        } elseif ($containerName === 'amnezia-openvpn-cloak') {
            $openvpnResult = self::generateOpenVpnConfig($serverData, $containerName, $containerConfig['openvpn'] ?? [], 'openvpn_cloak/template.ovpn', $containerConfig['shadowsocks'] ?? []);
            $containerConfig['openvpn']['last_config'] = json_encode($openvpnResult, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            $ssConfig = self::generateShadowSocksConfig($serverData, $containerName, $containerConfig['shadowsocks'] ?? []);
            $containerConfig['shadowsocks']['last_config'] = json_encode($ssConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            $cloakConfig = self::generateCloakConfig($serverData, $containerName, $containerConfig['cloak'] ?? []);
            $containerConfig['cloak']['last_config'] = json_encode($cloakConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        } elseif ($containerName === 'amnezia-ipsec') {
            $ikev2Config = self::generateIkev2Config($serverData, $containerName);
            $containerConfig['ikev2']['last_config'] = json_encode($ikev2Config, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        }

        $response = ['container' => $containerConfig];
        if ($clientIps) {
            $response['client_ips'] = $clientIps;
        }
        if ($defaultConfig !== '') {
            $response['default_config'] = $defaultConfig;
        }
        if ($awgKeys) {
            $response['awg_keys'] = $awgKeys;
            $response['awg_client_ip'] = $awgClientIp;
        }

        return $response;
    }

    private static function generateWireguardClientConfig(
        array $serverData,
        string $containerName,
        array $protocolConfig,
        bool $isAwg,
        string $clientName
    ): array {
        $configPath = $isAwg ? '/opt/amnezia/awg/wg0.conf' : '/opt/amnezia/wireguard/wg0.conf';
        $serverPubPath = $isAwg ? '/opt/amnezia/awg/wireguard_server_public_key.key' : '/opt/amnezia/wireguard/wireguard_server_public_key.key';
        $serverPskPath = $isAwg ? '/opt/amnezia/awg/wireguard_psk.key' : '/opt/amnezia/wireguard/wireguard_psk.key';
        $templatePath = $isAwg ? 'awg/template.conf' : 'wireguard/template.conf';

        $keys = self::generateClientKeys($serverData, $containerName, $clientName);
        $clientIp = self::getNextClientIPFromConfig($serverData, $containerName, $configPath, $protocolConfig['subnet_address'] ?? '10.8.1.0');

        $serverPubKey = trim(self::readContainerFile($serverData, $containerName, $serverPubPath));
        $presharedKey = trim(self::readContainerFile($serverData, $containerName, $serverPskPath));
        if ($presharedKey === '') {
            $presharedKey = $serverData['preshared_key'] ?? '';
        }

        self::addWireguardPeer($serverData, $containerName, $configPath, $keys['public'], $presharedKey, $clientIp);
        if ($isAwg) {
            self::updateClientsTable($serverData, $keys['public'], $clientName, $containerName);
        }

        $vars = [
            '$WIREGUARD_CLIENT_PRIVATE_KEY' => $keys['private'],
            '$WIREGUARD_CLIENT_IP' => $clientIp,
            '$WIREGUARD_SERVER_PUBLIC_KEY' => $serverPubKey,
            '$WIREGUARD_PSK' => $presharedKey,
            '$SERVER_IP_ADDRESS' => $serverData['host'] ?? '',
            '$PRIMARY_DNS' => self::DEFAULT_DNS1,
            '$SECONDARY_DNS' => self::DEFAULT_DNS2,
            '$AWG_SERVER_PORT' => (string)($protocolConfig['port'] ?? $serverData['vpn_port'] ?? 55424),
            '$WIREGUARD_SERVER_PORT' => (string)($protocolConfig['port'] ?? 51820),
            '$JUNK_PACKET_COUNT' => (string)($protocolConfig['Jc'] ?? 3),
            '$JUNK_PACKET_MIN_SIZE' => (string)($protocolConfig['Jmin'] ?? 10),
            '$JUNK_PACKET_MAX_SIZE' => (string)($protocolConfig['Jmax'] ?? 50),
            '$INIT_PACKET_JUNK_SIZE' => (string)($protocolConfig['S1'] ?? 15),
            '$RESPONSE_PACKET_JUNK_SIZE' => (string)($protocolConfig['S2'] ?? 18),
            '$INIT_PACKET_MAGIC_HEADER' => (string)($protocolConfig['H1'] ?? 1020325451),
            '$RESPONSE_PACKET_MAGIC_HEADER' => (string)($protocolConfig['H2'] ?? 3288052141),
            '$UNDERLOAD_PACKET_MAGIC_HEADER' => (string)($protocolConfig['H3'] ?? 1766607858),
            '$TRANSPORT_PACKET_MAGIC_HEADER' => (string)($protocolConfig['H4'] ?? 2528465083),
        ];

        $template = self::readScript($templatePath);
        $config = self::replaceVars($template, $vars);

        $lastConfig = [
            'config' => $config,
            'hostName' => $serverData['host'] ?? '',
            'port' => (int)($protocolConfig['port'] ?? ($isAwg ? 55424 : 51820)),
            'client_priv_key' => $keys['private'],
            'client_ip' => $clientIp,
            'client_pub_key' => $keys['public'],
            'psk_key' => $presharedKey,
            'server_pub_key' => $serverPubKey,
        ];

        if ($isAwg) {
            $lastConfig['Jc'] = (string)($protocolConfig['Jc'] ?? 3);
            $lastConfig['Jmin'] = (string)($protocolConfig['Jmin'] ?? 10);
            $lastConfig['Jmax'] = (string)($protocolConfig['Jmax'] ?? 50);
            $lastConfig['S1'] = (string)($protocolConfig['S1'] ?? 15);
            $lastConfig['S2'] = (string)($protocolConfig['S2'] ?? 18);
            $lastConfig['H1'] = (string)($protocolConfig['H1'] ?? 1020325451);
            $lastConfig['H2'] = (string)($protocolConfig['H2'] ?? 3288052141);
            $lastConfig['H3'] = (string)($protocolConfig['H3'] ?? 1766607858);
            $lastConfig['H4'] = (string)($protocolConfig['H4'] ?? 2528465083);
        }

        return [
            'config' => $config,
            'last_config' => $lastConfig,
            'client_ip' => $clientIp,
            'public_key' => $keys['public'],
            'private_key' => $keys['private'],
            'preshared_key' => $presharedKey,
        ];
    }

    private static function generateOpenVpnConfig(
        array $serverData,
        string $containerName,
        array $openvpnConfig,
        string $templatePath,
        array $shadowsocksConfig = []
    ): array {
        $clientId = bin2hex(random_bytes(8));

        $genReq = sprintf(
            "docker exec -i %s bash -c 'cd /opt/amnezia/openvpn && EASYRSA_BATCH=1 easyrsa gen-req %s nopass'",
            $containerName,
            $clientId
        );
        self::executeServerCommand($serverData, $genReq, true);

        $signReq = sprintf(
            "docker exec -i %s bash -c 'cd /opt/amnezia/openvpn && EASYRSA_BATCH=1 yes | easyrsa sign-req client %s'",
            $containerName,
            $clientId
        );
        self::executeServerCommand($serverData, $signReq, true);

        $caCert = self::readContainerFile($serverData, $containerName, '/opt/amnezia/openvpn/ca.crt');
        $clientCert = self::readContainerFile($serverData, $containerName, "/opt/amnezia/openvpn/pki/issued/{$clientId}.crt");
        $clientKey = self::readContainerFile($serverData, $containerName, "/opt/amnezia/openvpn/pki/private/{$clientId}.key");
        $taKey = self::readContainerFile($serverData, $containerName, '/opt/amnezia/openvpn/ta.key');

        $vars = [
            '$OPENVPN_TRANSPORT_PROTO' => (string)($openvpnConfig['transport_proto'] ?? 'udp'),
            '$OPENVPN_NCP_DISABLE' => !empty($openvpnConfig['ncp_disable']) ? 'ncp-disable' : '',
            '$OPENVPN_CIPHER' => (string)($openvpnConfig['cipher'] ?? 'AES-256-GCM'),
            '$OPENVPN_HASH' => (string)($openvpnConfig['hash'] ?? 'SHA512'),
            '$PRIMARY_DNS' => self::DEFAULT_DNS1,
            '$SECONDARY_DNS' => self::DEFAULT_DNS2,
            '$REMOTE_HOST' => $serverData['host'] ?? '',
            '$OPENVPN_PORT' => (string)($openvpnConfig['port'] ?? 1194),
            '$OPENVPN_ADDITIONAL_CLIENT_CONFIG' => (string)($openvpnConfig['additional_client_config'] ?? ''),
            '$SHADOWSOCKS_LOCAL_PORT' => (string)($shadowsocksConfig['local_port'] ?? 8585),
        ];

        $template = self::readScript($templatePath);
        $config = self::replaceVars($template, $vars);
        $config = str_replace('$OPENVPN_CA_CERT', trim($caCert), $config);
        $config = str_replace('$OPENVPN_CLIENT_CERT', trim($clientCert), $config);
        $config = str_replace('$OPENVPN_PRIV_KEY', trim($clientKey), $config);

        if (!isset($openvpnConfig['tls_auth']) || $openvpnConfig['tls_auth']) {
            $config = str_replace('$OPENVPN_TA_KEY', trim($taKey), $config);
        } else {
            $config = str_replace(['<tls-auth>', '</tls-auth>'], '', $config);
            $config = str_replace('$OPENVPN_TA_KEY', '', $config);
        }

        return [
            'config' => $config,
            'client_id' => $clientId,
        ];
    }

    private static function generateShadowSocksConfig(array $serverData, string $containerName, array $config): array {
        $password = trim(self::readContainerFile($serverData, $containerName, '/opt/amnezia/shadowsocks/shadowsocks.key'));
        $serverPort = self::allocateShadowSocksPort($serverData, $containerName, $config);
        $localPort = (int)($config['local_port'] ?? 8585);
        $cipher = (string)($config['cipher'] ?? 'chacha20-ietf-poly1305');

        $serverConfig = [
            'local_port' => $localPort,
            'method' => $cipher,
            'password' => $password,
            'server' => '0.0.0.0',
            'server_port' => $serverPort,
            'timeout' => 60,
        ];

        self::executeServerCommand(
            $serverData,
            "docker exec -i {$containerName} sh -c 'mkdir -p /opt/amnezia/shadowsocks/clients'",
            true
        );

        $clientConfigPath = "/opt/amnezia/shadowsocks/clients/{$serverPort}.json";
        self::writeContainerFile(
            $serverData,
            $containerName,
            $clientConfigPath,
            json_encode($serverConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)
        );
        self::executeServerCommand(
            $serverData,
            "docker exec -i {$containerName} sh -c " . escapeshellarg("ssserver -c {$clientConfigPath} &"),
            true
        );

        return [
            'server' => $serverData['host'] ?? '',
            'server_port' => $serverPort,
            'local_port' => $localPort,
            'password' => $password,
            'timeout' => 60,
            'method' => $cipher,
        ];
    }

    private static function allocateShadowSocksPort(array $serverData, string $containerName, array $config): int {
        $serverId = (int)($serverData['id'] ?? 0);
        $defaultRange = $containerName === 'amnezia-openvpn-cloak' ? [41000, 41999] : [40000, 40999];
        [$rangeStart, $rangeEnd] = self::parsePortRange($config, $defaultRange[0], $defaultRange[1]);

        $used = $serverId > 0 ? self::getUsedShadowSocksPorts($serverId, $containerName) : [];
        $basePort = (int)($config['port'] ?? 0);
        if ($basePort > 0) {
            $used[$basePort] = true;
        }

        if ($rangeStart > 0 && $rangeEnd >= $rangeStart) {
            for ($port = $rangeStart; $port <= $rangeEnd; $port++) {
                if (isset($used[$port])) {
                    continue;
                }
                return $port;
            }
        }

        if ($basePort > 0) {
            $serverUsed = self::listServerPorts($serverData, 'tcp');
            if (!isset($serverUsed[$basePort])) {
                return $basePort;
            }
        }

        throw new Exception('No free Shadowsocks ports available');
    }

    private static function parsePortRange(array $config, int $fallbackStart, int $fallbackEnd): array {
        $range = $config['port_range'] ?? '';
        if (is_string($range) && preg_match('/^\\s*(\\d+)\\s*-\\s*(\\d+)\\s*$/', $range, $matches)) {
            $start = (int)$matches[1];
            $end = (int)$matches[2];
        } elseif (isset($config['port_range_start'], $config['port_range_end'])) {
            $start = (int)$config['port_range_start'];
            $end = (int)$config['port_range_end'];
        } else {
            $start = $fallbackStart;
            $end = $fallbackEnd;
        }

        if ($start > 0 && $end > 0 && $start > $end) {
            [$start, $end] = [$end, $start];
        }

        return [$start, $end];
    }

    private static function getUsedShadowSocksPorts(int $serverId, string $containerName): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT protocols FROM vpn_clients WHERE server_id = ? AND protocols IS NOT NULL');
        $stmt->execute([$serverId]);

        $used = [];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $raw) {
            $containers = json_decode($raw ?: '[]', true);
            if (!is_array($containers)) {
                continue;
            }
            foreach ($containers as $container) {
                if (($container['container'] ?? '') !== $containerName) {
                    continue;
                }
                $lastConfigRaw = $container['shadowsocks']['last_config'] ?? '';
                if ($lastConfigRaw === '') {
                    continue;
                }
                $lastConfig = json_decode($lastConfigRaw, true);
                if (!is_array($lastConfig)) {
                    continue;
                }
                $port = $lastConfig['server_port'] ?? $lastConfig['port'] ?? null;
                if ($port) {
                    $used[(int)$port] = true;
                }
            }
        }

        return $used;
    }

    private static function listServerPorts(array $serverData, string $proto): array {
        $proto = $proto === 'udp' ? 'udp' : 'tcp';
        $key = (string)($serverData['id'] ?? ($serverData['host'] ?? 'server')) . ':' . (string)($serverData['port'] ?? '') . ':' . $proto;
        if (isset(self::$cachedUsedPorts[$key])) {
            return self::$cachedUsedPorts[$key];
        }

        $output = self::executeServerCommand($serverData, "cat /proc/net/{$proto} /proc/net/{$proto}6 2>/dev/null || true", false);
        $ports = self::parseProcNetPorts($output);
        $hasHeader = stripos($output, 'local_address') !== false;

        if (!$hasHeader) {
            $flag = $proto === 'tcp' ? '-ltnH' : '-lunH';
            $output = self::executeServerCommand($serverData, "ss {$flag} 2>/dev/null || true", false);
            $ports = self::parseSsPorts($output);
        }

        self::$cachedUsedPorts[$key] = $ports;
        return $ports;
    }

    private static function parseProcNetPorts(string $output): array {
        $ports = [];
        $lines = preg_split('/\r?\n/', trim($output));
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || stripos($line, 'local_address') !== false) {
                continue;
            }
            $parts = preg_split('/\s+/', $line);
            if (count($parts) < 2) {
                continue;
            }
            $local = $parts[1];
            $pos = strrpos($local, ':');
            if ($pos === false) {
                continue;
            }
            $hexPort = substr($local, $pos + 1);
            if ($hexPort === '') {
                continue;
            }
            $port = hexdec($hexPort);
            if ($port > 0) {
                $ports[$port] = true;
            }
        }
        return $ports;
    }

    private static function parseSsPorts(string $output): array {
        $ports = [];
        $lines = preg_split('/\r?\n/', trim($output));
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $parts = preg_split('/\s+/', $line);
            if (count($parts) < 4) {
                continue;
            }
            $local = $parts[3];
            if (preg_match('/:(\d+)$/', $local, $matches)) {
                $port = (int)$matches[1];
                if ($port > 0) {
                    $ports[$port] = true;
                }
            }
        }
        return $ports;
    }

    private static function isServerPortFree(array $serverData, int $port, string $proto = 'tcp'): bool {
        $used = self::listServerPorts($serverData, $proto);
        return !isset($used[$port]);
    }

    private static function generateCloakConfig(array $serverData, string $containerName, array $config): array {
        $publicKey = trim(self::readContainerFile($serverData, $containerName, '/opt/amnezia/cloak/cloak_public.key'));
        $bypassUid = trim(self::readContainerFile($serverData, $containerName, '/opt/amnezia/cloak/cloak_bypass_uid.key'));

        return [
            'Transport' => 'direct',
            'ProxyMethod' => 'openvpn',
            'EncryptionMethod' => 'aes-gcm',
            'UID' => $bypassUid,
            'PublicKey' => $publicKey,
            'ServerName' => (string)($config['site'] ?? 'tile.openstreetmap.org'),
            'NumConn' => 1,
            'BrowserSig' => 'chrome',
            'StreamTimeout' => 300,
            'RemoteHost' => $serverData['host'] ?? '',
            'RemotePort' => (int)($config['port'] ?? 443),
        ];
    }

    private static function generateIkev2Config(array $serverData, string $containerName): array {
        $clientId = bin2hex(random_bytes(8));
        $password = '';

        $createCmd = "docker exec -i {$containerName} bash -c " . escapeshellarg(
            "certutil -z <(head -c 1024 /dev/urandom) -S -c \"IKEv2 VPN CA\" -n \"{$clientId}\" " .
            "-s \"O=IKEv2 VPN,CN={$clientId}\" -k rsa -g 3072 -v 120 -d sql:/etc/ipsec.d -t \",,\" " .
            "--keyUsage digitalSignature,keyEncipherment --extKeyUsage serverAuth,clientAuth -8 \"{$clientId}\""
        );
        self::executeServerCommand($serverData, $createCmd, true);

        $exportCmd = "docker exec -i {$containerName} bash -c " . escapeshellarg(
            "pk12util -W \"{$password}\" -d sql:/etc/ipsec.d -n \"{$clientId}\" -o \"/opt/amnezia/ikev2/clients/{$clientId}.p12\""
        );
        self::executeServerCommand($serverData, $exportCmd, true);

        $certBase64 = trim(self::executeServerCommand(
            $serverData,
            "docker exec -i {$containerName} sh -c 'base64 /opt/amnezia/ikev2/clients/{$clientId}.p12 | tr -d \"\\n\"'",
            true
        ));

        return [
            'hostName' => $serverData['host'] ?? '',
            'userName' => $clientId,
            'cert' => $certBase64,
            'password' => $password,
        ];
    }

    private static function readContainerFile(array $serverData, string $containerName, string $path): string {
        $cmd = sprintf("docker exec -i %s cat %s 2>/dev/null", $containerName, escapeshellarg($path));
        return self::executeServerCommand($serverData, $cmd, true) ?? '';
    }

    private static function writeContainerFile(array $serverData, string $containerName, string $path, string $content): void {
        $b64 = base64_encode($content);
        $cmd = sprintf(
            "docker exec -i %s sh -c %s",
            $containerName,
            escapeshellarg("echo '{$b64}' | base64 -d > {$path}")
        );
        self::executeServerCommand($serverData, $cmd, true);
    }

    private static function getNextClientIPFromConfig(
        array $serverData,
        string $containerName,
        string $configPath,
        string $subnetAddress
    ): string {
        $cmd = sprintf(
            "docker exec -i %s sh -c %s",
            $containerName,
            escapeshellarg("grep -E '^AllowedIPs' {$configPath} | awk '{print \\$3}'")
        );
        $out = trim(self::executeServerCommand($serverData, $cmd, true));
        $used = [];
        if ($out !== '') {
            foreach (preg_split('/\r?\n/', $out) as $line) {
                $ip = trim(str_replace('/32', '', $line));
                if ($ip !== '') {
                    $used[$ip] = true;
                }
            }
        }

        $parts = explode('.', $subnetAddress);
        if (count($parts) !== 4) {
            throw new Exception('Invalid subnet address');
        }
        $base = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.';

        for ($i = 2; $i <= 254; $i++) {
            $candidate = $base . $i;
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }

        throw new Exception('No free IP addresses in subnet');
    }
    
    /**
     * Generate client keys on remote server
     */
    private static function generateClientKeys(array $serverData, string $containerName, string $clientName): array {
        $containerName = $containerName ?: ($serverData['container_name'] ?? '');
        
        $cmd = sprintf(
            "docker exec -i %s sh -c \"umask 077; wg genkey | tee /tmp/%s_priv.key | wg pubkey > /tmp/%s_pub.key; cat /tmp/%s_priv.key; echo '---'; cat /tmp/%s_pub.key; rm -f /tmp/%s_priv.key /tmp/%s_pub.key\"",
            $containerName,
            $clientName, $clientName, $clientName, $clientName, $clientName, $clientName
        );
        
        $escaped = escapeshellarg($cmd);
        $sshCmd = sprintf(
            "sshpass -p '%s' ssh -p %d -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            $serverData['password'],
            $serverData['port'],
            $serverData['username'],
            $serverData['host'],
            $escaped
        );
        
        $out = shell_exec($sshCmd);
        $parts = explode("---", trim($out));
        
        if (count($parts) < 2) {
            throw new Exception("Failed to generate client keys");
        }
        
        return [
            'private' => trim($parts[0]),
            'public' => trim($parts[1])
        ];
    }
    
    /**
     * Get next available client IP
     */
    private static function getNextClientIP(array $serverData): string {
        $pdo = DB::conn();
        
        // Get used IPs from database
        $stmt = $pdo->prepare('SELECT client_ip FROM vpn_clients WHERE server_id = ?');
        $stmt->execute([$serverData['id']]);
        $usedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Parse subnet
        $parts = explode('/', $serverData['vpn_subnet']);
        $networkLong = ip2long($parts[0]);
        
        // Reserve network address
        $used = ['10.8.1.0' => true];
        foreach ($usedIPs as $ip) {
            $used[$ip] = true;
        }
        
        // Find next free IP starting from .1
        for ($i = 1; $i <= 253; $i++) {
            $candidate = long2ip($networkLong + $i);
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }
        
        throw new Exception('No free IP addresses in subnet');
    }
    
    /**
     * Build client configuration file
     */
    private static function buildClientConfig(
        string $privateKey,
        string $clientIP,
        string $serverPublicKey,
        string $presharedKey,
        string $serverHost,
        int $serverPort,
        array $awgParams
    ): string {
        $config = "[Interface]\n";
        $config .= "PrivateKey = {$privateKey}\n";
        $config .= "Address = {$clientIP}/32\n";
        $config .= "DNS = 1.1.1.1, 1.0.0.1\n";
        
        // Add AWG parameters
        foreach (['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'] as $key) {
            if (isset($awgParams[$key])) {
                $config .= "{$key} = {$awgParams[$key]}\n";
            }
        }
        
        $config .= "\n[Peer]\n";
        $config .= "PublicKey = {$serverPublicKey}\n";
        $config .= "PresharedKey = {$presharedKey}\n";
        $config .= "Endpoint = {$serverHost}:{$serverPort}\n";
        $config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        $config .= "PersistentKeepalive = 25\n";
        
        return $config;
    }
    
    /**
     * Add client to server using official method (append + wg syncconf)
     */
    private static function addClientToServer(array $serverData, string $publicKey, string $clientIP): void {
        $containerName = $serverData['container_name'];
        self::addWireguardPeer(
            $serverData,
            $containerName,
            '/opt/amnezia/awg/wg0.conf',
            $publicKey,
            $serverData['preshared_key'],
            $clientIP
        );
        self::updateClientsTable($serverData, $publicKey, $clientIP, $containerName);
    }

    private static function addWireguardPeer(
        array $serverData,
        string $containerName,
        string $configPath,
        string $publicKey,
        string $presharedKey,
        string $clientIP
    ): void {
        $peerBlock = "\n[Peer]\n";
        $peerBlock .= "PublicKey = {$publicKey}\n";
        $peerBlock .= "PresharedKey = {$presharedKey}\n";
        $peerBlock .= "AllowedIPs = {$clientIP}/32\n";

        $escaped = addslashes($peerBlock);
        $tempFile = '/tmp/' . bin2hex(random_bytes(8)) . '.tmp';

        $cmd1 = sprintf("docker exec -i %s sh -c 'echo \"%s\" > %s'", $containerName, $escaped, $tempFile);
        self::executeServerCommand($serverData, $cmd1, true);

        $cmd2 = sprintf("docker exec -i %s sh -c 'cat %s >> %s'", $containerName, $tempFile, $configPath);
        self::executeServerCommand($serverData, $cmd2, true);

        $cmd3 = sprintf("docker exec -i %s bash -c 'wg syncconf wg0 <(wg-quick strip %s)'", $containerName, $configPath);
        self::executeServerCommand($serverData, $cmd3, true);

        $cmd4 = sprintf("docker exec -i %s rm -f %s", $containerName, $tempFile);
        self::executeServerCommand($serverData, $cmd4, true);
    }
    
    /**
     * Update clientsTable on server
     */
    private static function updateClientsTable(array $serverData, string $publicKey, string $name, string $containerName): void {
        
        // Read current table
        $cmd = sprintf("docker exec -i %s cat /opt/amnezia/awg/clientsTable 2>/dev/null", $containerName);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);
        
        if (!is_array($table)) {
            $table = [];
        }
        
        // Add new client
        $table[] = [
            'clientId' => $publicKey,
            'userData' => [
                'clientName' => $name,
                'creationDate' => date('D M j H:i:s Y')
            ]
        ];
        
        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > /opt/amnezia/awg/clientsTable'", $containerName, $escaped);
        self::executeServerCommand($serverData, $updateCmd, true);
    }
    
    /**
     * Execute command on server
     */
    private static function executeServerCommand(array $serverData, string $command, bool $sudo = false): string {
        if ($sudo && strtolower($serverData['username']) !== 'root') {
            $command = "echo '{$serverData['password']}' | sudo -S " . $command;
        }
        
        $escapedCommand = escapeshellarg($command);
        $sshCommand = sprintf(
            "sshpass -p '%s' ssh  -p %d -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            $serverData['password'],
            $serverData['port'],
            $serverData['username'],
            $serverData['host'],
            $escapedCommand
        );
        
        return shell_exec($sshCommand) ?? '';
    }
    
    /**
     * Generate QR code for configuration using Amnezia format
     * Uses working QrUtil from /Users/oleg/Documents/amnezia
     */
    private static function generateQRCode(string $payloadJson): string {
        require_once __DIR__ . '/QrUtil.php';
        
        try {
            $payload = QrUtil::encodeAmneziaPayloadFromJson($payloadJson);
            $dataUri = QrUtil::pngBase64($payload);
            return $dataUri;
        } catch (Throwable $e) {
            try {
                $payloadOld = QrUtil::encodeOldPayloadFromConf($payloadJson);
                return QrUtil::pngBase64($payloadOld);
            } catch (Throwable $legacyError) {
                error_log('Failed to generate QR code: ' . $legacyError->getMessage());
                return '';
            }
        }
    }
    
    /**
     * Get all clients for a server
     */
    public static function listByServer(int $serverId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE server_id = ? ORDER BY created_at DESC');
        $stmt->execute([$serverId]);
        return $stmt->fetchAll();
    }

    public static function findByShareToken(string $token): ?array {
        $pdo = DB::conn();
        if (!self::hasShareTokenColumn($pdo)) {
            return null;
        }
        try {
            $stmt = $pdo->prepare('SELECT * FROM vpn_clients WHERE share_token = ? LIMIT 1');
            $stmt->execute([$token]);
            $client = $stmt->fetch();
            return $client ?: null;
        } catch (Throwable $e) {
            return null;
        }
    }
    
    /**
     * Get all clients for a user
     */
    public static function listByUser(int $userId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host as server_host
            FROM vpn_clients c
            LEFT JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        ');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Revoke client access (disable without deleting)
     */
    public function revoke(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // Remove from server
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if ($serverData && $serverData['status'] === 'active') {
            try {
                if (!empty($this->data['protocols'])) {
                    self::revokeMultiProtocolClient($serverData, $this->data);
                } else {
                    self::removeClientFromServer($serverData, $this->data['public_key']);
                }
            } catch (Exception $e) {
                error_log('Failed to remove client from server: ' . $e->getMessage());
            }
        }
        
        // Mark as disabled in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['disabled', $this->clientId]);
    }
    
    /**
     * Restore client access
     */
    public function restore(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // Re-add to server
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if ($serverData && $serverData['status'] === 'active') {
            try {
                $containers = [];
                if (!empty($serverData['containers'])) {
                    $decoded = json_decode($serverData['containers'], true);
                    if (is_array($decoded)) {
                        $containers = $decoded;
                    }
                }

                if ($containers) {
                    $built = self::buildMultiProtocolClientData($serverData, $containers, $this->data['name']);
                    $pdo = DB::conn();
                    $stmt = $pdo->prepare('
                        UPDATE vpn_clients
                        SET client_ip = ?,
                            client_ips = ?,
                            public_key = ?,
                            private_key = ?,
                            preshared_key = ?,
                            config = ?,
                            protocols = ?,
                            qr_code = ?,
                            status = ?
                        WHERE id = ?
                    ');
                    $stmt->execute([
                        $built['awg_client_ip'] !== '' ? $built['awg_client_ip'] : ($built['client_ips']['awg'] ?? ''),
                        json_encode($built['client_ips']),
                        $built['awg_keys']['public'],
                        $built['awg_keys']['private'],
                        $built['awg_keys']['preshared'],
                        $built['default_config'],
                        json_encode($built['client_containers']),
                        $built['qr_code'],
                        'active',
                        $this->clientId
                    ]);
                    $this->load();
                    return true;
                }

                self::addClientToServer($serverData, $this->data['public_key'], $this->data['client_ip']);
            } catch (Exception $e) {
                throw new Exception('Failed to restore client on server: ' . $e->getMessage());
            }
        }
        
        // Mark as active in database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET status = ? WHERE id = ?');
        return $stmt->execute(['active', $this->clientId]);
    }

    public function regenerateQrFromProtocols(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }

        if (empty($this->data['protocols'])) {
            return false;
        }

        $containers = json_decode($this->data['protocols'], true);
        if (!is_array($containers) || !$containers) {
            return false;
        }

        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();

        $qrCode = self::buildQrCode($serverData, $containers);
        if ($qrCode === '') {
            return false;
        }

        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET qr_code = ? WHERE id = ?');
        $stmt->execute([$qrCode, $this->clientId]);
        $this->data['qr_code'] = $qrCode;
        return true;
    }
    
    /**
     * Delete client permanently
     */
    public function delete(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        // First revoke to remove from server
        if ($this->data['status'] === 'active') {
            $this->revoke();
        }
        
        // Delete from database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM vpn_clients WHERE id = ?');
        return $stmt->execute([$this->clientId]);
    }

    private static function revokeMultiProtocolClient(array $serverData, array $clientData): void {
        $containers = json_decode($clientData['protocols'] ?? '[]', true);
        if (!is_array($containers) || empty($containers)) {
            self::removeClientFromServer($serverData, $clientData['public_key'] ?? '');
            return;
        }

        foreach ($containers as $containerConfig) {
            $containerName = $containerConfig['container'] ?? '';
            if ($containerName === '') {
                continue;
            }

            $awgLast = self::decodeLastConfig($containerConfig, 'awg');
            if ($awgLast) {
                $publicKey = $awgLast['client_pub_key'] ?? ($clientData['public_key'] ?? '');
                if ($publicKey !== '') {
                    self::removeWireguardPeerFromContainer(
                        $serverData,
                        $containerName,
                        '/opt/amnezia/awg/wg0.conf',
                        $publicKey
                    );
                    self::removeFromClientsTable($serverData, $publicKey, $containerName);
                }
            }

            $wgLast = self::decodeLastConfig($containerConfig, 'wireguard');
            if ($wgLast) {
                $publicKey = $wgLast['client_pub_key'] ?? '';
                if ($publicKey !== '') {
                    self::removeWireguardPeerFromContainer(
                        $serverData,
                        $containerName,
                        '/opt/amnezia/wireguard/wg0.conf',
                        $publicKey
                    );
                }
            }

            $ovpnLast = self::decodeLastConfig($containerConfig, 'openvpn');
            if ($ovpnLast) {
                $clientId = (string)($ovpnLast['client_id'] ?? '');
                if ($clientId !== '') {
                    self::revokeOpenVpnClient($serverData, $containerName, $clientId);
                }
            }

            $ssLast = self::decodeLastConfig($containerConfig, 'shadowsocks');
            if ($ssLast) {
                $port = (int)($ssLast['server_port'] ?? $ssLast['port'] ?? 0);
                if ($port > 0) {
                    self::revokeShadowSocksClient($serverData, $containerName, $port);
                }
            }

            $ikev2Last = self::decodeLastConfig($containerConfig, 'ikev2');
            if ($ikev2Last) {
                $clientId = (string)($ikev2Last['userName'] ?? $ikev2Last['user'] ?? $ikev2Last['id'] ?? '');
                if ($clientId !== '') {
                    self::revokeIkev2Client($serverData, $containerName, $clientId);
                }
            }
        }
    }

    private static function decodeLastConfig(array $containerConfig, string $protocol): array {
        $raw = $containerConfig[$protocol]['last_config'] ?? '';
        if ($raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    private static function removeWireguardPeerFromContainer(
        array $serverData,
        string $containerName,
        string $configPath,
        string $publicKey
    ): void {
        $removeCmd = sprintf(
            "docker exec -i %s wg set wg0 peer %s remove",
            $containerName,
            escapeshellarg($publicKey)
        );
        self::executeServerCommand($serverData, $removeCmd, true);

        $readCmd = sprintf("docker exec -i %s cat %s", $containerName, $configPath);
        $config = self::executeServerCommand($serverData, $readCmd, true);
        $newConfig = self::removePeerFromConfig($config, $publicKey);
        $escapedConfig = str_replace("'", "'\\''", $newConfig);
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'echo '\\''%s'\\'' > %s'",
            $containerName,
            $escapedConfig,
            $configPath
        );
        self::executeServerCommand($serverData, $writeCmd, true);

        $syncCmd = sprintf(
            "docker exec -i %s bash -c 'wg syncconf wg0 <(wg-quick strip %s)'",
            $containerName,
            $configPath
        );
        self::executeServerCommand($serverData, $syncCmd, true);
    }

    private static function revokeOpenVpnClient(array $serverData, string $containerName, string $clientId): void {
        $cmd = sprintf(
            "docker exec -i %s bash -c %s",
            $containerName,
            escapeshellarg(
                "cd /opt/amnezia/openvpn && EASYRSA_BATCH=1 yes | easyrsa revoke {$clientId} || true; " .
                "easyrsa gen-crl || true; " .
                "cp pki/crl.pem /opt/amnezia/openvpn/crl.pem 2>/dev/null || true; " .
                "rm -f /opt/amnezia/openvpn/pki/issued/{$clientId}.crt /opt/amnezia/openvpn/pki/private/{$clientId}.key /opt/amnezia/openvpn/pki/reqs/{$clientId}.req"
            )
        );
        self::executeServerCommand($serverData, $cmd, true);
    }

    private static function revokeShadowSocksClient(array $serverData, string $containerName, int $port): void {
        $configPath = "/opt/amnezia/shadowsocks/clients/{$port}.json";
        $cmd = sprintf(
            "docker exec -i %s sh -c %s",
            $containerName,
            escapeshellarg("pkill -f 'ssserver -c {$configPath}' 2>/dev/null || true; rm -f {$configPath}")
        );
        self::executeServerCommand($serverData, $cmd, true);
    }

    private static function revokeIkev2Client(array $serverData, string $containerName, string $clientId): void {
        $cmd = sprintf(
            "docker exec -i %s bash -c %s",
            $containerName,
            escapeshellarg(
                "certutil -D -n \"{$clientId}\" -d sql:/etc/ipsec.d 2>/dev/null || true; " .
                "rm -f /opt/amnezia/ikev2/clients/{$clientId}.p12"
            )
        );
        self::executeServerCommand($serverData, $cmd, true);
    }
    
    /**
     * Remove client from server WireGuard configuration
     */
    private static function removeClientFromServer(array $serverData, string $publicKey): void {
        $containerName = $serverData['container_name'];
        
        // First, remove using wg command (live removal)
        $removeCmd = sprintf(
            "docker exec -i %s wg set wg0 peer %s remove",
            $containerName,
            escapeshellarg($publicKey)
        );
        
        self::executeServerCommand($serverData, $removeCmd, true);
        
        // Then remove from wg0.conf file to make it persistent
        // Use a more reliable method: read, filter, write
        $readCmd = sprintf("docker exec -i %s cat /opt/amnezia/awg/wg0.conf", $containerName);
        $config = self::executeServerCommand($serverData, $readCmd, true);
        
        // Parse and remove the peer section
        $newConfig = self::removePeerFromConfig($config, $publicKey);
        
        // Write back to file
        $escapedConfig = str_replace("'", "'\\''", $newConfig);
        $writeCmd = sprintf(
            "docker exec -i %s sh -c 'echo '\''%s'\'' > /opt/amnezia/awg/wg0.conf'",
            $containerName,
            $escapedConfig
        );
        
        self::executeServerCommand($serverData, $writeCmd, true);
        
        // Save config
        $saveCmd = sprintf("docker exec -i %s wg-quick save wg0", $containerName);
        self::executeServerCommand($serverData, $saveCmd, true);
        
        // Remove from clientsTable
        self::removeFromClientsTable($serverData, $publicKey, $containerName);
    }
    
    /**
     * Remove peer section from WireGuard config
     */
    private static function removePeerFromConfig(string $config, string $publicKey): string {
        $lines = explode("\n", $config);
        $newLines = [];
        $inPeerBlock = false;
        $skipBlock = false;
        
        foreach ($lines as $line) {
            $trimmed = trim($line);
            
            // Start of new section
            if (strpos($trimmed, '[') === 0) {
                $inPeerBlock = ($trimmed === '[Peer]');
                $skipBlock = false;
            }
            
            // Check if this peer block should be skipped
            if ($inPeerBlock && strpos($trimmed, 'PublicKey') === 0) {
                $parts = explode('=', $line, 2);
                if (count($parts) === 2 && trim($parts[1]) === $publicKey) {
                    $skipBlock = true;
                    // Remove the [Peer] line that was already added
                    array_pop($newLines);
                    continue;
                }
            }
            
            // Skip lines in the block to be removed
            if ($skipBlock && $inPeerBlock) {
                // Empty line ends the peer block
                if (empty($trimmed)) {
                    $skipBlock = false;
                    $inPeerBlock = false;
                }
                continue;
            }
            
            $newLines[] = $line;
        }
        
        return implode("\n", $newLines);
    }
    
    /**
     * Remove client from clientsTable
     */
    private static function removeFromClientsTable(array $serverData, string $publicKey, string $containerName): void {
        
        // Read current table
        $cmd = sprintf("docker exec -i %s cat /opt/amnezia/awg/clientsTable 2>/dev/null", $containerName);
        $tableJson = self::executeServerCommand($serverData, $cmd, true);
        $table = json_decode(trim($tableJson), true);
        
        if (!is_array($table)) {
            return;
        }
        
        // Filter out the client
        $table = array_filter($table, function($client) use ($publicKey) {
            return ($client['clientId'] ?? '') !== $publicKey;
        });
        
        // Re-index array
        $table = array_values($table);
        
        // Save back
        $newTableJson = json_encode($table, JSON_PRETTY_PRINT);
        $escaped = addslashes($newTableJson);
        $updateCmd = sprintf("docker exec -i %s sh -c 'echo \"%s\" > /opt/amnezia/awg/clientsTable'", $containerName, $escaped);
        self::executeServerCommand($serverData, $updateCmd, true);
    }
    
    /**
     * Get client data
     */
    public function getData(): ?array {
        return $this->data;
    }

    public function ensureShareToken(): string {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        $pdo = DB::conn();
        if (!self::hasShareTokenColumn($pdo)) {
            return '';
        }
        if (!empty($this->data['share_token'])) {
            return (string)$this->data['share_token'];
        }

        $token = self::generateUniqueShareToken($pdo);
        $stmt = $pdo->prepare('UPDATE vpn_clients SET share_token = ? WHERE id = ?');
        $stmt->execute([$token, $this->clientId]);
        $this->data['share_token'] = $token;

        return $token;
    }
    
    /**
     * Get configuration file content
     */
    public function getConfig(): string {
        return $this->data['config'] ?? '';
    }

    public function getProtocolContainers(): array {
        $decoded = json_decode($this->data['protocols'] ?? '[]', true);
        return is_array($decoded) ? $decoded : [];
    }

    public function getProtocolConfig(string $protocol, ?string $container = null): string {
        $containers = $this->getProtocolContainers();
        foreach ($containers as $containerConfig) {
            if ($container && ($containerConfig['container'] ?? '') !== $container) {
                continue;
            }
            if (empty($containerConfig[$protocol]['last_config'])) {
                continue;
            }
            $lastConfigRaw = $containerConfig[$protocol]['last_config'];
            $lastConfig = json_decode($lastConfigRaw, true);
            if (is_array($lastConfig) && isset($lastConfig['config'])) {
                return (string)$lastConfig['config'];
            }
            return (string)$lastConfigRaw;
        }

        return '';
    }
    
    /**
     * Get QR code
     */
    public function getQRCode(): string {
        return $this->data['qr_code'] ?? '';
    }
    
    /**
     * Sync traffic statistics from server
     */
    public function syncStats(): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        $server = new VpnServer($this->data['server_id']);
        $serverData = $server->getData();
        
        if (!$serverData || $serverData['status'] !== 'active') {
            return false;
        }
        
        try {
            $stats = self::getClientStatsFromServer($serverData, $this->data['public_key']);
            
            $pdo = DB::conn();
            $stmt = $pdo->prepare('
                UPDATE vpn_clients 
                SET bytes_sent = ?, bytes_received = ?, last_handshake = ?, last_sync_at = NOW()
                WHERE id = ?
            ');
            
            $lastHandshake = $stats['last_handshake'] > 0 
                ? date('Y-m-d H:i:s', $stats['last_handshake']) 
                : null;
            
            return $stmt->execute([
                $stats['bytes_sent'],
                $stats['bytes_received'],
                $lastHandshake,
                $this->clientId
            ]);
        } catch (Exception $e) {
            error_log('Failed to sync client stats: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get client statistics from server
     */
    private static function getClientStatsFromServer(array $serverData, string $publicKey): array {
        $containerName = $serverData['container_name'];
        
        // Get WireGuard interface stats
        $cmd = sprintf("docker exec -i %s wg show wg0 dump", $containerName);
        $output = self::executeServerCommand($serverData, $cmd, true);
        
        $stats = [
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'last_handshake' => 0
        ];
        
        // Parse wg dump output
        // Format: public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
        // First line is server (private key), skip it
        // For clients: transfer_rx = bytes received by server (sent by client)
        //              transfer_tx = bytes sent by server (received by client)
        $lines = explode("\n", trim($output));
        foreach ($lines as $line) {
            if (empty($line)) continue;
            
            $parts = preg_split('/\s+/', trim($line));
            
            // Skip first line (server) - it has different format
            if (count($parts) < 7) continue;
            
            // Match by public key
            if ($parts[0] === $publicKey) {
                $stats['last_handshake'] = (int)$parts[4];
                $stats['bytes_sent'] = (int)$parts[5];      // transfer_rx - client sent
                $stats['bytes_received'] = (int)$parts[6];  // transfer_tx - client received
                break;
            }
        }
        
        return $stats;
    }
    
    /**
     * Sync stats for all active clients on a server
     */
    public static function syncAllStatsForServer(int $serverId): int {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND status = ?');
        $stmt->execute([$serverId, 'active']);
        $clientIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        $synced = 0;
        foreach ($clientIds as $clientId) {
            try {
                $client = new VpnClient($clientId);
                if ($client->syncStats()) {
                    $synced++;
                }
            } catch (Exception $e) {
                error_log('Failed to sync stats for client ' . $clientId . ': ' . $e->getMessage());
            }
        }
        
        return $synced;
    }
    
    /**
     * Get human-readable traffic statistics
     */
    public function getFormattedStats(): array {
        if (!$this->data) {
            return ['sent' => 'N/A', 'received' => 'N/A', 'total' => 'N/A', 'last_seen' => 'Never'];
        }
        
        $sent = $this->formatBytes($this->data['bytes_sent'] ?? 0);
        $received = $this->formatBytes($this->data['bytes_received'] ?? 0);
        $total = $this->formatBytes(($this->data['bytes_sent'] ?? 0) + ($this->data['bytes_received'] ?? 0));
        
        $lastSeen = 'Never';
        if (!empty($this->data['last_handshake'])) {
            $lastHandshake = strtotime($this->data['last_handshake']);
            $diff = time() - $lastHandshake;
            
            if ($diff < 300) {
                $lastSeen = 'Online';
            } elseif ($diff < 3600) {
                $lastSeen = floor($diff / 60) . ' minutes ago';
            } elseif ($diff < 86400) {
                $lastSeen = floor($diff / 3600) . ' hours ago';
            } else {
                $lastSeen = floor($diff / 86400) . ' days ago';
            }
        }
        
        return [
            'sent' => $sent,
            'received' => $received,
            'total' => $total,
            'last_seen' => $lastSeen,
            'is_online' => !empty($this->data['last_handshake']) && (time() - strtotime($this->data['last_handshake'])) < 300
        ];
    }
    
    /**
     * Format bytes to human-readable string (always in MB)
     */
    private function formatBytes(int $bytes): string {
        $mb = $bytes / 1048576; // 1024 * 1024
        return number_format($mb, 2) . ' MB';
    }
    
    /**
     * Set client expiration date
     * 
     * @param int $clientId Client ID
     * @param string|null $expiresAt Expiration date (Y-m-d H:i:s) or null for never expires
     * @return bool Success
     */
    public static function setExpiration(int $clientId, ?string $expiresAt): bool {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET expires_at = ? WHERE id = ?');
        return $stmt->execute([$expiresAt, $clientId]);
    }
    
    /**
     * Extend client expiration by days
     * 
     * @param int $clientId Client ID
     * @param int $days Days to extend
     * @return bool Success
     */
    public static function extendExpiration(int $clientId, int $days): bool {
        $pdo = DB::conn();
        
        // Get current expiration
        $stmt = $pdo->prepare('SELECT expires_at FROM vpn_clients WHERE id = ?');
        $stmt->execute([$clientId]);
        $client = $stmt->fetch();
        
        if (!$client) {
            return false;
        }
        
        // Calculate new expiration from current or now
        $baseDate = $client['expires_at'] ? strtotime($client['expires_at']) : time();
        $newExpiration = date('Y-m-d H:i:s', strtotime("+{$days} days", $baseDate));
        
        return self::setExpiration($clientId, $newExpiration);
    }
    
    /**
     * Get clients expiring soon
     * 
     * @param int $days Check for clients expiring within N days
     * @return array List of expiring clients
     */
    public static function getExpiringClients(int $days = 7): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT c.*, s.name as server_name, s.host, u.name as user_name, u.email
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            JOIN users u ON c.user_id = u.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= DATE_ADD(NOW(), INTERVAL ? DAY)
            AND c.expires_at > NOW()
            AND c.status = "active"
            ORDER BY c.expires_at ASC
        ');
        $stmt->execute([$days]);
        return $stmt->fetchAll();
    }
    
    /**
     * Get expired clients
     * 
     * @return array List of expired clients
     */
    public static function getExpiredClients(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT c.*, s.name as server_name, s.host
            FROM vpn_clients c
            JOIN vpn_servers s ON c.server_id = s.id
            WHERE c.expires_at IS NOT NULL 
            AND c.expires_at <= NOW()
            AND c.status = "active"
            ORDER BY c.expires_at DESC
        ');
        return $stmt->fetchAll();
    }
    
    /**
     * Disable expired clients automatically
     * 
     * @return int Number of clients disabled
     */
    public static function disableExpiredClients(): int {
        $expiredClients = self::getExpiredClients();
        $count = 0;
        
        foreach ($expiredClients as $clientData) {
            try {
                $client = new self($clientData['id']);
                $client->revoke();
                $count++;
            } catch (Exception $e) {
                error_log("Failed to disable expired client {$clientData['id']}: " . $e->getMessage());
            }
        }
        
        return $count;
    }
    
    /**
     * Check if client is expired
     * 
     * @return bool True if expired
     */
    public function isExpired(): bool {
        if (!$this->data) {
            return false;
        }
        
        return $this->data['expires_at'] !== null && strtotime($this->data['expires_at']) <= time();
    }
    
    /**
     * Get days until expiration
     * 
     * @return int|null Days until expiration (negative if expired, null if never expires)
     */
    public function getDaysUntilExpiration(): ?int {
        if (!$this->data || $this->data['expires_at'] === null) {
            return null;
        }
        
        $diff = strtotime($this->data['expires_at']) - time();
        return (int)floor($diff / 86400);
    }
    
    /**
     * Set traffic limit for client
     * 
     * @param int|null $limitBytes Traffic limit in bytes (NULL = unlimited)
     * @return bool Success
     */
    public function setTrafficLimit(?int $limitBytes): bool {
        if (!$this->data) {
            throw new Exception('Client not loaded');
        }
        
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_clients SET traffic_limit = ? WHERE id = ?');
        $result = $stmt->execute([$limitBytes, $this->clientId]);
        
        if ($result) {
            $this->data['traffic_limit'] = $limitBytes;
        }
        
        return $result;
    }
    
    /**
     * Get total traffic used (sent + received)
     * 
     * @return int Total traffic in bytes
     */
    public function getTotalTraffic(): int {
        if (!$this->data) {
            return 0;
        }

        // Prefer the current bytes_* columns, but gracefully handle legacy traffic_* keys if present
        $sent = $this->data['bytes_sent'] ?? $this->data['traffic_sent'] ?? 0;
        $received = $this->data['bytes_received'] ?? $this->data['traffic_received'] ?? 0;

        return (int)$sent + (int)$received;
    }
    
    /**
     * Check if client has exceeded traffic limit
     * 
     * @return bool True if over limit
     */
    public function isOverLimit(): bool {
        if (!$this->data || $this->data['traffic_limit'] === null) {
            return false; // No limit set
        }
        
        $totalTraffic = $this->getTotalTraffic();
        return $totalTraffic >= (int)$this->data['traffic_limit'];
    }
    
    /**
     * Get traffic limit status
     * 
     * @return array Status info
     */
    public function getTrafficLimitStatus(): array {
        $totalTraffic = $this->getTotalTraffic();
        $limit = $this->data['traffic_limit'] ?? null;
        
        return [
            'total_traffic' => $totalTraffic,
            'traffic_limit' => $limit,
            'is_unlimited' => $limit === null,
            'is_over_limit' => $this->isOverLimit(),
            'percentage_used' => $limit ? min(100, round(($totalTraffic / $limit) * 100, 2)) : 0,
            'remaining' => $limit ? max(0, $limit - $totalTraffic) : null
        ];
    }
    
    /**
     * Get all clients that exceeded their traffic limit
     * 
     * @return array List of client IDs over limit
     */
    public static function getClientsOverLimit(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('
            SELECT id, name, bytes_sent, bytes_received, traffic_limit
            FROM vpn_clients
            WHERE traffic_limit IS NOT NULL
            AND (bytes_sent + bytes_received) >= traffic_limit
            AND status = "active"
            ORDER BY id
        ');
        
        return $stmt->fetchAll();
    }
    
    /**
     * Disable all clients that exceeded their traffic limit
     * 
     * @return int Number of clients disabled
     */
    public static function disableClientsOverLimit(): int {
        $clients = self::getClientsOverLimit();
        $disabled = 0;
        
        foreach ($clients as $clientData) {
            try {
                $client = new VpnClient($clientData['id']);
                if ($client->revoke()) {
                    $disabled++;
                    error_log("Client {$clientData['name']} (ID: {$clientData['id']}) disabled: traffic limit exceeded");
                }
            } catch (Exception $e) {
                error_log("Failed to disable client {$clientData['id']}: " . $e->getMessage());
            }
        }
        
        return $disabled;
    }
}
