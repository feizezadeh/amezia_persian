<?php
/**
 * VPN Server Management Class
 * Handles deployment and management of Amnezia VPN servers
 * Based on amnezia_deploy_v2.php
 */
class VpnServer {
    private $serverId;
    private $data;
    private array $cachedUsedPorts = [];

    private const SCRIPT_ROOT = __DIR__ . '/../assets/amnezia_scripts';
    private const DEFAULT_DNS1 = '1.1.1.1';
    private const DEFAULT_DNS2 = '1.0.0.1';
    
    public function __construct(?int $serverId = null) {
        $this->serverId = $serverId;
        if ($serverId) {
            $this->load();
        }
    }
    
    /**
     * Load server data from database
     */
    private function load(): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$this->serverId]);
        $this->data = $stmt->fetch();
        if (!$this->data) {
            throw new Exception('Server not found');
        }
    }

    private static function containerDefinitions(): array {
        return [
            'awg' => [
                'container' => 'amnezia-awg',
                'scripts' => 'awg',
                'protocols' => ['awg'],
            ],
            'wireguard' => [
                'container' => 'amnezia-wireguard',
                'scripts' => 'wireguard',
                'protocols' => ['wireguard'],
            ],
            'openvpn' => [
                'container' => 'amnezia-openvpn',
                'scripts' => 'openvpn',
                'protocols' => ['openvpn'],
            ],
            'shadowsocks' => [
                'container' => 'amnezia-shadowsocks',
                'scripts' => 'openvpn_shadowsocks',
                'protocols' => ['openvpn', 'shadowsocks'],
            ],
            'cloak' => [
                'container' => 'amnezia-openvpn-cloak',
                'scripts' => 'openvpn_cloak',
                'protocols' => ['openvpn', 'shadowsocks', 'cloak'],
            ],
            'ipsec' => [
                'container' => 'amnezia-ipsec',
                'scripts' => 'ipsec',
                'protocols' => ['ikev2'],
            ],
        ];
    }

    private static function defaultProtocolConfigs(): array {
        return [
            'awg' => [
                'port' => 55424,
                'subnet_address' => '10.8.1.0',
                'subnet_cidr' => '24',
                'subnet_mask' => self::cidrToMask(24),
                'Jc' => 3,
                'Jmin' => 10,
                'Jmax' => 50,
                'S1' => random_int(50, 250),
                'S2' => random_int(50, 250),
                'H1' => random_int(100000, 2000000000),
                'H2' => random_int(100000, 2000000000),
                'H3' => random_int(100000, 2000000000),
                'H4' => random_int(100000, 2000000000),
            ],
            'wireguard' => [
                'port' => 51820,
                'subnet_address' => '10.8.1.0',
                'subnet_cidr' => '24',
                'subnet_mask' => self::cidrToMask(24),
            ],
            'openvpn' => [
                'port' => 1194,
                'transport_proto' => 'udp',
                'subnet_address' => '10.8.0.0',
                'subnet_cidr' => '24',
                'subnet_mask' => self::cidrToMask(24),
                'cipher' => 'AES-256-GCM',
                'hash' => 'SHA512',
                'ncp_disable' => false,
                'tls_auth' => true,
                'additional_client_config' => '',
                'additional_server_config' => '',
            ],
            'shadowsocks' => [
                'port' => 6789,
                'local_port' => 8585,
                'cipher' => 'chacha20-ietf-poly1305',
                'port_range' => '40000-40999',
            ],
            'cloak' => [
                'port' => 443,
                'site' => 'tile.openstreetmap.org',
            ],
            'ikev2' => [],
        ];
    }

    private static function buildContainersConfig(array $overrides = []): array {
        $defaults = self::defaultProtocolConfigs();

        foreach ($overrides as $protocol => $values) {
            if (isset($defaults[$protocol]) && is_array($values)) {
                $defaults[$protocol] = array_merge($defaults[$protocol], $values);
            }
        }

        $shadowsocksDefaults = $defaults['shadowsocks'];
        if (empty($shadowsocksDefaults['port_range'])) {
            $shadowsocksDefaults['port_range'] = '40000-40999';
        }

        $cloakShadowsocks = $shadowsocksDefaults;
        if (!empty($overrides['cloak_shadowsocks']) && is_array($overrides['cloak_shadowsocks'])) {
            $cloakShadowsocks = array_merge($cloakShadowsocks, $overrides['cloak_shadowsocks']);
        } else {
            $cloakShadowsocks['port_range'] = '41000-41999';
            if (isset($shadowsocksDefaults['port'])) {
                $cloakShadowsocks['port'] = (int)$shadowsocksDefaults['port'] + 1;
            }
        }
        if (empty($cloakShadowsocks['port_range'])) {
            $cloakShadowsocks['port_range'] = '41000-41999';
        }

        return [
            [
                'container' => self::containerDefinitions()['awg']['container'],
                'awg' => $defaults['awg'],
            ],
            [
                'container' => self::containerDefinitions()['wireguard']['container'],
                'wireguard' => $defaults['wireguard'],
            ],
            [
                'container' => self::containerDefinitions()['openvpn']['container'],
                'openvpn' => $defaults['openvpn'],
            ],
            [
                'container' => self::containerDefinitions()['shadowsocks']['container'],
                'openvpn' => array_merge($defaults['openvpn'], ['transport_proto' => 'tcp']),
                'shadowsocks' => $shadowsocksDefaults,
            ],
            [
                'container' => self::containerDefinitions()['cloak']['container'],
                'openvpn' => array_merge($defaults['openvpn'], ['transport_proto' => 'tcp']),
                'shadowsocks' => $cloakShadowsocks,
                'cloak' => $defaults['cloak'],
            ],
            [
                'container' => self::containerDefinitions()['ipsec']['container'],
                'ikev2' => $defaults['ikev2'],
            ],
        ];
    }

    private function getContainersConfig(): array {
        $containers = [];
        if (!empty($this->data['containers'])) {
            $decoded = json_decode($this->data['containers'], true);
            if (is_array($decoded)) {
                $containers = $decoded;
            }
        }
        return $containers;
    }

    private function saveContainersConfig(array $containers): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('UPDATE vpn_servers SET containers = ?, updated_at = NOW() WHERE id = ?');
        $stmt->execute([json_encode($containers), $this->serverId]);
        $this->data['containers'] = json_encode($containers);
    }

    public function updateProtocolOverrides(array $overrides): void {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $containers = $this->getContainersConfig();
        if (empty($containers)) {
            $containers = self::buildContainersConfig($overrides);
        } else {
            $containers = self::applyProtocolOverrides($containers, $overrides);
        }

        $containers = $this->ensureContainerDefaults($containers);
        $this->saveContainersConfig($containers);
    }

    private static function applyProtocolOverrides(array $containers, array $overrides): array {
        $openvpnOverrides = $overrides['openvpn'] ?? [];
        $openvpnPortOverrides = $openvpnOverrides;
        if (array_key_exists('transport_proto', $openvpnPortOverrides)) {
            unset($openvpnPortOverrides['transport_proto']);
        }

        foreach ($containers as &$container) {
            $name = $container['container'] ?? '';
            if ($name === 'amnezia-awg' && !empty($overrides['awg'])) {
                $container['awg'] = array_merge($container['awg'] ?? [], $overrides['awg']);
            } elseif ($name === 'amnezia-wireguard' && !empty($overrides['wireguard'])) {
                $container['wireguard'] = array_merge($container['wireguard'] ?? [], $overrides['wireguard']);
            } elseif ($name === 'amnezia-openvpn') {
                if ($openvpnOverrides) {
                    $container['openvpn'] = array_merge($container['openvpn'] ?? [], $openvpnOverrides);
                }
            } elseif ($name === 'amnezia-shadowsocks') {
                if ($openvpnPortOverrides) {
                    $container['openvpn'] = array_merge($container['openvpn'] ?? [], $openvpnPortOverrides);
                    $container['openvpn']['transport_proto'] = 'tcp';
                }
                if (!empty($overrides['shadowsocks'])) {
                    $container['shadowsocks'] = array_merge($container['shadowsocks'] ?? [], $overrides['shadowsocks']);
                }
            } elseif ($name === 'amnezia-openvpn-cloak') {
                if ($openvpnPortOverrides) {
                    $container['openvpn'] = array_merge($container['openvpn'] ?? [], $openvpnPortOverrides);
                    $container['openvpn']['transport_proto'] = 'tcp';
                }
                if (!empty($overrides['shadowsocks'])) {
                    $container['shadowsocks'] = array_merge($container['shadowsocks'] ?? [], $overrides['shadowsocks']);
                }
                if (!empty($overrides['cloak_shadowsocks'])) {
                    $container['shadowsocks'] = array_merge($container['shadowsocks'] ?? [], $overrides['cloak_shadowsocks']);
                }
                if (!empty($overrides['cloak'])) {
                    $container['cloak'] = array_merge($container['cloak'] ?? [], $overrides['cloak']);
                }
            }
        }
        unset($container);

        return $containers;
    }

    private function resolveServerIp(): string {
        $host = $this->data['host'] ?? '';
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }
        $resolved = gethostbyname($host);
        if ($resolved && $resolved !== $host) {
            return $resolved;
        }
        return $host;
    }

    private static function cidrToMask(int $cidr): string {
        $cidr = max(0, min(32, $cidr));
        $maskParts = [];
        for ($i = 0; $i < 4; $i++) {
            $bits = max(0, min(8, $cidr - ($i * 8)));
            $maskParts[] = $bits === 0 ? 0 : (256 - (1 << (8 - $bits)));
        }
        return implode('.', $maskParts);
    }

    private function readScript(string $relativePath): string {
        $path = self::SCRIPT_ROOT . '/' . ltrim($relativePath, '/');
        if (!file_exists($path)) {
            throw new Exception('Script not found: ' . $relativePath);
        }
        return file_get_contents($path) ?: '';
    }

    private function replaceVars(string $script, array $vars): string {
        return str_replace(array_keys($vars), array_values($vars), $script);
    }

    private function uploadFile(string $remotePath, string $content, bool $sudo = false): void {
        $b64 = base64_encode($content);
        $cmd = "echo '{$b64}' | base64 -d > " . escapeshellarg($remotePath);
        $this->executeCommand($cmd, $sudo);
    }

    private function uploadFileToContainer(string $containerName, string $path, string $content): void {
        $b64 = base64_encode($content);
        $cmd = "docker exec -i {$containerName} sh -c " . escapeshellarg("echo '{$b64}' | base64 -d > {$path}");
        $this->executeCommand($cmd, true);
    }

    private function runRemoteScript(string $script, bool $sudo = false): string {
        $b64 = base64_encode($script);
        $cmd = "echo '{$b64}' | base64 -d | sh";
        return $this->executeCommand($cmd, $sudo);
    }

    private function runContainerScript(string $containerName, string $script): string {
        $b64 = base64_encode($script);
        $cmd = "docker exec -i {$containerName} sh -c " . escapeshellarg("echo '{$b64}' | base64 -d | sh");
        return $this->executeCommand($cmd, true);
    }

    private function buildScriptVars(array $containerConfig): array {
        $openvpn = $containerConfig['openvpn'] ?? [];
        $cloak = $containerConfig['cloak'] ?? [];
        $shadowsocks = $containerConfig['shadowsocks'] ?? [];
        $wireguard = $containerConfig['wireguard'] ?? [];
        $awg = $containerConfig['awg'] ?? [];

        $vars = [
            '$REMOTE_HOST' => $this->data['host'] ?? '',
            '$CONTAINER_NAME' => $containerConfig['container'] ?? '',
            '$DOCKERFILE_FOLDER' => '/opt/amnezia/' . ($containerConfig['container'] ?? ''),
            '$SERVER_IP_ADDRESS' => $this->resolveServerIp(),
            '$PRIMARY_DNS' => self::DEFAULT_DNS1,
            '$SECONDARY_DNS' => self::DEFAULT_DNS2,
        ];

        $vars['$OPENVPN_SUBNET_IP'] = (string)($openvpn['subnet_address'] ?? '10.8.0.0');
        $vars['$OPENVPN_SUBNET_CIDR'] = (string)($openvpn['subnet_cidr'] ?? '24');
        $vars['$OPENVPN_SUBNET_MASK'] = (string)($openvpn['subnet_mask'] ?? '255.255.255.0');
        $vars['$OPENVPN_PORT'] = (string)($openvpn['port'] ?? 1194);
        $vars['$OPENVPN_TRANSPORT_PROTO'] = (string)($openvpn['transport_proto'] ?? 'udp');
        $vars['$OPENVPN_NCP_DISABLE'] = !empty($openvpn['ncp_disable']) ? 'ncp-disable' : '';
        $vars['$OPENVPN_CIPHER'] = (string)($openvpn['cipher'] ?? 'AES-256-GCM');
        $vars['$OPENVPN_HASH'] = (string)($openvpn['hash'] ?? 'SHA512');
        $vars['$OPENVPN_TLS_AUTH'] = (!isset($openvpn['tls_auth']) || $openvpn['tls_auth']) ? 'tls-auth /opt/amnezia/openvpn/ta.key 0' : '';
        $vars['$OPENVPN_ADDITIONAL_CLIENT_CONFIG'] = (string)($openvpn['additional_client_config'] ?? '');
        $vars['$OPENVPN_ADDITIONAL_SERVER_CONFIG'] = (string)($openvpn['additional_server_config'] ?? '');

        $vars['$SHADOWSOCKS_SERVER_PORT'] = (string)($shadowsocks['port'] ?? 6789);
        $vars['$SHADOWSOCKS_LOCAL_PORT'] = (string)($shadowsocks['local_port'] ?? 8585);
        $vars['$SHADOWSOCKS_CIPHER'] = (string)($shadowsocks['cipher'] ?? 'chacha20-ietf-poly1305');
        $vars['$SHADOWSOCKS_PORT_RANGE'] = (string)($shadowsocks['port_range'] ?? '');

        $vars['$CLOAK_SERVER_PORT'] = (string)($cloak['port'] ?? 443);
        $vars['$FAKE_WEB_SITE_ADDRESS'] = (string)($cloak['site'] ?? 'tile.openstreetmap.org');

        $vars['$WIREGUARD_SUBNET_IP'] = (string)($wireguard['subnet_address'] ?? '10.8.1.0');
        $vars['$WIREGUARD_SUBNET_CIDR'] = (string)($wireguard['subnet_cidr'] ?? '24');
        $vars['$WIREGUARD_SUBNET_MASK'] = (string)($wireguard['subnet_mask'] ?? '255.255.255.0');
        $vars['$WIREGUARD_SERVER_PORT'] = (string)($wireguard['port'] ?? 51820);

        $vars['$AWG_SERVER_PORT'] = (string)($awg['port'] ?? 55424);
        $vars['$JUNK_PACKET_COUNT'] = (string)($awg['Jc'] ?? 3);
        $vars['$JUNK_PACKET_MIN_SIZE'] = (string)($awg['Jmin'] ?? 10);
        $vars['$JUNK_PACKET_MAX_SIZE'] = (string)($awg['Jmax'] ?? 50);
        $vars['$INIT_PACKET_JUNK_SIZE'] = (string)($awg['S1'] ?? 15);
        $vars['$RESPONSE_PACKET_JUNK_SIZE'] = (string)($awg['S2'] ?? 18);
        $vars['$INIT_PACKET_MAGIC_HEADER'] = (string)($awg['H1'] ?? 1020325451);
        $vars['$RESPONSE_PACKET_MAGIC_HEADER'] = (string)($awg['H2'] ?? 3288052141);
        $vars['$UNDERLOAD_PACKET_MAGIC_HEADER'] = (string)($awg['H3'] ?? 1766607858);
        $vars['$TRANSPORT_PACKET_MAGIC_HEADER'] = (string)($awg['H4'] ?? 2528465083);

        $vars['$PRIMARY_SERVER_DNS'] = self::DEFAULT_DNS1;
        $vars['$SECONDARY_SERVER_DNS'] = self::DEFAULT_DNS2;

        return $vars;
    }

    private function ensureContainerFolder(string $containerName): void {
        $path = '/opt/amnezia/' . $containerName;
        $this->executeCommand("mkdir -p " . escapeshellarg($path), true);
    }

    private function stopAndRemoveContainer(string $containerName): void {
        $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rmi {$containerName} 2>/dev/null || true", true);
    }

    private function prepareHostNetwork(string $containerName): void {
        $script = $this->readScript('shared/prepare_host.sh');
        $vars = [
            '$DOCKERFILE_FOLDER' => '/opt/amnezia/' . $containerName,
        ];
        $this->runRemoteScript($this->replaceVars($script, $vars), true);
    }

    private function setupHostFirewall(): void {
        $script = $this->readScript('shared/setup_host_firewall.sh');
        $this->runRemoteScript($script, true);
    }

    private function deployContainer(array $containerConfig): void {
        $containerName = $containerConfig['container'] ?? '';
        if ($containerName === '') {
            throw new Exception('Missing container name');
        }

        $definitions = self::containerDefinitions();
        $scriptFolder = null;
        foreach ($definitions as $def) {
            if ($def['container'] === $containerName) {
                $scriptFolder = $def['scripts'];
                break;
            }
        }
        if ($scriptFolder === null) {
            throw new Exception('Unsupported container: ' . $containerName);
        }

        $vars = $this->buildScriptVars($containerConfig);

        $this->stopAndRemoveContainer($containerName);
        $this->prepareHostNetwork($containerName);
        $this->ensureContainerFolder($containerName);

        $dockerfile = $this->readScript($scriptFolder . '/Dockerfile');
        $this->uploadFile('/opt/amnezia/' . $containerName . '/Dockerfile', $dockerfile, true);

        $buildCmd = sprintf(
            'docker build --no-cache --pull -t %s /opt/amnezia/%s --build-arg SERVER_ARCH=$(uname -m)',
            $containerName,
            $containerName
        );
        $this->executeCommand($buildCmd, true);

        $runScript = $this->replaceVars($this->readScript($scriptFolder . '/run_container.sh'), $vars);
        $this->runRemoteScript($runScript, true);

        $configureScript = $this->replaceVars($this->readScript($scriptFolder . '/configure_container.sh'), $vars);
        $this->runContainerScript($containerName, $configureScript);

        $startScript = $this->replaceVars($this->readScript($scriptFolder . '/start.sh'), $vars);
        if (trim($startScript) !== '') {
            $this->uploadFileToContainer($containerName, '/opt/amnezia/start.sh', $startScript);
            $this->executeCommand("docker exec -d {$containerName} sh -c 'chmod a+x /opt/amnezia/start.sh && /opt/amnezia/start.sh'", true);
        }
    }

    private function listUsedPorts(string $proto): array {
        $proto = $proto === 'tcp' ? 'tcp' : 'udp';
        if (isset($this->cachedUsedPorts[$proto])) {
            return $this->cachedUsedPorts[$proto];
        }

        $proc = $proto;
        $output = $this->executeCommand("cat /proc/net/{$proc} /proc/net/{$proc}6 2>/dev/null || true", false);
        $ports = $this->parseProcNetPorts($output);
        $hasHeader = stripos($output, 'local_address') !== false;

        if (!$hasHeader) {
            $flag = $proto === 'tcp' ? '-ltnH' : '-lunH';
            $output = $this->executeCommand("ss {$flag} 2>/dev/null || true", false);
            $ports = $this->parseSsPorts($output);
        }

        $this->cachedUsedPorts[$proto] = $ports;
        return $ports;
    }

    private function parseProcNetPorts(string $output): array {
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

    private function parseSsPorts(string $output): array {
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

    private function findFreePort(string $proto, int $min = 30000, int $max = 50000): int {
        $used = $this->listUsedPorts($proto);
        for ($attempt = 0; $attempt < 30; $attempt++) {
            $candidate = random_int($min, $max);
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }
        for ($candidate = $min; $candidate <= $max; $candidate++) {
            if (!isset($used[$candidate])) {
                return $candidate;
            }
        }
        throw new Exception('Could not find free ' . $proto . ' port');
    }

    private function isPortFree(int $port, string $proto): bool {
        $used = $this->listUsedPorts($proto);
        return !isset($used[$port]);
    }

    private function ensureContainerPorts(array $containers): array {
        $used = [];
        foreach ($containers as &$container) {
            $name = $container['container'] ?? '';
            if ($name === 'amnezia-awg') {
                $container['awg']['port'] = $this->selectPort($container['awg']['port'] ?? null, 'udp', $used);
                $used[] = $container['awg']['port'];
            } elseif ($name === 'amnezia-wireguard') {
                $container['wireguard']['port'] = $this->selectPort($container['wireguard']['port'] ?? null, 'udp', $used);
                $used[] = $container['wireguard']['port'];
            } elseif ($name === 'amnezia-openvpn') {
                $proto = ($container['openvpn']['transport_proto'] ?? 'udp') === 'tcp' ? 'tcp' : 'udp';
                $container['openvpn']['port'] = $this->selectPort($container['openvpn']['port'] ?? null, $proto, $used);
                $used[] = $container['openvpn']['port'];
            } elseif ($name === 'amnezia-shadowsocks') {
                $container['shadowsocks']['port'] = $this->selectPort($container['shadowsocks']['port'] ?? null, 'tcp', $used);
                $used[] = $container['shadowsocks']['port'];
            } elseif ($name === 'amnezia-openvpn-cloak') {
                $container['shadowsocks']['port'] = $this->selectPort($container['shadowsocks']['port'] ?? null, 'tcp', $used, 6790);
                $used[] = $container['shadowsocks']['port'];
                $container['cloak']['port'] = $this->selectPort($container['cloak']['port'] ?? null, 'tcp', $used, 443);
                $used[] = $container['cloak']['port'];
            }
        }
        unset($container);
        return $containers;
    }

    private function ensureContainerDefaults(array $containers): array {
        $defaults = self::defaultProtocolConfigs();
        foreach ($containers as &$container) {
            $name = $container['container'] ?? '';
            if (in_array($name, ['amnezia-shadowsocks', 'amnezia-openvpn-cloak'], true)) {
                if (empty($container['shadowsocks']) || !is_array($container['shadowsocks'])) {
                    $container['shadowsocks'] = [];
                }
                if (empty($container['shadowsocks']['port'])) {
                    $container['shadowsocks']['port'] = $defaults['shadowsocks']['port'] ?? 6789;
                }
                if (empty($container['shadowsocks']['port_range'])) {
                    $container['shadowsocks']['port_range'] = $name === 'amnezia-openvpn-cloak'
                        ? '41000-41999'
                        : ($defaults['shadowsocks']['port_range'] ?? '40000-40999');
                }
            }
        }
        unset($container);
        return $containers;
    }

    private function selectPort(?int $desired, string $proto, array $used, int $fallback = 0): int {
        if ($desired && $desired > 0 && !in_array($desired, $used, true) && $this->isPortFree($desired, $proto)) {
            return $desired;
        }
        if ($fallback > 0 && !in_array($fallback, $used, true) && $this->isPortFree($fallback, $proto)) {
            return $fallback;
        }
        $port = $this->findFreePort($proto);
        while (in_array($port, $used, true)) {
            $port = $this->findFreePort($proto);
        }
        return $port;
    }
    
    /**
     * Create new VPN server in database
     */
    public static function create(array $data): int {
        $pdo = DB::conn();
        
        // Validate required fields
        $required = ['user_id', 'name', 'host', 'port', 'username', 'password'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("Field {$field} is required");
            }
        }
        
        $containers = $data['containers'] ?? self::buildContainersConfig($data['protocol_overrides'] ?? []);
        $defaultContainer = $data['default_container'] ?? 'amnezia-awg';

        $stmt = $pdo->prepare('
            INSERT INTO vpn_servers 
            (user_id, name, host, port, username, password, container_name, vpn_subnet, containers, default_container, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        
        $stmt->execute([
            $data['user_id'],
            $data['name'],
            $data['host'],
            $data['port'],
            $data['username'],
            $data['password'],
            $data['container_name'] ?? 'amnezia-awg',
            $data['vpn_subnet'] ?? '10.8.1.0/24',
            json_encode($containers),
            $defaultContainer,
            'deploying'
        ]);
        
        return (int)$pdo->lastInsertId();
    }
    
    /**
     * Deploy VPN server using amnezia_deploy_v2.php logic
     */
    public function deploy(): array {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }

        $containers = $this->getContainersConfig();
        if (empty($containers)) {
            return $this->deployLegacy();
        }

        return $this->deployMultiProtocol($containers);
    }

    private function deployLegacy(): array {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }
        
        $pdo = DB::conn();
        $errors = [];
        
        try {
            // Update status to deploying
            $pdo->prepare('UPDATE vpn_servers SET status = ? WHERE id = ?')
                ->execute(['deploying', $this->serverId]);
            
            // Test SSH connection
            if (!$this->testConnection()) {
                throw new Exception('SSH connection failed');
            }
            
            // Install Docker if needed
            $this->installDocker();
            
            // Create directories
            $this->executeCommand('mkdir -p /opt/amnezia/amnezia-awg', true);
            
            // Find free UDP port
            $vpnPort = $this->findFreeUdpPort();
            
            // Create Dockerfile
            $this->createDockerfile();
            
            // Create start script
            $this->createStartScript();
            
            // Build Docker image
            $this->buildDockerImage();
            
            // Run container
            $this->runContainer($vpnPort);
            
            // Initialize server config
            $keys = $this->initializeServerConfig($vpnPort);
            
            // Update database with deployment info
            $stmt = $pdo->prepare('
                UPDATE vpn_servers 
                SET vpn_port = ?, 
                    server_public_key = ?, 
                    preshared_key = ?, 
                    awg_params = ?,
                    status = ?,
                    deployed_at = NOW(),
                    error_message = NULL
                WHERE id = ?
            ');
            
            $stmt->execute([
                $vpnPort,
                $keys['public_key'],
                $keys['preshared_key'],
                json_encode($keys['awg_params']),
                'active',
                $this->serverId
            ]);
            
            // Reload data
            $this->load();
            
            return [
                'success' => true,
                'vpn_port' => $vpnPort,
                'public_key' => $keys['public_key']
            ];
            
        } catch (Exception $e) {
            // Update status to error
            $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?')
                ->execute(['error', $e->getMessage(), $this->serverId]);
            
            throw $e;
        }
    }

    private function deployMultiProtocol(array $containers): array {
        $pdo = DB::conn();

        try {
            $pdo->prepare('UPDATE vpn_servers SET status = ? WHERE id = ?')
                ->execute(['deploying', $this->serverId]);

            if (!$this->testConnection()) {
                throw new Exception('SSH connection failed');
            }

            $this->installDocker();
            $this->setupHostFirewall();

            $containers = $this->ensureContainerDefaults($containers);
            $containers = $this->ensureContainerPorts($containers);

            foreach ($containers as $containerConfig) {
                $this->deployContainer($containerConfig);
            }

            $awgContainer = $this->findContainerConfig($containers, 'amnezia-awg');
            if ($awgContainer) {
                $awgConfig = $awgContainer['awg'] ?? [];
                $awgPort = (int)($awgConfig['port'] ?? 0);

                $pubKey = trim($this->executeCommand('docker exec -i amnezia-awg cat /opt/amnezia/awg/wireguard_server_public_key.key', true));
                $psk = trim($this->executeCommand('docker exec -i amnezia-awg cat /opt/amnezia/awg/wireguard_psk.key', true));

                $stmt = $pdo->prepare('
                    UPDATE vpn_servers
                    SET vpn_port = ?,
                        server_public_key = ?,
                        preshared_key = ?,
                        awg_params = ?,
                        container_name = ?,
                        vpn_subnet = ?,
                        status = ?,
                        deployed_at = NOW(),
                        error_message = NULL
                    WHERE id = ?
                ');
                $stmt->execute([
                    $awgPort,
                    $pubKey,
                    $psk,
                    json_encode([
                        'Jc' => $awgConfig['Jc'] ?? null,
                        'Jmin' => $awgConfig['Jmin'] ?? null,
                        'Jmax' => $awgConfig['Jmax'] ?? null,
                        'S1' => $awgConfig['S1'] ?? null,
                        'S2' => $awgConfig['S2'] ?? null,
                        'H1' => $awgConfig['H1'] ?? null,
                        'H2' => $awgConfig['H2'] ?? null,
                        'H3' => $awgConfig['H3'] ?? null,
                        'H4' => $awgConfig['H4'] ?? null,
                    ]),
                    'amnezia-awg',
                    ($awgConfig['subnet_address'] ?? '10.8.1.0') . '/' . ($awgConfig['subnet_cidr'] ?? '24'),
                    'active',
                    $this->serverId
                ]);
            } else {
                $pdo->prepare('UPDATE vpn_servers SET status = ?, deployed_at = NOW(), error_message = NULL WHERE id = ?')
                    ->execute(['active', $this->serverId]);
            }

            $this->saveContainersConfig($containers);
            $this->load();

            return [
                'success' => true,
                'vpn_port' => $this->data['vpn_port'] ?? null,
                'public_key' => $this->data['server_public_key'] ?? null
            ];
        } catch (Exception $e) {
            $pdo->prepare('UPDATE vpn_servers SET status = ?, error_message = ? WHERE id = ?')
                ->execute(['error', $e->getMessage(), $this->serverId]);
            throw $e;
        }
    }

    private function findContainerConfig(array $containers, string $name): ?array {
        foreach ($containers as $container) {
            if (($container['container'] ?? '') === $name) {
                return $container;
            }
        }
        return null;
    }
    
    /**
     * Test SSH connection to server
     */
    private function testConnection(): bool {
        $testCommand = sprintf(
            "sshpass -p '%s' ssh -p %d -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10 %s@%s 'echo test' 2>/dev/null",
            $this->data['password'],
            $this->data['port'],
            $this->data['username'],
            $this->data['host']
        );
        
        $result = shell_exec($testCommand);
        return trim($result) === 'test';
    }
    
    /**
     * Execute command on remote server
     */
    private function executeCommand(string $command, bool $sudo = false): string {
        if ($sudo && strtolower($this->data['username']) !== 'root') {
            $command = "echo '{$this->data['password']}' | sudo -S " . $command;
        }
        
        $escapedCommand = escapeshellarg($command);
        $sshCommand = sprintf(
            "sshpass -p '%s' ssh -p %d -q -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no %s@%s %s 2>&1",
            $this->data['password'],
            $this->data['port'],
            $this->data['username'],
            $this->data['host'],
            $escapedCommand
        );
        
        return shell_exec($sshCommand) ?? '';
    }
    
    /**
     * Install Docker on remote server
     */
    private function installDocker(): void {
        $dockerVersion = $this->executeCommand('docker --version');
        if (stripos($dockerVersion, 'version') !== false) {
            return; // Docker already installed
        }
        
        $this->executeCommand('curl -fsSL https://get.docker.com | sh', true);
        $this->executeCommand('systemctl enable --now docker', true);
    }
    
    /**
     * Find free UDP port on remote server
     */
    private function findFreeUdpPort(): int {
        return $this->findFreePort('udp', 30000, 65000);
    }
    
    /**
     * Create Dockerfile on remote server
     */
    private function createDockerfile(): void {
        $dockerfile = <<<'DOCKERFILE'
FROM amneziavpn/amnezia-wg:latest

LABEL maintainer="AmneziaVPN"

RUN apk add --no-cache bash curl dumb-init
RUN apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia
RUN echo -e "#!/bin/bash\ntail -f /dev/null" > /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
CMD [ "" ]
DOCKERFILE;
        
        $escaped = addslashes(trim($dockerfile));
        $this->executeCommand("echo \"{$escaped}\" > /opt/amnezia/amnezia-awg/Dockerfile", true);
    }
    
    /**
     * Create start script on remote server
     */
    private function createStartScript(): void {
        $script = <<<'BASH'
#!/bin/bash

echo "Container startup"

# Wait for config if not exists yet
for i in {1..30}; do
    if [ -f /opt/amnezia/awg/wg0.conf ]; then
        break
    fi
    sleep 1
done

# Kill daemons in case of restart
wg-quick down /opt/amnezia/awg/wg0.conf 2>/dev/null || true

# Start daemons if configured
if [ -f /opt/amnezia/awg/wg0.conf ]; then
    wg-quick up /opt/amnezia/awg/wg0.conf
    echo "WireGuard started"
else
    echo "No wg0.conf found, skipping WireGuard startup"
fi

# Allow traffic on the TUN interface
iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i wg0 -o eth1 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth1 -j MASQUERADE 2>/dev/null || true

tail -f /dev/null
BASH;
        
        $escaped = addslashes(trim($script));
        $this->executeCommand("echo \"{$escaped}\" > /opt/amnezia/amnezia-awg/start.sh", true);
        $this->executeCommand("chmod +x /opt/amnezia/amnezia-awg/start.sh", true);
    }
    
    /**
     * Build Docker image
     */
    private function buildDockerImage(): void {
        $containerName = $this->data['container_name'];
        
        // Cleanup old container/image
        $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
        $this->executeCommand("docker rmi {$containerName} 2>/dev/null || true", true);
        
        // Build new image
        $buildCmd = sprintf(
            'docker build --no-cache --pull -t %s /opt/amnezia/amnezia-awg',
            $containerName
        );
        $this->executeCommand($buildCmd, true);
    }
    
    /**
     * Run Docker container
     */
    private function runContainer(int $vpnPort): void {
        $containerName = $this->data['container_name'];
        
        $runCmd = sprintf(
            'docker run -d --log-driver none --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p %d:%d/udp -v /lib/modules:/lib/modules --name %s %s',
            $vpnPort,
            $vpnPort,
            $containerName,
            $containerName
        );
        
        $this->executeCommand($runCmd, true);
        sleep(3); // Wait for container to start
    }
    
    /**
     * Initialize server configuration with AWG parameters
     */
    private function initializeServerConfig(int $vpnPort): array {
        $containerName = $this->data['container_name'];
        
        // Create directory
        $this->executeCommand("docker exec -i {$containerName} mkdir -p /opt/amnezia/awg", true);
        
        // Generate keys
        $this->executeCommand("docker exec -i {$containerName} sh -c 'cd /opt/amnezia/awg && umask 077 && wg genkey | tee server_private.key | wg pubkey > wireguard_server_public_key.key'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'cd /opt/amnezia/awg && wg genpsk > wireguard_psk.key'", true);
        $this->executeCommand("docker exec -i {$containerName} chmod 600 /opt/amnezia/awg/server_private.key /opt/amnezia/awg/wireguard_psk.key /opt/amnezia/awg/wireguard_server_public_key.key", true);
        
        // Get keys
        $privKey = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/server_private.key", true));
        $pubKey = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/wireguard_server_public_key.key", true));
        $psk = trim($this->executeCommand("docker exec -i {$containerName} cat /opt/amnezia/awg/wireguard_psk.key", true));
        
        // Generate AWG parameters
        $awgParams = [
            'Jc' => 3,
            'Jmin' => 10,
            'Jmax' => 50,
            'S1' => rand(50, 250),
            'S2' => rand(50, 250),
            'H1' => rand(100000, 2000000000),
            'H2' => rand(100000, 2000000000),
            'H3' => rand(100000, 2000000000),
            'H4' => rand(100000, 2000000000)
        ];
        
        // Create wg0.conf
        $wgConfig = "[Interface]\n";
        $wgConfig .= "PrivateKey = {$privKey}\n";
        $wgConfig .= "Address = {$this->data['vpn_subnet']}\n";
        $wgConfig .= "ListenPort = {$vpnPort}\n";
        foreach ($awgParams as $key => $value) {
            $wgConfig .= "{$key} = {$value}\n";
        }
        $wgConfig .= "\n";
        
        $escaped = addslashes($wgConfig);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'echo \"{$escaped}\" > /opt/amnezia/awg/wg0.conf'", true);
        $this->executeCommand("docker exec -i {$containerName} chmod 600 /opt/amnezia/awg/wg0.conf", true);
        
        // Create clientsTable
        $this->executeCommand("docker exec -i {$containerName} sh -c 'echo \"[]\" > /opt/amnezia/awg/clientsTable'", true);
        
        // Start WireGuard
        $this->executeCommand("docker exec -i {$containerName} wg-quick up /opt/amnezia/awg/wg0.conf 2>&1", true);
        
        // Apply firewall rules
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A OUTPUT -o wg0 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT 2>/dev/null || true'", true);
        $this->executeCommand("docker exec -i {$containerName} sh -c 'iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true'", true);
        
        sleep(2);
        
        return [
            'public_key' => $pubKey,
            'preshared_key' => $psk,
            'awg_params' => $awgParams
        ];
    }
    
    /**
     * Get server status from database
     */
    public function getStatus(): string {
        return $this->data['status'] ?? 'unknown';
    }
    
    /**
     * Get all servers for a user
     */
    public static function listByUser(int $userId): array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    /**
     * Get server by ID
     */
    public static function getById(int $serverId): ?array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM vpn_servers WHERE id = ?');
        $stmt->execute([$serverId]);
        $server = $stmt->fetch();
        return $server ?: null;
    }
    
    /**
     * Get all servers (admin only)
     */
    public static function listAll(): array {
        $pdo = DB::conn();
        $stmt = $pdo->query('SELECT s.*, u.email as user_email FROM vpn_servers s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC');
        return $stmt->fetchAll();
    }
    
    /**
     * Delete server
     */
    public function delete(): bool {
        // Stop and remove container
        try {
            $containers = $this->getContainersConfig();
            if ($containers) {
                foreach ($containers as $container) {
                    $name = $container['container'] ?? null;
                    if (!$name) {
                        continue;
                    }
                    $this->executeCommand("docker stop {$name} 2>/dev/null || true", true);
                    $this->executeCommand("docker rm -fv {$name} 2>/dev/null || true", true);
                    $this->executeCommand("rm -rf /opt/amnezia/{$name}", true);
                }
            } else {
                $containerName = $this->data['container_name'];
                $this->executeCommand("docker stop {$containerName} 2>/dev/null || true", true);
                $this->executeCommand("docker rm -fv {$containerName} 2>/dev/null || true", true);
                $this->executeCommand("rm -rf /opt/amnezia/amnezia-awg", true);
            }
        } catch (Exception $e) {
            // Ignore errors during cleanup
        }
        
        // Delete from database
        $pdo = DB::conn();
        $stmt = $pdo->prepare('DELETE FROM vpn_servers WHERE id = ?');
        return $stmt->execute([$this->serverId]);
    }
    
    /**
     * Get server data
     */
    public function getData(): ?array {
        return $this->data;
    }
    
    /**
     * Create backup of server configuration and all clients
     * 
     * @param int $userId User who creates the backup
     * @param string $backupType Type: 'manual' or 'automatic'
     * @return int Backup ID
     */
    public function createBackup(int $userId, string $backupType = 'manual'): int {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }
        
        $pdo = DB::conn();
        $backupName = 'backup_' . $this->serverId . '_' . date('Y-m-d_His') . '.json';
        $backupDir = '/var/www/html/backups';
        $backupPath = $backupDir . '/' . $backupName;
        
        // Create backups directory if not exists
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0755, true);
        }
        
        try {
            // Get all clients for this server
            $stmt = $pdo->prepare('
                SELECT id, name, client_ip, public_key, private_key, preshared_key, 
                       config, protocols, client_ips, status, expires_at, created_at
                FROM vpn_clients 
                WHERE server_id = ?
            ');
            $stmt->execute([$this->serverId]);
            $clients = $stmt->fetchAll();
            
            // Prepare backup data
            $backupData = [
                'server' => [
                    'name' => $this->data['name'],
                    'host' => $this->data['host'],
                    'port' => $this->data['port'],
                    'vpn_port' => $this->data['vpn_port'],
                    'vpn_subnet' => $this->data['vpn_subnet'],
                    'container_name' => $this->data['container_name'],
                    'server_public_key' => $this->data['server_public_key'],
                    'preshared_key' => $this->data['preshared_key'],
                    'awg_params' => $this->data['awg_params'],
                    'containers' => $this->data['containers'] ?? null,
                    'default_container' => $this->data['default_container'] ?? null,
                ],
                'clients' => $clients,
                'backup_date' => date('Y-m-d H:i:s'),
                'version' => '1.0'
            ];
            
            // Write backup to file
            $json = json_encode($backupData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            file_put_contents($backupPath, $json);
            
            $backupSize = filesize($backupPath);
            
            // Insert backup record
            $stmt = $pdo->prepare('
                INSERT INTO server_backups 
                (server_id, backup_name, backup_path, backup_size, clients_count, backup_type, status, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ');
            
            $stmt->execute([
                $this->serverId,
                $backupName,
                $backupPath,
                $backupSize,
                count($clients),
                $backupType,
                'completed',
                $userId
            ]);
            
            return (int)$pdo->lastInsertId();
            
        } catch (Exception $e) {
            // Mark backup as failed
            if (isset($stmt)) {
                $stmt = $pdo->prepare('
                    INSERT INTO server_backups 
                    (server_id, backup_name, backup_path, backup_type, status, error_message, created_by) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ');
                
                $stmt->execute([
                    $this->serverId,
                    $backupName,
                    $backupPath,
                    $backupType,
                    'failed',
                    $e->getMessage(),
                    $userId
                ]);
            }
            
            throw $e;
        }
    }
    
    /**
     * List all backups for this server
     * 
     * @return array List of backups
     */
    public function listBackups(): array {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }
        
        $pdo = DB::conn();
        $stmt = $pdo->prepare('
            SELECT b.*, u.name as created_by_name, u.email as created_by_email
            FROM server_backups b
            LEFT JOIN users u ON b.created_by = u.id
            WHERE b.server_id = ?
            ORDER BY b.created_at DESC
        ');
        $stmt->execute([$this->serverId]);
        return $stmt->fetchAll();
    }
    
    /**
     * Restore server from backup
     * Note: This only restores client configurations to database
     * Server must already be deployed
     * 
     * @param int $backupId Backup ID
     * @return array Restoration results
     */
    public function restoreBackup(int $backupId): array {
        if (!$this->data) {
            throw new Exception('Server not loaded');
        }
        
        if ($this->data['status'] !== 'active') {
            throw new Exception('Server must be active to restore backup');
        }
        
        $pdo = DB::conn();
        
        // Get backup record
        $stmt = $pdo->prepare('SELECT * FROM server_backups WHERE id = ? AND server_id = ?');
        $stmt->execute([$backupId, $this->serverId]);
        $backup = $stmt->fetch();
        
        if (!$backup) {
            throw new Exception('Backup not found');
        }
        
        if (!file_exists($backup['backup_path'])) {
            throw new Exception('Backup file not found');
        }
        
        // Read backup data
        $backupData = json_decode(file_get_contents($backup['backup_path']), true);
        
        if (!$backupData || !isset($backupData['clients'])) {
            throw new Exception('Invalid backup format');
        }
        
        $restored = 0;
        $failed = 0;
        $errors = [];
        
        foreach ($backupData['clients'] as $clientData) {
            try {
                // Check if client already exists by IP
                $stmt = $pdo->prepare('SELECT id FROM vpn_clients WHERE server_id = ? AND client_ip = ?');
                $stmt->execute([$this->serverId, $clientData['client_ip']]);
                $existing = $stmt->fetch();
                
                if ($existing) {
                    $errors[] = "Client {$clientData['name']} already exists";
                    $failed++;
                    continue;
                }
                
                // Insert client
                $stmt = $pdo->prepare('
                    INSERT INTO vpn_clients 
                    (server_id, user_id, name, client_ip, client_ips, public_key, private_key, preshared_key, 
                     config, protocols, status, expires_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ');
                
                $stmt->execute([
                    $this->serverId,
                    $this->data['user_id'],
                    $clientData['name'],
                    $clientData['client_ip'],
                    $clientData['client_ips'] ?? null,
                    $clientData['public_key'],
                    $clientData['private_key'],
                    $clientData['preshared_key'],
                    $clientData['config'],
                    $clientData['protocols'] ?? null,
                    'disabled', // Restore as disabled for safety
                    $clientData['expires_at']
                ]);
                
                // Add client to server container
                VpnClient::addClientToServer($this->data, $clientData['public_key'], $clientData['client_ip']);
                
                $restored++;
                
            } catch (Exception $e) {
                $failed++;
                $errors[] = "Failed to restore {$clientData['name']}: " . $e->getMessage();
            }
        }
        
        return [
            'success' => true, // Always success if process completed
            'restored' => $restored,
            'failed' => $failed,
            'total' => count($backupData['clients']),
            'errors' => $errors,
            'message' => $restored > 0 ? "Restored $restored clients" : "No clients restored"
        ];
    }
    
    /**
     * Delete backup
     * 
     * @param int $backupId Backup ID
     * @return bool Success
     */
    public static function deleteBackup(int $backupId): bool {
        $pdo = DB::conn();
        
        // Get backup path
        $stmt = $pdo->prepare('SELECT backup_path FROM server_backups WHERE id = ?');
        $stmt->execute([$backupId]);
        $backup = $stmt->fetch();
        
        if (!$backup) {
            return false;
        }
        
        // Delete file
        if (file_exists($backup['backup_path'])) {
            unlink($backup['backup_path']);
        }
        
        // Delete record
        $stmt = $pdo->prepare('DELETE FROM server_backups WHERE id = ?');
        return $stmt->execute([$backupId]);
    }
    
    /**
     * Get backup by ID
     * 
     * @param int $backupId Backup ID
     * @return array|null Backup data
     */
    public static function getBackup(int $backupId): ?array {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT * FROM server_backups WHERE id = ?');
        $stmt->execute([$backupId]);
        return $stmt->fetch() ?: null;
    }
}
