-- Migration: Add protocol UI translations
-- Date: 2025-11-15

INSERT IGNORE INTO translations (locale, category, key_name, translation) VALUES
-- English
('en', 'protocols', 'protocol', 'Protocol'),
('en', 'protocols', 'port_range', 'Port range'),
('en', 'protocols', 'port_range_hint', 'Used for per-client Shadowsocks ports.'),

-- Russian
('ru', 'protocols', 'protocol', 'Протокол'),
('ru', 'protocols', 'port_range', 'Диапазон портов'),
('ru', 'protocols', 'port_range_hint', 'Используется для портов Shadowsocks для каждого клиента.'),

-- Spanish
('es', 'protocols', 'protocol', 'Protocolo'),
('es', 'protocols', 'port_range', 'Rango de puertos'),
('es', 'protocols', 'port_range_hint', 'Se usa para puertos Shadowsocks por cliente.'),

-- German
('de', 'protocols', 'protocol', 'Protokoll'),
('de', 'protocols', 'port_range', 'Portbereich'),
('de', 'protocols', 'port_range_hint', 'Wird für Shadowsocks-Ports pro Client verwendet.'),

-- French
('fr', 'protocols', 'protocol', 'Protocole'),
('fr', 'protocols', 'port_range', 'Plage de ports'),
('fr', 'protocols', 'port_range_hint', 'Utilisé pour les ports Shadowsocks par client.'),

-- Chinese
('zh', 'protocols', 'protocol', '协议'),
('zh', 'protocols', 'port_range', '端口范围'),
('zh', 'protocols', 'port_range_hint', '用于每个客户端的 Shadowsocks 端口。');
