-- Add multi-protocol support (containers and per-client protocol configs)

ALTER TABLE vpn_servers
ADD COLUMN containers JSON NULL COMMENT 'Amnezia container configs (protocol ports/settings)' AFTER awg_params,
ADD COLUMN default_container VARCHAR(100) NULL COMMENT 'Default container name for clients' AFTER containers;

ALTER TABLE vpn_clients
ADD COLUMN protocols JSON NULL COMMENT 'Per-protocol client configs (last_config data)' AFTER config,
ADD COLUMN client_ips JSON NULL COMMENT 'Per-protocol client IPs' AFTER client_ip;
