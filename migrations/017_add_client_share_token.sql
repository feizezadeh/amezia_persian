-- Add share token for public client pages

ALTER TABLE vpn_clients
ADD COLUMN share_token VARCHAR(64) NULL AFTER qr_code;

CREATE UNIQUE INDEX idx_vpn_clients_share_token ON vpn_clients (share_token);
