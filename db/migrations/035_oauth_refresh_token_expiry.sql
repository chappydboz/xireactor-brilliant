-- 035_oauth_refresh_token_expiry.sql
-- Explicit, non-renewable absolute lifetime for OAuth refresh tokens.
--
-- New tokens receive expires_at = issuance time + REFRESH_TOKEN_EXPIRY_SECONDS
-- (365 days by default). Rotations retain the original deadline. Existing rows
-- receive a one-time one-year grace period from this migration; there is no
-- blanket revocation, so valid in-flight Claude connections remain usable.

BEGIN;

ALTER TABLE oauth_refresh_tokens
    ADD COLUMN IF NOT EXISTS expires_at BIGINT;

UPDATE oauth_refresh_tokens
SET expires_at = extract(epoch from now())::BIGINT + 31536000
WHERE expires_at IS NULL;

ALTER TABLE oauth_refresh_tokens
    ALTER COLUMN expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires
    ON oauth_refresh_tokens (expires_at);

COMMIT;
