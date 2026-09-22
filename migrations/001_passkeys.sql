-- Passkey credential storage for WebAuthn authentication.
--
-- One row per enrolled credential. `passkey` holds the serialised
-- `webauthn_rs::Passkey` (credential public key + sign counter) as JSONB, which
-- is exactly the shape `auth::webauthn::PasskeyRecord` carries. A Postgres
-- `PasskeyStore` implementation maps directly onto this table:
--
--   save_passkey    -> INSERT ... ON CONFLICT (user_id, cred_id) DO UPDATE
--   get_passkeys    -> SELECT passkey FROM passkeys WHERE user_id = $1
--   update_passkey  -> UPDATE passkeys SET passkey = $3, last_used_at = NOW()
--                      WHERE user_id = $1 AND cred_id = $2
--   delete_passkey  -> DELETE FROM passkeys WHERE user_id = $1 AND cred_id = $2
--
-- Challenge state (PasskeyRegistration / PasskeyAuthentication) is short-lived
-- and single-use: it belongs in Redis or in-memory, never in this table.

CREATE TABLE IF NOT EXISTS passkeys (
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cred_id      TEXT         NOT NULL,
    passkey      JSONB        NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, cred_id)
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys (user_id);
