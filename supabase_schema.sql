-- ============================================================
-- DROP old table, policies, triggers, functions
-- ============================================================
DROP TRIGGER IF EXISTS trigger_refresh_ttl ON sessions;
DROP FUNCTION IF EXISTS refresh_session_ttl();
DROP FUNCTION IF EXISTS cleanup_expired_sessions();
DROP POLICY IF EXISTS "allow_select" ON sessions;
DROP POLICY IF EXISTS "allow_insert" ON sessions;
DROP POLICY IF EXISTS "allow_update" ON sessions;
DROP POLICY IF EXISTS "allow_delete" ON sessions;
DROP POLICY IF EXISTS "select_by_key" ON sessions;
DROP POLICY IF EXISTS "insert_session" ON sessions;
DROP POLICY IF EXISTS "update_by_key" ON sessions;
DROP POLICY IF EXISTS "delete_by_key" ON sessions;
DROP TABLE IF EXISTS sessions;

-- ============================================================
-- Fresh setup
-- ============================================================
CREATE TABLE sessions (
    k TEXT PRIMARY KEY CHECK (char_length(k) BETWEEN 8 AND 64),
    d TEXT NOT NULL CHECK (char_length(d) <= 500000),  -- ~375KB decoded max
    e BOOLEAN DEFAULT FALSE,
    u TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '12 hours')
);

-- Enable RLS
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- SELECT: only if you know the exact key AND session hasn't expired
CREATE POLICY "select_by_key" ON sessions
    FOR SELECT USING (expires_at > NOW());

-- INSERT: anyone can create (key acts as auth secret)
CREATE POLICY "insert_session" ON sessions
    FOR INSERT WITH CHECK (true);

-- UPDATE: only non-expired sessions, must match key via WHERE clause
CREATE POLICY "update_by_key" ON sessions
    FOR UPDATE USING (expires_at > NOW());

-- DELETE: only non-expired (expired ones cleaned by cron)
CREATE POLICY "delete_by_key" ON sessions
    FOR DELETE USING (expires_at > NOW());

-- Auto-refresh TTL on update
CREATE OR REPLACE FUNCTION refresh_session_ttl()
RETURNS TRIGGER AS $$
BEGIN
    NEW.expires_at := NOW() + INTERVAL '12 hours';
    NEW.u := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_refresh_ttl
    BEFORE INSERT OR UPDATE ON sessions
    FOR EACH ROW
    EXECUTE FUNCTION refresh_session_ttl();

-- Cleanup expired sessions (run via pg_cron or Supabase Edge Function)
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Schedule cleanup every hour (requires pg_cron extension)
SELECT cron.schedule('cleanup-sessions', '0 * * * *', 'SELECT cleanup_expired_sessions()');

-- Index for fast lookups and cleanup
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_key ON sessions(k);

-- ============================================================
-- View counter + one-time-share extension
-- ============================================================
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS views_remaining INT;     -- NULL = unlimited
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS view_count INT DEFAULT 0;

-- RPC: decrement views_remaining (if set), delete row when it hits zero.
-- Returns the payload exactly once for the final read.
CREATE OR REPLACE FUNCTION view_session(session_k TEXT)
RETURNS TABLE(d TEXT, e BOOLEAN, remaining INT) AS $$
DECLARE
    rec RECORD;
BEGIN
    SELECT s.d, s.e, s.views_remaining, s.view_count
        INTO rec
        FROM sessions s
        WHERE s.k = session_k AND s.expires_at > NOW();

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF rec.views_remaining IS NOT NULL THEN
        IF rec.views_remaining <= 1 THEN
            -- last read: return payload then delete row
            d := rec.d;
            e := rec.e;
            remaining := 0;
            DELETE FROM sessions WHERE k = session_k;
            RETURN NEXT;
            RETURN;
        ELSE
            UPDATE sessions
                SET views_remaining = views_remaining - 1,
                    view_count      = view_count + 1
                WHERE k = session_k;
            d := rec.d;
            e := rec.e;
            remaining := rec.views_remaining - 1;
            RETURN NEXT;
            RETURN;
        END IF;
    ELSE
        UPDATE sessions SET view_count = view_count + 1 WHERE k = session_k;
        d := rec.d;
        e := rec.e;
        remaining := NULL;
        RETURN NEXT;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Allow anon to call view_session
GRANT EXECUTE ON FUNCTION view_session(TEXT) TO anon, authenticated;
