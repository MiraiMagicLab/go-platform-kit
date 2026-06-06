-- Backfill: create one session row per distinct (user_id, session_id) from existing refresh_tokens.
-- This is idempotent and safe to run multiple times.
INSERT INTO sessions (id, user_id, device_name, ip_address, user_agent, created_at, last_seen_at, revoked_at)
SELECT DISTINCT ON (rt.user_id, rt.session_id)
       rt.session_id,
       rt.user_id,
       NULL,
       rt.ip_address,
       rt.user_agent,
       r2.first_created,
       rt.last_used_at,
       NULL
FROM refresh_tokens rt
JOIN (
    SELECT user_id, session_id, MIN(created_at) AS first_created
    FROM refresh_tokens
    GROUP BY user_id, session_id
) r2 ON r2.user_id = rt.user_id AND r2.session_id = rt.session_id
WHERE rt.session_id IS NOT NULL
ON CONFLICT (id) DO NOTHING;
