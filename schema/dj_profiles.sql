-- Apply to PREVIEW D1 only before enabling DJ profiles.
CREATE TABLE IF NOT EXISTS dj_profiles (
 user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 dj_name TEXT NOT NULL DEFAULT '',
 bio TEXT NOT NULL DEFAULT '',
 photo_url TEXT NOT NULL DEFAULT '',
 social_url TEXT NOT NULL DEFAULT '',
 updated_at INTEGER NOT NULL
);
