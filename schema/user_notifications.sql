-- Preview D1 only. In-app notification inbox (not Web Push subscriptions).
CREATE TABLE IF NOT EXISTS user_notifications (
 id TEXT PRIMARY KEY NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 station_id TEXT REFERENCES stations(id) ON DELETE CASCADE,
 kind TEXT NOT NULL,
 title TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 read_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_user_notifications_inbox ON user_notifications(user_id,created_at DESC);
