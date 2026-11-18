-- Apply only to preview D1, after chat_messages.sql.
CREATE TABLE IF NOT EXISTS chat_message_reactions (
 message_id TEXT NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 emoji TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(message_id,user_id,emoji)
);
CREATE TABLE IF NOT EXISTS chat_message_pins (
 message_id TEXT PRIMARY KEY REFERENCES chat_messages(id) ON DELETE CASCADE,
 pinned_by TEXT NOT NULL REFERENCES users(id),
 pinned_at INTEGER NOT NULL
);
