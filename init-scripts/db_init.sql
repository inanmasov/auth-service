DROP TABLE IF EXISTS user_tokens;

CREATE TABLE user_tokens (
    user_id TEXT NOT NULL PRIMARY KEY,
    token TEXT NOT NULL UNIQUE
);