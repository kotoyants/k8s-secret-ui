-- +goose Up
CREATE TYPE role_permission AS ENUM ('read', 'read_write');

CREATE TABLE users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE CHECK (email = lower(email) AND email <> ''),
    name          TEXT        NOT NULL DEFAULT '',
    avatar_url    TEXT        NOT NULL DEFAULT '',
    disabled      BOOLEAN     NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE roles (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT            NOT NULL UNIQUE CHECK (name <> ''),
    permission role_permission NOT NULL DEFAULT 'read',
    builtin    BOOLEAN         NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE TABLE role_tags (
    role_id BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    tag     TEXT   NOT NULL CHECK (tag ~ '^[a-z0-9_-]{1,64}$'),
    PRIMARY KEY (role_id, tag)
);
CREATE INDEX role_tags_tag_idx ON role_tags (tag);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_roles_role_id_idx ON user_roles (role_id);

CREATE TABLE secrets (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider   TEXT        NOT NULL CHECK (provider <> ''),
    locator    JSONB       NOT NULL CHECK (jsonb_typeof(locator) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    UNIQUE (provider, locator)
);

CREATE TABLE secret_tags (
    secret_id BIGINT NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    tag       TEXT   NOT NULL CHECK (tag ~ '^[a-z0-9_-]{1,64}$'),
    PRIMARY KEY (secret_id, tag)
);
CREATE INDEX secret_tags_tag_idx ON secret_tags (tag);

INSERT INTO roles (name, permission, builtin) VALUES
    ('admin', 'read_write', true),
    ('default', 'read', true);

-- +goose Down
DROP TABLE secret_tags;
DROP TABLE secrets;
DROP TABLE user_roles;
DROP TABLE role_tags;
DROP TABLE roles;
DROP TABLE users;
DROP TYPE role_permission;
