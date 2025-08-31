--liquibase formatted sql

--changeset zomor-pgcrypto:0-1
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

--changeset zomor-permissions:1
CREATE TABLE IF NOT EXISTS permissions
(
    id         UUID PRIMARY KEY,
    name       VARCHAR(120) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

--changeset zomor-roles:0-1
CREATE TABLE IF NOT EXISTS roles
(
    id         UUID PRIMARY KEY,
    name       VARCHAR(80) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

--changeset zomor-role_permissions:0-1
CREATE TABLE IF NOT EXISTS role_permissions
(
    id            UUID PRIMARY KEY,
    role_id       UUID NOT NULL,
    permission_id UUID NOT NULL,
    CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT fk_rp_perm FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

--changeset zomor-users:0-1
CREATE TABLE IF NOT EXISTS users
(
    id         UUID PRIMARY KEY,
    email      VARCHAR(255) NOT NULL,
    username   varchar(32),
    password   VARCHAR(255) NOT NULL,
    enabled    BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    CONSTRAINT uq_user_email UNIQUE (email),
    CONSTRAINT uq_user_username UNIQUE (username)
);

--changeset zomor-user_roles:0-1
CREATE TABLE IF NOT EXISTS user_roles
(
    id      UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

--changeset zomor-user_roles_generalmodel:0-1
CREATE OR REPLACE VIEW user_roles_generalmodel
AS
SELECT user_roles.id,
       users.username,
       users.email,
       roles.name AS role_name
FROM users
         JOIN user_roles ON users.id = user_roles.user_id
         JOIN roles ON user_roles.role_id = roles.id;

--changeset zomor-user_roles_permissions_generalmodel:0-1
CREATE OR REPLACE VIEW user_roles_permissions_generalmodel
AS
SELECT role_permissions.id,
       users.username,
       users.email,
       users.enabled,
       roles.name       AS role_name,
       permissions.name AS permission_name
FROM users
         JOIN user_roles ON users.id = user_roles.user_id
         JOIN roles ON user_roles.role_id = roles.id
         JOIN role_permissions ON role_permissions.role_id = roles.id
         JOIN permissions ON role_permissions.permission_id = permissions.id
;

