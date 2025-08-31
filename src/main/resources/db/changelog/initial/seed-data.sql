--liquibase formatted sql

--changeset zomor-permissions:1-1
INSERT INTO permissions (id, name, created_at)
VALUES (gen_random_uuid(), 'user.read', now()),
       (gen_random_uuid(), 'user.write', now()),
       (gen_random_uuid(), 'role.read', now()),
       (gen_random_uuid(), 'role.write', now());

--changeset zomor-roles:1-1
INSERT INTO roles (id, name, created_at)
VALUES (gen_random_uuid(), 'ROLE_ADMIN', now()),
       (gen_random_uuid(), 'ROLE_USER', now());

--changeset zomor-role_permissions:1-1
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(), r.id, p.id
FROM roles r
         JOIN permissions p ON p.name IN ('user.read', 'user.write', 'role.read', 'role.write')
WHERE r.name = 'ROLE_ADMIN';

--changeset zomor-users:1-1
INSERT INTO users (id, email, password, enabled, created_at)
VALUES (gen_random_uuid(),
        'admin@local',
           -- BCrypt hash for "Admin@123"
        '$2a$12$5MWsPdbaAbu40Dx0pf99QezOYVuBGUBHF82yoIG3cVLX478owxL5W',
        true,
        now())

--changeset zomor-user_roles:1-1
    INSERT
INTO user_roles (id, user_id, role_id)
SELECT gen_random_uuid(), u.id, r.id
FROM users u,
     roles r
WHERE u.email = 'admin@local'
  AND r.name = 'ROLE_ADMIN';