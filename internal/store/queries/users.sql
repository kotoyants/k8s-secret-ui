-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: InsertUser :one
-- Returns no row if the user already exists (concurrent first login).
INSERT INTO users (email, name, avatar_url, last_login_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (email) DO NOTHING
RETURNING *;

-- name: UpdateUserLogin :one
UPDATE users
SET name = $2, avatar_url = $3, last_login_at = now()
WHERE id = $1
RETURNING *;

-- name: ListUsers :many
SELECT * FROM users ORDER BY email;

-- name: SetUserDisabled :execrows
UPDATE users SET disabled = $2 WHERE id = $1;

-- name: CountUserRoles :one
SELECT count(*) FROM user_roles WHERE user_id = $1;

-- name: AddUserRole :exec
INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: AddUserRoleByName :exec
INSERT INTO user_roles (user_id, role_id)
SELECT $1, id FROM roles WHERE name = $2
ON CONFLICT DO NOTHING;

-- name: RemoveUserRole :execrows
DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;

-- name: ListUserRoles :many
-- Roles of one user with their tags (used for authorization on every request).
SELECT r.id, r.name, r.permission, r.builtin,
       COALESCE(array_agg(rt.tag ORDER BY rt.tag) FILTER (WHERE rt.tag IS NOT NULL), '{}')::text[] AS tags
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
LEFT JOIN role_tags rt ON rt.role_id = r.id
WHERE ur.user_id = $1
GROUP BY r.id
ORDER BY r.name;

-- name: ListUserRoleNames :many
-- Role names per user, for the admin users page.
SELECT ur.user_id, r.id AS role_id, r.name AS role_name
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
ORDER BY ur.user_id, r.name;
