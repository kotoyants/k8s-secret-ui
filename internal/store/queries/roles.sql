-- name: CreateRole :one
INSERT INTO roles (name, permission) VALUES ($1, $2)
RETURNING *;

-- name: UpdateRole :execrows
-- Built-in roles cannot be changed.
UPDATE roles SET name = $2, permission = $3
WHERE id = $1 AND NOT builtin;

-- name: DeleteRole :execrows
-- Built-in roles cannot be deleted.
DELETE FROM roles WHERE id = $1 AND NOT builtin;

-- name: GetRole :one
SELECT r.id, r.name, r.permission, r.builtin, r.created_at,
       COALESCE(array_agg(rt.tag ORDER BY rt.tag) FILTER (WHERE rt.tag IS NOT NULL), '{}')::text[] AS tags
FROM roles r
LEFT JOIN role_tags rt ON rt.role_id = r.id
WHERE r.id = $1
GROUP BY r.id;

-- name: ListRoles :many
SELECT r.id, r.name, r.permission, r.builtin, r.created_at,
       COALESCE(array_agg(DISTINCT rt.tag) FILTER (WHERE rt.tag IS NOT NULL), '{}')::text[] AS tags,
       (SELECT count(*) FROM user_roles ur WHERE ur.role_id = r.id) AS member_count
FROM roles r
LEFT JOIN role_tags rt ON rt.role_id = r.id
GROUP BY r.id
ORDER BY r.builtin DESC, r.name;

-- name: DeleteRoleTags :exec
DELETE FROM role_tags WHERE role_id = $1;

-- name: InsertRoleTags :exec
INSERT INTO role_tags (role_id, tag)
SELECT $1, unnest(@tags::text[])
ON CONFLICT DO NOTHING;

-- name: ListRoleMembers :many
SELECT u.* FROM users u
JOIN user_roles ur ON ur.user_id = u.id
WHERE ur.role_id = $1
ORDER BY u.email;
