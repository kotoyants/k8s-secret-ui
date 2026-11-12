-- name: InsertSecret :one
INSERT INTO secrets (provider, locator, created_by) VALUES ($1, $2, $3)
RETURNING *;

-- name: DeleteSecret :execrows
DELETE FROM secrets WHERE id = $1;

-- name: GetSecret :one
SELECT s.id, s.provider, s.locator, s.created_at, s.created_by,
       COALESCE(array_agg(st.tag ORDER BY st.tag) FILTER (WHERE st.tag IS NOT NULL), '{}')::text[] AS tags
FROM secrets s
LEFT JOIN secret_tags st ON st.secret_id = s.id
WHERE s.id = $1
GROUP BY s.id;

-- name: ListSecrets :many
SELECT s.id, s.provider, s.locator, s.created_at, s.created_by,
       COALESCE(array_agg(st.tag ORDER BY st.tag) FILTER (WHERE st.tag IS NOT NULL), '{}')::text[] AS tags
FROM secrets s
LEFT JOIN secret_tags st ON st.secret_id = s.id
GROUP BY s.id
ORDER BY s.provider, s.locator;

-- name: ListSecretLocators :many
-- Locators already imported from a provider (to mark them in the import view).
SELECT locator FROM secrets WHERE provider = $1;

-- name: DeleteSecretTags :exec
DELETE FROM secret_tags WHERE secret_id = $1;

-- name: InsertSecretTags :exec
INSERT INTO secret_tags (secret_id, tag)
SELECT $1, unnest(@tags::text[])
ON CONFLICT DO NOTHING;

-- name: ListTags :many
-- All tags in use, for autocomplete.
SELECT tag FROM role_tags
UNION
SELECT tag FROM secret_tags
ORDER BY tag;
