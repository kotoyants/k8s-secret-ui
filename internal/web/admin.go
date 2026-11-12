package web

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/kotoyants/k8s-secret-ui/internal/audit"
	"github.com/kotoyants/k8s-secret-ui/internal/auth"
	"github.com/kotoyants/k8s-secret-ui/internal/provider"
	"github.com/kotoyants/k8s-secret-ui/internal/store"
	"github.com/kotoyants/k8s-secret-ui/internal/store/db"
	"github.com/kotoyants/k8s-secret-ui/internal/tags"
)

const maxRoleNameLen = 64

func (h *handlers) adminRoutes(r chi.Router) {
	r.Use(auth.RequireAdmin)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/users", http.StatusFound) })

	r.Get("/users", h.adminUsers)
	r.Get("/users/{id}", h.adminUser)
	r.Post("/users/{id}/roles", h.adminUserAddRole)
	r.Post("/users/{id}/roles/{roleID}/remove", h.adminUserRemoveRole)
	r.Post("/users/{id}/disable", h.adminUserSetDisabled(true))
	r.Post("/users/{id}/enable", h.adminUserSetDisabled(false))

	r.Get("/roles", h.adminRoles)
	r.Post("/roles", h.adminRoleCreate)
	r.Get("/roles/{id}", h.adminRole)
	r.Post("/roles/{id}", h.adminRoleUpdate)
	r.Post("/roles/{id}/delete", h.adminRoleDelete)
	r.Post("/roles/{id}/members", h.adminRoleAddMember)
	r.Post("/roles/{id}/members/{userID}/remove", h.adminRoleRemoveMember)

	r.Get("/secrets", h.adminSecrets)
	r.Post("/secrets/{id}", h.adminSecretUpdateTags)
	r.Post("/secrets/{id}/delete", h.adminSecretDelete)

	r.Get("/import", h.adminImport)
	r.Post("/import", h.adminImportSecret)
}

// ---- helpers ---------------------------------------------------------------

func pathID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		return 0, store.ErrNotFound
	}
	return id, nil
}

func formID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(r.PostFormValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errorf("Please choose an item from the list.")
	}
	return id, nil
}

func (h *handlers) logAudit(r *http.Request, action, targetType, targetID string, details map[string]any) {
	p := auth.FromContext(r.Context())
	h.audit.Log(r.Context(), audit.Event{
		ActorID: p.User.ID, ActorEmail: p.User.Email, Action: action,
		TargetType: targetType, TargetID: targetID, IP: audit.ClientIP(r), Details: details,
	})
}

func idStr(id int64) string { return strconv.FormatInt(id, 10) }

func parsePermission(s string) (db.RolePermission, error) {
	switch p := db.RolePermission(s); p {
	case db.RolePermissionRead, db.RolePermissionReadWrite:
		return p, nil
	}
	return "", errorf("Choose a valid permission.")
}

func parseRoleName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxRoleNameLen {
		return "", errorf(fmt.Sprintf("Role name must be 1-%d characters.", maxRoleNameLen))
	}
	return s, nil
}

func decodeLocator(raw []byte) (map[string]string, error) {
	var loc map[string]string
	if err := json.Unmarshal(raw, &loc); err != nil {
		return nil, fmt.Errorf("decode locator: %w", err)
	}
	return loc, nil
}

// isSelfAdminRole reports whether removing roleID from userID would remove the
// current admin's own admin role (which could lock everyone out).
func (h *handlers) isSelfAdminRole(r *http.Request, userID, roleID int64) (bool, error) {
	if auth.FromContext(r.Context()).User.ID != userID {
		return false, nil
	}
	role, err := h.store.GetRole(r.Context(), roleID)
	if err != nil {
		return false, err
	}
	return role.Builtin && role.Name == store.RoleAdmin, nil
}

// ---- users -----------------------------------------------------------------

type userRow struct {
	User  db.User
	Roles []string
}

func (h *handlers) adminUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := h.store.ListUsers(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	names, err := h.store.ListUserRoleNames(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	byUser := map[int64][]string{}
	for _, n := range names {
		byUser[n.UserID] = append(byUser[n.UserID], n.RoleName)
	}
	rows := make([]userRow, len(users))
	for i, u := range users {
		rows[i] = userRow{User: u, Roles: byUser[u.ID]}
	}
	h.render(w, r, http.StatusOK, "admin_users", pageData{Nav: "users", Data: rows})
}

type userPage struct {
	User      db.User
	Roles     []db.ListUserRolesRow
	Available []db.ListRolesRow
	IsSelf    bool
}

func (h *handlers) adminUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	u, err := h.store.GetUserByID(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	roles, err := h.store.ListUserRoles(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	all, err := h.store.ListRoles(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	has := map[int64]bool{}
	for _, ro := range roles {
		has[ro.ID] = true
	}
	page := userPage{User: u, Roles: roles, IsSelf: auth.FromContext(ctx).User.ID == id}
	for _, ro := range all {
		if !has[ro.ID] {
			page.Available = append(page.Available, ro)
		}
	}
	h.render(w, r, http.StatusOK, "admin_user", pageData{Nav: "users", Data: page})
}

func (h *handlers) adminUserAddRole(w http.ResponseWriter, r *http.Request) {
	userID, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	back := "/admin/users/" + idStr(userID)
	roleID, err := formID(r, "role_id")
	if err == nil {
		err = h.assignRole(r, userID, roleID)
	}
	h.done(w, r, back, "Role assigned.", err)
}

func (h *handlers) adminUserRemoveRole(w http.ResponseWriter, r *http.Request) {
	userID, err1 := pathID(r, "id")
	roleID, err2 := pathID(r, "roleID")
	if err1 != nil || err2 != nil {
		h.fail(w, r, store.ErrNotFound)
		return
	}
	h.done(w, r, "/admin/users/"+idStr(userID), "Role removed.", h.unassignRole(r, userID, roleID))
}

func (h *handlers) assignRole(r *http.Request, userID, roleID int64) error {
	ctx := r.Context()
	if _, err := h.store.GetUserByID(ctx, userID); err != nil {
		return err
	}
	role, err := h.store.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	if err := h.store.AddUserRole(ctx, db.AddUserRoleParams{UserID: userID, RoleID: roleID}); err != nil {
		return err
	}
	h.logAudit(r, audit.ActionUserRoleAssign, "user", idStr(userID), map[string]any{"role_id": roleID, "role": role.Name})
	return nil
}

func (h *handlers) unassignRole(r *http.Request, userID, roleID int64) error {
	self, err := h.isSelfAdminRole(r, userID, roleID)
	if err != nil {
		return err
	}
	if self {
		return errorf("You cannot remove your own admin role.")
	}
	n, err := h.store.RemoveUserRole(r.Context(), db.RemoveUserRoleParams{UserID: userID, RoleID: roleID})
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	h.logAudit(r, audit.ActionUserRoleRemove, "user", idStr(userID), map[string]any{"role_id": roleID})
	return nil
}

func (h *handlers) adminUserSetDisabled(disabled bool) http.HandlerFunc {
	action, msg := audit.ActionUserEnable, "User enabled."
	if disabled {
		action, msg = audit.ActionUserDisable, "User disabled. Their access is revoked immediately."
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := pathID(r, "id")
		if err != nil {
			h.fail(w, r, err)
			return
		}
		back := "/admin/users/" + idStr(id)
		if disabled && auth.FromContext(r.Context()).User.ID == id {
			h.done(w, r, back, "", errorf("You cannot disable yourself."))
			return
		}
		n, err := h.store.SetUserDisabled(r.Context(), db.SetUserDisabledParams{ID: id, Disabled: disabled})
		if err == nil && n == 0 {
			err = store.ErrNotFound
		}
		if err == nil {
			h.logAudit(r, action, "user", idStr(id), nil)
		}
		h.done(w, r, back, msg, err)
	}
}

// ---- roles -----------------------------------------------------------------

type rolesPage struct {
	Roles []db.ListRolesRow
	Tags  []string
}

func (h *handlers) adminRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.store.ListRoles(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	allTags, err := h.store.ListTags(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, http.StatusOK, "admin_roles", pageData{Nav: "roles", Data: rolesPage{Roles: roles, Tags: allTags}})
}

func (h *handlers) adminRoleCreate(w http.ResponseWriter, r *http.Request) {
	name, err := parseRoleName(r.PostFormValue("name"))
	var perm db.RolePermission
	var t []string
	if err == nil {
		perm, err = parsePermission(r.PostFormValue("permission"))
	}
	if err == nil {
		t, err = tags.Parse(r.PostFormValue("tags"))
	}
	var id int64
	if err == nil {
		id, err = h.store.CreateRoleWithTags(r.Context(), name, perm, t)
	}
	if err != nil {
		h.done(w, r, "/admin/roles", "", err)
		return
	}
	h.logAudit(r, audit.ActionRoleCreate, "role", idStr(id), map[string]any{"name": name, "permission": perm, "tags": t})
	h.done(w, r, "/admin/roles/"+idStr(id), "Role created.", nil)
}

type rolePage struct {
	Role      db.GetRoleRow
	TagsStr   string
	Members   []db.User
	NonMember []db.User
	Tags      []string
	MyID      int64
}

func (h *handlers) adminRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	role, err := h.store.GetRole(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	members, err := h.store.ListRoleMembers(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	users, err := h.store.ListUsers(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	allTags, err := h.store.ListTags(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	isMember := map[int64]bool{}
	for _, m := range members {
		isMember[m.ID] = true
	}
	page := rolePage{Role: role, TagsStr: strings.Join(role.Tags, ", "), Members: members, Tags: allTags,
		MyID: auth.FromContext(ctx).User.ID}
	for _, u := range users {
		if !isMember[u.ID] {
			page.NonMember = append(page.NonMember, u)
		}
	}
	h.render(w, r, http.StatusOK, "admin_role", pageData{Nav: "roles", Data: page})
}

func (h *handlers) adminRoleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	name, err := parseRoleName(r.PostFormValue("name"))
	var perm db.RolePermission
	var t []string
	if err == nil {
		perm, err = parsePermission(r.PostFormValue("permission"))
	}
	if err == nil {
		t, err = tags.Parse(r.PostFormValue("tags"))
	}
	if err == nil {
		err = h.store.UpdateRoleWithTags(r.Context(), id, name, perm, t)
	}
	if err == nil {
		h.logAudit(r, audit.ActionRoleUpdate, "role", idStr(id), map[string]any{"name": name, "permission": perm, "tags": t})
	}
	h.done(w, r, "/admin/roles/"+idStr(id), "Role saved.", err)
}

func (h *handlers) adminRoleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	role, err := h.store.GetRole(r.Context(), id)
	if err == nil && role.Builtin {
		err = store.ErrBuiltinRole
	}
	if err == nil {
		_, err = h.store.DeleteRole(r.Context(), id)
	}
	if err != nil {
		h.done(w, r, "/admin/roles/"+idStr(id), "", err)
		return
	}
	h.logAudit(r, audit.ActionRoleDelete, "role", idStr(id), map[string]any{"name": role.Name})
	h.done(w, r, "/admin/roles", "Role deleted.", nil)
}

func (h *handlers) adminRoleAddMember(w http.ResponseWriter, r *http.Request) {
	roleID, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	userID, err := formID(r, "user_id")
	if err == nil {
		err = h.assignRole(r, userID, roleID)
	}
	h.done(w, r, "/admin/roles/"+idStr(roleID), "Member added.", err)
}

func (h *handlers) adminRoleRemoveMember(w http.ResponseWriter, r *http.Request) {
	roleID, err1 := pathID(r, "id")
	userID, err2 := pathID(r, "userID")
	if err1 != nil || err2 != nil {
		h.fail(w, r, store.ErrNotFound)
		return
	}
	h.done(w, r, "/admin/roles/"+idStr(roleID), "Member removed.", h.unassignRole(r, userID, roleID))
}

// ---- imported secrets ------------------------------------------------------

type secretRow struct {
	ID        int64
	Provider  string
	Group     string
	Name      string
	Tags      []string
	TagsStr   string
	Status    string // "ok", "missing", "unknown"
	ManagedBy string
}

type secretsPage struct {
	Secrets   []secretRow
	ListError string
}

// providerIndex lists every provider's secrets, keyed by ref string. Providers that
// fail to list are reported in errs (their secrets get status "unknown").
func (h *handlers) providerIndex(r *http.Request) (map[string]provider.SecretInfo, map[string]bool, []string) {
	index := map[string]provider.SecretInfo{}
	failed := map[string]bool{}
	var errs []string
	for _, p := range h.providers.All() {
		list, err := p.List(r.Context())
		if err != nil {
			h.log.WarnContext(r.Context(), "provider list failed", "provider", p.ID(), "err", err)
			failed[p.ID()] = true
			errs = append(errs, fmt.Sprintf("Could not list secrets from %q.", p.ID()))
			continue
		}
		for _, s := range list {
			index[s.Ref.String()] = s
		}
	}
	return index, failed, errs
}

func (h *handlers) adminSecrets(w http.ResponseWriter, r *http.Request) {
	secrets, err := h.store.ListSecrets(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	index, failed, errs := h.providerIndex(r)
	page := secretsPage{ListError: strings.Join(errs, " ")}
	for _, s := range secrets {
		row := secretRow{ID: s.ID, Provider: s.Provider, Tags: s.Tags, TagsStr: strings.Join(s.Tags, ", "), Status: "unknown"}
		loc, err := decodeLocator(s.Locator)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		ref := provider.SecretRef{Provider: s.Provider, Locator: loc}
		row.Name = ref.String()
		if p, err := h.providers.Get(s.Provider); err == nil {
			row.Group, row.Name = p.Describe(ref)
		}
		if info, ok := index[ref.String()]; ok {
			row.Status, row.ManagedBy = "ok", info.ManagedBy
		} else if !failed[s.Provider] {
			row.Status = "missing"
		}
		page.Secrets = append(page.Secrets, row)
	}
	slices.SortFunc(page.Secrets, func(a, b secretRow) int {
		return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Name, b.Name))
	})
	h.render(w, r, http.StatusOK, "admin_secrets", pageData{Nav: "secrets", Data: page})
}

func (h *handlers) adminSecretUpdateTags(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	t, err := tags.Parse(r.PostFormValue("tags"))
	if err == nil {
		err = h.store.SetSecretTags(r.Context(), id, t)
	}
	if err == nil {
		h.logAudit(r, audit.ActionSecretTagsUpdate, "secret", idStr(id), map[string]any{"tags": t})
	}
	h.done(w, r, "/admin/secrets", "Tags saved.", err)
}

func (h *handlers) adminSecretDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	sec, err := h.store.GetSecret(r.Context(), id)
	if err == nil {
		_, err = h.store.DeleteSecret(r.Context(), id)
	}
	if err == nil {
		h.logAudit(r, audit.ActionSecretUnimport, "secret", idStr(id),
			map[string]any{"provider": sec.Provider, "locator": string(sec.Locator)})
	}
	h.done(w, r, "/admin/secrets", "Secret removed from the app (it still exists in its storage).", err)
}

// ---- import ----------------------------------------------------------------

type importRow struct {
	Provider  string
	Name      string
	Keys      int
	Locator   string // JSON, posted back on import
	Imported  bool
	ManagedBy string
}

type importGroup struct {
	Name  string
	Items []importRow
}

type importPage struct {
	Groups    []importGroup
	ListError string
	Tags      []string
}

func (h *handlers) adminImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := importPage{}
	var err error
	if page.Tags, err = h.store.ListTags(ctx); err != nil {
		h.fail(w, r, err)
		return
	}
	var errs []string
	byGroup := map[string][]importRow{}
	for _, p := range h.providers.All() {
		imported := map[string]bool{}
		locs, err := h.store.ListSecretLocators(ctx, p.ID())
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, raw := range locs {
			loc, err := decodeLocator(raw)
			if err != nil {
				h.fail(w, r, err)
				return
			}
			imported[provider.SecretRef{Provider: p.ID(), Locator: loc}.String()] = true
		}
		list, err := p.List(ctx)
		if err != nil {
			h.log.WarnContext(ctx, "provider list failed", "provider", p.ID(), "err", err)
			errs = append(errs, fmt.Sprintf("Could not list secrets from %q.", p.ID()))
			continue
		}
		for _, s := range list {
			locJSON, _ := json.Marshal(s.Ref.Locator)
			byGroup[s.Group] = append(byGroup[s.Group], importRow{
				Provider: p.ID(), Name: s.Name, Keys: len(s.Keys), Locator: string(locJSON),
				Imported: imported[s.Ref.String()], ManagedBy: s.ManagedBy,
			})
		}
	}
	for _, g := range slices.Sorted(maps.Keys(byGroup)) {
		page.Groups = append(page.Groups, importGroup{Name: g, Items: byGroup[g]})
	}
	page.ListError = strings.Join(errs, " ")
	h.render(w, r, http.StatusOK, "admin_import", pageData{Nav: "import", Data: page})
}

func (h *handlers) adminImportSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := func() error {
		p, err := h.providers.Get(r.PostFormValue("provider"))
		if err != nil {
			return errorf("Unknown storage.")
		}
		loc, err := decodeLocator([]byte(r.PostFormValue("locator")))
		if err != nil {
			return errorf("Invalid secret reference.")
		}
		t, err := tags.Parse(r.PostFormValue("tags"))
		if err != nil {
			return err
		}
		ref := provider.SecretRef{Provider: p.ID(), Locator: loc}
		// Validates the reference (allowed namespace, supported type, exists).
		if _, err := p.Get(ctx, ref); err != nil {
			return err
		}
		me := auth.FromContext(ctx).User.ID
		id, err := h.store.ImportSecret(ctx, p.ID(), loc, t, &me)
		if err != nil {
			return err
		}
		h.logAudit(r, audit.ActionSecretImport, "secret", idStr(id), map[string]any{"ref": ref.String(), "tags": t})
		return nil
	}()
	h.done(w, r, "/admin/import", "Secret imported.", err)
}
