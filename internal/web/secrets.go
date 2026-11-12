package web

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/kotoyants/secrets-ui/internal/audit"
	"github.com/kotoyants/secrets-ui/internal/auth"
	"github.com/kotoyants/secrets-ui/internal/authz"
	"github.com/kotoyants/secrets-ui/internal/provider"
	"github.com/kotoyants/secrets-ui/internal/store"
	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// newKeyRows is the number of empty "add key" rows on the edit form.
const newKeyRows = 3

func (h *handlers) secretRoutes(r chi.Router) {
	r.Use(auth.RequireUser)
	r.Get("/", h.secretList)
	r.Get("/secrets/{id}", h.secretView)
	r.Post("/secrets/{id}/reveal", h.secretReveal)
	r.Get("/secrets/{id}/edit", h.secretEditForm)
	r.Post("/secrets/{id}", h.secretSave)
}

// accessible is an imported secret the current user may read.
type accessible struct {
	Row      db.GetSecretRow
	Ref      provider.SecretRef
	Provider provider.Provider
	Group    string
	Name     string
	CanWrite bool
}

// loadSecret loads secret {id} and checks read access. Secrets the user cannot
// read are reported as not found, so their existence is not revealed.
func (h *handlers) loadSecret(r *http.Request) (*accessible, error) {
	id, err := pathID(r, "id")
	if err != nil {
		return nil, err
	}
	row, err := h.store.GetSecret(r.Context(), id)
	if err != nil {
		return nil, err
	}
	subj := authz.FromPrincipal(auth.FromContext(r.Context()))
	if !subj.CanRead(row.Tags) {
		return nil, store.ErrNotFound
	}
	loc, err := decodeLocator(row.Locator)
	if err != nil {
		return nil, err
	}
	p, err := h.providers.Get(row.Provider)
	if err != nil {
		return nil, err
	}
	ref := provider.SecretRef{Provider: row.Provider, Locator: loc}
	group, name := p.Describe(ref)
	return &accessible{Row: row, Ref: ref, Provider: p, Group: group, Name: name, CanWrite: subj.CanWrite(row.Tags)}, nil
}

// ---- list ------------------------------------------------------------------

type listRow struct {
	ID       int64
	Group    string
	Name     string
	Tags     []string
	CanWrite bool
}

type listPage struct {
	Secrets  []listRow
	Total    int // readable secrets before filtering
	Groups   []string
	AllTags  []string
	Tag      string
	Group    string
	Query    string
	HasRoles bool
}

func (h *handlers) secretList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	subj := authz.FromPrincipal(p)
	rows, err := h.store.ListSecrets(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	page := listPage{Tag: q.Get("tag"), Group: q.Get("ns"), Query: strings.TrimSpace(q.Get("q"))}
	for _, ro := range p.Roles {
		if len(ro.Tags) > 0 || (ro.Builtin && ro.Name == store.RoleAdmin) {
			page.HasRoles = true
		}
	}

	groups, allTags := map[string]bool{}, map[string]bool{}
	for _, s := range authz.Filter(subj, authz.Read, rows, func(s db.ListSecretsRow) []string { return s.Tags }) {
		loc, err := decodeLocator(s.Locator)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		ref := provider.SecretRef{Provider: s.Provider, Locator: loc}
		row := listRow{ID: s.ID, Name: ref.String(), Tags: s.Tags, CanWrite: subj.CanWrite(s.Tags)}
		if prov, err := h.providers.Get(s.Provider); err == nil {
			row.Group, row.Name = prov.Describe(ref)
		}
		page.Total++
		groups[row.Group] = true
		for _, t := range s.Tags {
			allTags[t] = true
		}
		if page.Tag != "" && !slices.Contains(s.Tags, page.Tag) ||
			page.Group != "" && row.Group != page.Group ||
			page.Query != "" && !strings.Contains(strings.ToLower(row.Name), strings.ToLower(page.Query)) {
			continue
		}
		page.Secrets = append(page.Secrets, row)
	}
	slices.SortFunc(page.Secrets, func(a, b listRow) int {
		return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Name, b.Name))
	})
	page.Groups = slices.Sorted(maps.Keys(groups))
	page.AllTags = slices.Sorted(maps.Keys(allTags))
	h.render(w, r, http.StatusOK, "secrets", pageData{Nav: "home", Data: page})
}

// ---- view & reveal ---------------------------------------------------------

type keyView struct {
	Index    int
	Key      string
	Revealed bool
	Value    string
	Binary   bool // value is not valid UTF-8 and is shown base64-encoded
}

type secretPage struct {
	ID        int64
	Group     string
	Name      string
	Tags      []string
	CanWrite  bool
	ManagedBy string
	Missing   bool
	Keys      []keyView
}

// displayValue returns v as text, or base64 if it is binary.
func displayValue(v []byte) (string, bool) {
	if utf8.Valid(v) {
		return string(v), false
	}
	return base64.StdEncoding.EncodeToString(v), true
}

// buildSecretPage reads the secret from its provider. Values are included only
// for keys where reveal returns true (reveal may be nil).
func (h *handlers) buildSecretPage(r *http.Request, s *accessible, reveal func(key string) bool) (secretPage, error) {
	page := secretPage{ID: s.Row.ID, Group: s.Group, Name: s.Name, Tags: s.Row.Tags, CanWrite: s.CanWrite}
	data, err := s.Provider.Get(r.Context(), s.Ref)
	switch {
	case errors.Is(err, provider.ErrNotFound):
		page.Missing = true
		return page, nil
	case err != nil:
		return page, err
	}
	page.ManagedBy = data.ManagedBy
	for i, k := range data.SortedKeys() {
		kv := keyView{Index: i, Key: k}
		if reveal != nil && reveal(k) {
			kv.Revealed = true
			kv.Value, kv.Binary = displayValue(data.Values[k])
		}
		page.Keys = append(page.Keys, kv)
	}
	return page, nil
}

func (h *handlers) secretView(w http.ResponseWriter, r *http.Request) {
	s, err := h.loadSecret(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	page, err := h.buildSecretPage(r, s, nil)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, r, http.StatusOK, "secret", pageData{Nav: "home", Data: page})
}

// secretReveal reveals one key ("key") or every key ("all"). Parameters come from
// the form body or the query string. For htmx it returns out-of-band fragments:
// value cells for the view page, or prefilled textareas when "for=edit" (binary
// values are skipped there, since they can't be edited as text). Without
// JavaScript it renders the full view page. "for=copy" returns one key's value as
// plain text, for double-click copy on a masked field. Every reveal is audited.
func (h *handlers) secretReveal(w http.ResponseWriter, r *http.Request) {
	s, err := h.loadSecret(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	all := r.FormValue("all") != ""
	key := r.FormValue("key")
	page, err := h.buildSecretPage(r, s, func(k string) bool { return all || k == key })
	if err != nil {
		h.fail(w, r, err)
		return
	}
	htmx := r.Header.Get("HX-Request") == "true"
	edit := htmx && r.FormValue("for") == "edit"
	cp := r.FormValue("for") == "copy"
	if cp && all {
		h.fail(w, r, errorf("Copy takes a single key."))
		return
	}
	var revealed []keyView
	for _, k := range page.Keys {
		if k.Revealed && (!edit || !k.Binary) {
			revealed = append(revealed, k)
		}
	}
	if !all && len(revealed) == 0 {
		h.fail(w, r, store.ErrNotFound)
		return
	}
	attrs := map[string]any{"ref": s.Ref.String()}
	if all {
		names := make([]string, len(revealed))
		for i, k := range revealed {
			names[i] = k.Key
		}
		attrs["keys"] = names
	} else {
		attrs["key"] = key
	}
	if cp {
		attrs["copy"] = true
	}
	h.logAudit(r, audit.ActionSecretReveal, "secret", idStr(s.Row.ID), attrs)

	switch {
	case cp:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, revealed[0].Value)
	case edit:
		h.renderFragment(w, r, "secret_edit", "edit-values", revealed)
	case htmx:
		h.renderFragment(w, r, "secret", "revealed-values", revealed)
	default:
		h.render(w, r, http.StatusOK, "secret", pageData{Nav: "home", Data: page})
	}
}

func (h *handlers) renderFragment(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	var buf bytes.Buffer
	if err := pages[page].ExecuteTemplate(&buf, name, data); err != nil {
		h.log.ErrorContext(r.Context(), "render fragment", "page", page, "fragment", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// ---- edit ------------------------------------------------------------------

type editKey struct {
	Index  int
	Key    string
	Binary bool
}

type editPage struct {
	ID        int64
	Group     string
	Name      string
	ManagedBy string
	Version   string
	Keys      []editKey
	NewRows   []int
}

func (h *handlers) loadWritable(w http.ResponseWriter, r *http.Request) (*accessible, *provider.SecretData, bool) {
	s, err := h.loadSecret(r)
	if err != nil {
		h.fail(w, r, err)
		return nil, nil, false
	}
	if !s.CanWrite {
		h.render(w, r, http.StatusForbidden, "error", pageData{Error: "You can view this secret but not change it."})
		return nil, nil, false
	}
	data, err := s.Provider.Get(r.Context(), s.Ref)
	if err != nil {
		h.fail(w, r, err)
		return nil, nil, false
	}
	return s, data, true
}

func (h *handlers) secretEditForm(w http.ResponseWriter, r *http.Request) {
	s, data, ok := h.loadWritable(w, r)
	if !ok {
		return
	}
	page := editPage{ID: s.Row.ID, Group: s.Group, Name: s.Name, ManagedBy: data.ManagedBy, Version: data.Version}
	for i, k := range data.SortedKeys() {
		page.Keys = append(page.Keys, editKey{Index: i, Key: k, Binary: !utf8.Valid(data.Values[k])})
	}
	for i := range newKeyRows {
		page.NewRows = append(page.NewRows, i)
	}
	h.render(w, r, http.StatusOK, "secret_edit", pageData{Nav: "home", Data: page})
}

// secretSave applies the edit form. Existing keys keep their value when the field
// is left blank; keys in "delete" are removed; new rows with a key are added.
func (h *handlers) secretSave(w http.ResponseWriter, r *http.Request) {
	s, current, ok := h.loadWritable(w, r)
	if !ok {
		return
	}
	back := "/secrets/" + idStr(s.Row.ID)
	if err := r.ParseForm(); err != nil {
		h.done(w, r, back+"/edit", "", errorf("Invalid form."))
		return
	}
	version := r.PostForm.Get("version")
	if version != current.Version {
		h.done(w, r, back+"/edit", "", provider.ErrConflict)
		return
	}

	keys, values := r.PostForm["key"], r.PostForm["value"]
	if len(keys) != len(values) {
		h.done(w, r, back+"/edit", "", errorf("Invalid form."))
		return
	}
	next := maps.Clone(current.Values)
	var changed, added, removed []string
	for i, k := range keys {
		k = strings.TrimSpace(k)
		v := strings.ReplaceAll(values[i], "\r\n", "\n")
		if k == "" {
			continue // unused "new key" row
		}
		_, exists := current.Values[k]
		switch {
		case exists && v == "":
			// blank = keep current value
		case exists:
			if !bytes.Equal(next[k], []byte(v)) {
				changed = append(changed, k)
			}
			next[k] = []byte(v)
		default:
			if _, dup := next[k]; dup {
				h.done(w, r, back+"/edit", "", errorf("Key "+k+" is listed twice."))
				return
			}
			added = append(added, k)
			next[k] = []byte(v)
		}
	}
	for _, k := range r.PostForm["delete"] {
		if _, ok := next[k]; ok {
			delete(next, k)
			removed = append(removed, k)
		}
	}
	if len(changed)+len(added)+len(removed) == 0 {
		h.done(w, r, back, "No changes.", nil)
		return
	}

	err := s.Provider.Update(r.Context(), s.Ref, &provider.SecretData{Values: next, Version: version})
	if err != nil {
		h.done(w, r, back+"/edit", "", err)
		return
	}
	h.logAudit(r, audit.ActionSecretUpdate, "secret", idStr(s.Row.ID), map[string]any{
		"ref": s.Ref.String(), "changed": changed, "added": added, "removed": removed,
	})
	msg := "Secret saved."
	if current.ManagedBy != "" {
		msg += " Note: it is managed by " + current.ManagedBy + ", which may overwrite your change."
	}
	h.done(w, r, back, msg, nil)
}
