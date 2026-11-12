package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kotoyants/k8s-secret-ui/internal/auth"
	"github.com/kotoyants/k8s-secret-ui/internal/provider"
	"github.com/kotoyants/k8s-secret-ui/internal/store"
	"github.com/kotoyants/k8s-secret-ui/internal/tags"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var funcs = template.FuncMap{
	"join": strings.Join,
	// lines is a textarea height for s: its line count, between 1 and 10.
	"lines": func(s string) int { return min(max(strings.Count(s, "\n")+1, 1), 10) },
	"time": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			return v.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if v == nil {
				return "never"
			}
			return v.UTC().Format("2006-01-02 15:04 UTC")
		}
		return ""
	},
}

// pages maps a page name to its template set (layout + page).
var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{
		"login", "error", "secrets", "secret", "secret_edit",
		"admin_users", "admin_user", "admin_roles", "admin_role", "admin_import",
	} {
		pages[name] = template.Must(template.New("").Funcs(funcs).ParseFS(templateFS,
			"templates/layout.html", "templates/"+name+".html"))
	}
}

// staticHandler serves embedded CSS/JS.
func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	fileServer := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(w, r)
	})
}

// pageData is passed to every template.
type pageData struct {
	Principal *auth.Principal
	Flash     *flash
	Nav       string // active navigation item
	Error     string
	Next      string
	Data      any
}

// flash is a one-time status message carried across a redirect in a short-lived cookie.
type flash struct {
	Kind string `json:"k"` // "ok" or "error"
	Msg  string `json:"m"`
}

const flashCookie = "sm_flash"

func setFlash(w http.ResponseWriter, kind, msg string) {
	b, _ := json.Marshal(flash{Kind: kind, Msg: msg})
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: not sensitive; Secure is irrelevant for a status message
		Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString(b),
		Path: "/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func popFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}) //nolint:gosec // G124: deletion
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var f flash
	if json.Unmarshal(b, &f) != nil || f.Msg == "" || (f.Kind != "ok" && f.Kind != "error") {
		return nil
	}
	return &f
}

var loginErrors = map[string]string{
	auth.ErrCodeInvalidState:     "Your sign-in session expired or was invalid. Please try again.",
	auth.ErrCodeProviderError:    "Google sign-in failed. Please try again.",
	auth.ErrCodeEmailNotVerified: "Your Google account email is not verified.",
	auth.ErrCodeDomainNotAllowed: "This Google account's domain is not allowed to sign in.",
	auth.ErrCodeUserDisabled:     "Your account has been disabled. Contact an administrator.",
	auth.ErrCodeInternal:         "Something went wrong. Please try again later.",
}

func (h *handlers) loginPage(w http.ResponseWriter, r *http.Request) {
	if auth.FromContext(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	q := r.URL.Query()
	data := pageData{Next: auth.SafeNext(q.Get("next"))}
	if code := q.Get("error"); code != "" {
		data.Error = loginErrors[code]
		if data.Error == "" {
			data.Error = loginErrors[auth.ErrCodeInternal]
		}
	}
	h.render(w, r, http.StatusOK, "login", data)
}

// render executes a page into a buffer (so template errors don't produce half pages)
// and writes it with no-store caching.
func (h *handlers) render(w http.ResponseWriter, r *http.Request, status int, name string, data pageData) {
	data.Principal = auth.FromContext(r.Context())
	if data.Flash == nil {
		data.Flash = popFlash(w, r)
	}
	var buf bytes.Buffer
	if err := pages[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.ErrorContext(r.Context(), "render template", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// userError is an error whose message is safe and useful to show to the user.
type userError struct{ msg string }

func (e userError) Error() string { return e.msg }

func errorf(msg string) error { return userError{msg} }

// describeErr maps an error to an HTTP status and a user-facing message.
// Unknown errors become a generic 500 message (and should be logged by the caller).
func describeErr(err error) (int, string, bool) {
	var ue userError
	switch {
	case errors.As(err, &ue):
		return http.StatusBadRequest, ue.msg, true
	case errors.Is(err, tags.ErrInvalid):
		return http.StatusBadRequest, err.Error(), true
	case store.IsNotFound(err):
		return http.StatusNotFound, "Not found.", true
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, "That name or secret already exists.", true
	case errors.Is(err, store.ErrBuiltinRole):
		return http.StatusBadRequest, "Built-in roles cannot be changed.", true
	case errors.Is(err, provider.ErrNotFound):
		return http.StatusNotFound, "The secret no longer exists in its storage.", true
	case errors.Is(err, provider.ErrConflict):
		return http.StatusConflict, provider.ErrConflict.Error(), true
	case errors.Is(err, provider.ErrForbidden):
		return http.StatusForbidden, "Access to this location is not allowed.", true
	case errors.Is(err, provider.ErrUnsupported):
		return http.StatusBadRequest, "This secret type is not supported.", true
	case errors.Is(err, provider.ErrInvalid):
		return http.StatusBadRequest, err.Error(), true
	}
	return http.StatusInternalServerError, "Something went wrong. Please try again.", false
}

// fail renders an error page for err.
func (h *handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, msg, known := describeErr(err)
	if !known {
		h.log.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "err", err)
	}
	h.render(w, r, status, "error", pageData{Error: msg})
}

// done finishes a POST: sets a flash message (success or error) and redirects to path.
// path must be built by the handler (constant prefix + numeric ID), never taken from the request.
func (h *handlers) done(w http.ResponseWriter, r *http.Request, path, okMsg string, err error) {
	if err != nil {
		_, msg, known := describeErr(err)
		if !known {
			h.log.ErrorContext(r.Context(), "action failed", "path", r.URL.Path, "err", err)
		}
		setFlash(w, "error", msg)
	} else {
		setFlash(w, "ok", okMsg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther) //nolint:gosec // G710: path is always built by handlers from constants + numeric IDs
}
