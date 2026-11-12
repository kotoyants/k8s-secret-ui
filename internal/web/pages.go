package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"

	"github.com/kotoyants/k8s-secret-ui/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

// pages maps a page name to its template set (layout + page).
var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{"login", "home"} {
		pages[name] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html"))
	}
}

// pageData is passed to every template.
type pageData struct {
	Principal *auth.Principal
	Error     string
	Next      string
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
	h.render(w, r, "login", data)
}

func (h *handlers) home(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "home", pageData{})
}

// render executes a page into a buffer (so template errors don't produce half pages)
// and writes it with no-store caching.
func (h *handlers) render(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	data.Principal = auth.FromContext(r.Context())
	var buf bytes.Buffer
	if err := pages[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.ErrorContext(r.Context(), "render template", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}
