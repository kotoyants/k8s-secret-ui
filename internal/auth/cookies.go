package auth

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type stateClaims struct {
	State    string `json:"st"`
	Nonce    string `json:"nn"`
	Verifier string `json:"pv"`
	Next     string `json:"nx,omitempty"`
	jwt.RegisteredClaims
}

func (s *Service) sign(claims jwt.Claims, key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

func (s *Service) parse(raw string, claims jwt.Claims, key []byte, aud string) error {
	_, err := jwt.ParseWithClaims(raw, claims,
		func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(aud),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.now),
	)
	return err
}

func (s *Service) registered(aud string, ttl time.Duration) jwt.RegisteredClaims {
	now := s.now()
	return jwt.RegisteredClaims{
		Issuer:    tokenIssuer,
		Audience:  jwt.ClaimStrings{aud},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
}

// setSession issues a session cookie for userID.
func (s *Service) setSession(w http.ResponseWriter, userID int64) error {
	c := s.registered(audSession, s.cfg.SessionTTL)
	c.Subject = strconv.FormatInt(userID, 10)
	tok, err := s.sign(c, s.sessionKey)
	if err != nil {
		return err
	}
	http.SetCookie(w, s.cookie(sessionCookie, tok, s.cfg.SessionTTL))
	return nil
}

var errNoSession = errors.New("no session cookie")

// sessionUserID validates the session cookie and returns the user ID in it.
func (s *Service) sessionUserID(r *http.Request) (int64, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return 0, errNoSession
	}
	var claims jwt.RegisteredClaims
	if err := s.parse(c.Value, &claims, s.sessionKey, audSession); err != nil {
		return 0, err
	}
	return strconv.ParseInt(claims.Subject, 10, 64)
}

func (s *Service) setState(w http.ResponseWriter, sc stateClaims) error {
	sc.RegisteredClaims = s.registered(audState, stateTTL)
	tok, err := s.sign(sc, s.stateKey)
	if err != nil {
		return err
	}
	http.SetCookie(w, s.cookie(stateCookie, tok, stateTTL))
	return nil
}

func (s *Service) readState(r *http.Request) (*stateClaims, error) {
	c, err := r.Cookie(stateCookie)
	if err != nil {
		return nil, err
	}
	var sc stateClaims
	if err := s.parse(c.Value, &sc, s.stateKey, audState); err != nil {
		return nil, err
	}
	return &sc, nil
}

// cookie builds an HttpOnly, SameSite=Lax cookie. Secure is set whenever BASE_URL
// is https; it is off only for plain-http local development.
func (s *Service) cookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure depends on BASE_URL scheme (see above)
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	c := s.cookie(name, "", 0) //nolint:gosec // G124: same attributes as cookie()
	c.MaxAge = -1
	http.SetCookie(w, c)
}
