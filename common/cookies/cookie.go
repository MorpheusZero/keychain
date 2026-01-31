package cookies

import "net/http"

type CookieOptions struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	MaxAge   int // seconds; <=0 means delete
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

type ICookieJar interface {
	SetCookie(w http.ResponseWriter, options *CookieOptions)
	GetCookieValue(r *http.Request, name string) (string, error)
	DeleteCookie(w http.ResponseWriter, name string)
}

type CookieJar struct{}

func NewCookieJar() *CookieJar {
	return &CookieJar{}
}

func (c *CookieJar) SetCookie(w http.ResponseWriter, options *CookieOptions) {
	cookie := &http.Cookie{
		Name:     options.Name,
		Value:    options.Value,
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}
	http.SetCookie(w, cookie)
}
func (c *CookieJar) GetCookieValue(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (c *CookieJar) DeleteCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}
