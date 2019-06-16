package render

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"github.com/ably/comply/internal/config"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

var Store *sessions.FilesystemStore
var authConf *config.AuthConf

func initAuth() {
	authConf = &config.Config().Auth
	if !authConf.Disabled {
		authConf.Disabled = os.Getenv("AUTH_DISABLED") == "true"
	}
	if authConf.ClientSecret == "" {
		authConf.ClientSecret = os.Getenv("AUTH_CLIENT_SECRET")
	}
	if authConf.FilestoreSecret == "" {
		authConf.FilestoreSecret = os.Getenv("AUTH_FILESTORE_SECRET")
	}
	if authConf.CallbackURL == "" {
		authConf.CallbackURL = os.Getenv("AUTH_CALLBACK_URL")
	}
	if authConf.LogoutURL == "" {
		authConf.LogoutURL = os.Getenv("AUTH_LOGOUT_URL")
	}

	Store = sessions.NewFilesystemStore(filepath.Join(config.ProjectRoot(), authConf.FilestorePath), []byte(authConf.FilestoreSecret))
	gob.Register(map[string]interface{}{})
}

func isAuthenticated(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	session, err := Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := session.Values["profile"]; !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		next(w, r)
	}
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	domain := authConf.Domain

	conf := &oauth2.Config{
		ClientID:     authConf.ClientID,
		ClientSecret: authConf.ClientSecret,
		RedirectURL:  authConf.CallbackURL,
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}

	error := r.URL.Query().Get("error")
	if error != "" {
		http.Error(w, r.URL.Query().Get("error_description"), http.StatusUnauthorized)
		return
	}

	state := r.URL.Query().Get("state")
	session, err := Store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if state != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := conf.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Getting now the userInfo
	client := conf.Client(context.TODO(), token)
	resp, err := client.Get("https://" + domain + "/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var profile map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err = Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = token.Extra("id_token")
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	domain := authConf.Domain
	aud := authConf.Audience

	conf := &oauth2.Config{
		ClientID:     authConf.ClientID,
		ClientSecret: authConf.ClientSecret,
		RedirectURL:  authConf.CallbackURL,
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}

	if aud == "" {
		aud = "https://" + domain + "/userinfo"
	}

	// Generate random state
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, err := Store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audience := oauth2.SetAuthURLParam("audience", aud)
	url := conf.AuthCodeURL(state, audience)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {

	domain := authConf.Domain

	var Url *url.URL
	Url, err := url.Parse("https://" + domain)

	if err != nil {
		panic("boom")
	}

	Url.Path += "/v2/logout"
	parameters := url.Values{}
	parameters.Add("returnTo", authConf.LogoutURL)
	parameters.Add("client_id", authConf.ClientID)
	Url.RawQuery = parameters.Encode()

	http.Redirect(w, r, Url.String(), http.StatusTemporaryRedirect)
}
