package steam

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type LoginResponse struct {
	Success      bool   `json:"success"`
	PublicKeyMod string `json:"publickey_mod"`
	PublicKeyExp string `json:"publickey_exp"`
	Timestamp    string
	TokenGID     string
}

type OAuth struct {
	SteamID       SteamID `json:"steamid,string"`
	Token         string  `json:"oauth_token"`
	WGToken       string  `json:"wgtoken"`
	WGTokenSecure string  `json:"wgtoken_secure"`
	WebCookie     string  `json:"webcookie"`
}

type LoginSession struct {
	Success           bool   `json:"success"`
	LoginComplete     bool   `json:"login_complete"`
	RequiresTwoFactor bool   `json:"requires_twofactor"`
	Message           string `json:"message"`
	RedirectURI       string `json:"redirect_uri"`
	OAuthInfo         string `json:"oauth"`
}

type WGTokenAPIResponse struct {
	Response *WGTokenResponse `json:"response"`
}

type WGTokenResponse struct {
	Token       string `json:"token"`
	TokenSecure string `json:"token_secure"`
}

type Session struct {
	client      *http.Client
	oauth       OAuth
	sessionID   string
	apiKey      string
	deviceID    string
	umqID       string
	chatMessage int
	language    string
}

const (
	steamBaseUrl  = "https://steamcommunity.com"
	steamLoginUrl = steamBaseUrl + "/login"

	apiGetWGToken = "https://api.steampowered.com/IMobileAuthService/GetWGToken/v1"
)

var (
	ErrEmptySessionID  = errors.New("sessionid is empty")
	ErrInvalidUsername = errors.New("invalid username")
	ErrNeedTwoFactor   = errors.New("invalid twofactor code")
)

func (session *Session) proceedDirectLogin(response *LoginResponse, accountName, password, twoFactorCode string) error {
	var n big.Int
	n.SetString(response.PublicKeyMod, 16)

	exp, err := strconv.ParseInt(response.PublicKeyExp, 16, 32)
	if err != nil {
		return err
	}

	pub := rsa.PublicKey{N: &n, E: int(exp)}
	rsaOut, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, []byte(password))
	if err != nil {
		return err
	}

	reqData := url.Values{
		"captcha_text":      {""},
		"captchagid":        {"-1"},
		"emailauth":         {""},
		"emailsteamid":      {""},
		"username":          {accountName},
		"password":          {base64.StdEncoding.EncodeToString(rsaOut)},
		"remember_login":    {"true"},
		"rsatimestamp":      {response.Timestamp},
		"twofactorcode":     {twoFactorCode},
		"donotcache":        {strconv.FormatInt(time.Now().Unix()*1000, 10)},
		"loginfriendlyname": {""},
		"oauth_client_id":   {"DE45CD61"},
		"oauth_scope":       {"read_profile write_profile read_client write_client"},
	}.Encode()

	req, err := http.NewRequest(
		http.MethodPost,
		steamLoginUrl+"/dologin",
		strings.NewReader(reqData),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("Content-Length", strconv.Itoa(len(reqData)))
	req.Header.Add("X-Requested-With", "com.valvesoftware.android.steam.community")
	req.Header.Add("Origin", steamBaseUrl)
	req.Header.Add("Referer", steamLoginUrl+"?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30")
	req.Header.Add("Accept", "text/javascript, text/html, application/xml, text/xml, */*")

	resp, err := session.client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return err
	}

	var loginSession LoginSession
	if err := json.NewDecoder(resp.Body).Decode(&loginSession); err != nil {
		return err
	}

	if !loginSession.Success {
		if loginSession.RequiresTwoFactor {
			return ErrNeedTwoFactor
		}

		return errors.New(loginSession.Message)
	}

	if err := json.Unmarshal([]byte(loginSession.OAuthInfo), &session.oauth); err != nil {
		return err
	}

	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return err
	}

	sessionID := make([]byte, hex.EncodedLen(len(randomBytes)))
	hex.Encode(sessionID, randomBytes)
	session.sessionID = string(sessionID)

	url, _ := url.Parse(steamBaseUrl)
	cookies := session.client.Jar.Cookies(url)
	for _, cookie := range cookies {
		if cookie.Name == "mobileClient" || cookie.Name == "mobileClientVersion" || cookie.Name == "steamCountry" || strings.Contains(cookie.Name, "steamMachineAuth") {
			// remove by setting max age -1
			cookie.MaxAge = -1
		}
	}

	sum := md5.Sum([]byte(accountName + password))
	session.deviceID = fmt.Sprintf(
		"android:%x-%x-%x-%x-%x",
		sum[:2], sum[2:4], sum[4:6], sum[6:8], sum[8:10],
	)

	session.client.Jar.SetCookies(
		url,
		append(cookies, &http.Cookie{
			Name:  "sessionid",
			Value: session.sessionID,
		}),
	)

	return nil
}

func (session *Session) makeLoginRequest(accountName string) (*LoginResponse, error) {
	reqData := url.Values{
		"username":   {accountName},
		"donotcache": {strconv.FormatInt(time.Now().Unix()*1000, 10)},
	}.Encode()

	req, err := http.NewRequest(
		http.MethodPost,
		steamLoginUrl+"/getrsakey",
		strings.NewReader(reqData),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("Content-Length", strconv.Itoa(len(reqData)))
	req.Header.Add("X-Requested-With", "XMLHttpRequest")
	req.Header.Add("Origin", steamBaseUrl)
	req.Header.Add("Referer", steamLoginUrl)
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	req.Header.Add("Accept", "*/*")

	resp, err := session.client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	var response LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	if !response.Success {
		return nil, ErrInvalidUsername
	}

	return &response, nil
}

func (session *Session) setupCookieJar() error {
	req, err := http.NewRequest(
		http.MethodGet,
		steamLoginUrl,
		nil,
	)
	if err != nil {
		return err
	}

	resp, err := session.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	steamURL, err := url.Parse(steamBaseUrl)
	if err != nil {
		return err
	}

	now := time.Now()
	_, offset := now.Zone()

	cookies := []*http.Cookie{
		{Name: "timezoneOffset", Value: fmt.Sprintf("%d,0", offset)},
		{Name: "mobileClient", Value: "android"},
		{Name: "mobileClientVersion", Value: "0 (2.1.3)"},
		{Name: "Steam_Language", Value: "english"},
	}

	for _, cookie := range resp.Cookies() {
		cookies = append(cookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}

	jar.SetCookies(steamURL, cookies)
	session.client.Jar = jar

	return nil
}

// func (session *Session) addWgCookies() {
// 	url, _ := url.Parse(steamBaseUrl)
// 	steamID := strconv.FormatUint(uint64(session.oauth.SteamID), 10)
// 	session.client.Jar.SetCookies(url, []*http.Cookie{
// 		{Name: "steamLogin", Value: steamID + "%7C%7C" + session.oauth.WGToken, HttpOnly: true},
// 		{Name: "steamLoginSecure", Value: steamID + "%7C%7C" + session.oauth.WGTokenSecure, HttpOnly: true, Secure: true},
// 	})
// }

// LoginTwoFactorCode logs in with the @twoFactorCode provided,
// note that in the case of having shared secret known, then it's better to
// use Login() because it's more accurate.
// Note: You can provide an empty two factor code if two factor authentication is not
// enabled on the account provided.
func (session *Session) LoginTwoFactorCode(accountName, password, twoFactorCode string) error {
	err := session.setupCookieJar()
	if err != nil {
		return err
	}

	response, err := session.makeLoginRequest(accountName)
	if err != nil {
		return err
	}

	return session.proceedDirectLogin(response, accountName, password, twoFactorCode)
}

// Login requests log in information first, then generates two factor code, and proceeds
// to do the actual login, this provides a better chance that the code generated will work
// because of the slowness of the API.
func (session *Session) Login(accountName, password, sharedSecret string, timeOffset time.Duration) error {
	err := session.setupCookieJar()
	if err != nil {
		return err
	}

	response, err := session.makeLoginRequest(accountName)
	if err != nil {
		return err
	}

	var twoFactorCode string
	if len(sharedSecret) != 0 {
		if twoFactorCode, err = GenerateTwoFactorCode(sharedSecret, time.Now().Add(timeOffset).Unix()); err != nil {
			return err
		}
	}

	return session.proceedDirectLogin(response, accountName, password, twoFactorCode)
}

func (session *Session) GetSteamID() SteamID {
	return session.oauth.SteamID
}

func (session *Session) SetLanguage(lang string) {
	session.language = lang
}

func (session *Session) RefreshSession() error {
	reqData := url.Values{
		"access_token": {session.oauth.Token},
	}.Encode()

	req, err := http.NewRequest(http.MethodPost, apiGetWGToken, strings.NewReader(reqData))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")

	resp, err := session.client.Do(req)

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return err
	}

	var response WGTokenAPIResponse
	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	session.oauth.WGTokenSecure = response.Response.TokenSecure
	session.oauth.WGToken = response.Response.Token

	//session.addWgCookies()
	url, _ := url.Parse(steamBaseUrl)
	steamID := strconv.FormatUint(uint64(session.oauth.SteamID), 10)
	session.client.Jar.SetCookies(url, []*http.Cookie{
		{Name: "steamLoginSecure", Value: steamID + "%7C%7C" + session.oauth.WGTokenSecure, HttpOnly: true, Secure: true},
	})

	return nil
}

func NewSessionWithAPIKey(apiKey string) *Session {
	return &Session{
		client:   &http.Client{},
		apiKey:   apiKey,
		language: "english",
	}
}

func NewSession(client *http.Client, apiKey string) *Session {
	return &Session{
		client:   client,
		apiKey:   apiKey,
		language: "english",
	}
}
