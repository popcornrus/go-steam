package steam

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/popcornrus/steam/pb"
)

type LoginFinalized struct {
	SteamID      SteamID        `json:"steamID,string"`
	TransferInfo []TransferInfo `json:"transfer_info"`
}

type TransferInfo struct {
	URL    string        `json:"url"`
	Params TransferParam `json:"params"`
}

type TransferParam struct {
	Nonce string `json:"nonce"`
	Auth  string `json:"auth"`
}

type OAuth struct {
	SteamID       SteamID `json:"steamid,string"`
	Token         string  `json:"oauth_token"`
	WGToken       string  `json:"wgtoken"`
	WGTokenSecure string  `json:"wgtoken_secure"`
	WebCookie     string  `json:"webcookie"`
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
	RSAPublicKey      = APIBaseUrl + "/IAuthenticationService/GetPasswordRSAPublicKey/v1"
	AuthSession       = APIBaseUrl + "/IAuthenticationService/BeginAuthSessionViaCredentials/v1"
	UpdateAuthSession = APIBaseUrl + "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1"
	Poll              = APIBaseUrl + "/IAuthenticationService/PollAuthSessionStatus/v1"

	LoginBaseUrl   = "https://login.steampowered.com"
	FinalizeLogin  = LoginBaseUrl + "/jwt/finalizelogin"
	RefreshSession = LoginBaseUrl + "/jwt/refresh?redir=https%3A%2F%2Fsteamcommunity.com"
)

var (
	ErrEmptySessionID  = errors.New("sessionid is empty")
	ErrInvalidUsername = errors.New("invalid username")
	ErrNeedTwoFactor   = errors.New("invalid twofactor code")
)

func getRSAKey(accountName string) (*pb.CAuthentication_GetPasswordRSAPublicKey_Response, error) {

	l := len(accountName)
	b := make([]byte, l+2)
	b[0] = 10
	b[1] = uint8(l)
	copy(b[2:], []byte(accountName))

	resp, err := http.Get(RSAPublicKey + "?" + "origin=https://steamcommunity.com&input_protobuf_encoded=" + base64.StdEncoding.EncodeToString(b))

	if err != nil {
		return nil, err
	}

	if xe := resp.Header.Get("x-eresult"); xe != "1" {
		return nil, errors.New(xe)
	}

	b, err = io.ReadAll(resp.Body)

	if b == nil {
		return nil, err
	}

	//decodedBytes, _ := base64.StdEncoding.DecodeString(string(b))

	var rsaKey pb.CAuthentication_GetPasswordRSAPublicKey_Response
	_ = proto.Unmarshal(b, &rsaKey)

	return &rsaKey, nil
}

func encryptPasword(pwd string, key *pb.CAuthentication_GetPasswordRSAPublicKey_Response) (string, error) {

	var n big.Int
	n.SetString(*key.PublickeyMod, 16)

	exp, err := strconv.ParseInt(*key.PublickeyExp, 16, 32)
	if err != nil {
		return "", err
	}

	pub := rsa.PublicKey{N: &n, E: int(exp)}
	rsaOut, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, []byte(pwd))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsaOut), nil
}

func beginAuthSession(crypt string, accountName string, timestamp *uint64) (*pb.CAuthentication_BeginAuthSessionViaCredentials_Response, error) {

	deviceFriendlyName := "Galaxy S22"
	platformType := pb.EAuthTokenPlatformType_k_EAuthTokenPlatformType_MobileApp.Enum()

	deviceDetails := pb.CAuthentication_DeviceDetails{
		DeviceFriendlyName: &deviceFriendlyName,
		PlatformType:       platformType,
		OsType:             proto.Int32(-500),
		GamingDeviceType:   proto.Uint32(528),
	}

	reqBody := pb.CAuthentication_BeginAuthSessionViaCredentials_Request{
		DeviceFriendlyName:  &deviceFriendlyName,
		AccountName:         &accountName,
		EncryptedPassword:   &crypt,
		EncryptionTimestamp: timestamp,
		RememberLogin:       proto.Bool(true),
		PlatformType:        platformType,
		Persistence:         pb.ESessionPersistence_k_ESessionPersistence_Persistent.Enum(),
		WebsiteId:           proto.String("Mobile"),
		DeviceDetails:       &deviceDetails,
	}

	data, _ := proto.Marshal(&reqBody)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	writer.WriteField("input_protobuf_encoded", base64.StdEncoding.EncodeToString(data))
	writer.Close()

	req, _ := http.NewRequest("POST", AuthSession, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if xe := resp.Header.Get("x-eresult"); xe != "1" {
		return nil, errors.New(xe)
	}

	b, err := io.ReadAll(resp.Body)
	if b == nil {
		return nil, err
	}

	var authResponse pb.CAuthentication_BeginAuthSessionViaCredentials_Response
	_ = proto.Unmarshal(b, &authResponse)

	return &authResponse, nil
}

func updateAuthSession(code string, authSession *pb.CAuthentication_BeginAuthSessionViaCredentials_Response) error {

	reqBody := pb.CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request{
		ClientId: authSession.ClientId,
		Steamid:  authSession.Steamid,
		Code:     &code,
		CodeType: pb.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceCode.Enum(),
	}

	data, _ := proto.Marshal(&reqBody)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	writer.WriteField("input_protobuf_encoded", base64.StdEncoding.EncodeToString(data))
	writer.Close()

	req, _ := http.NewRequest("POST", UpdateAuthSession, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if xe := resp.Header.Get("x-eresult"); xe != "1" {
		return errors.New(xe)
	}

	return nil
}

func pollAuthSession(authSession *pb.CAuthentication_BeginAuthSessionViaCredentials_Response) (*pb.CAuthentication_PollAuthSessionStatus_Response, error) {

	reqBody := pb.CAuthentication_PollAuthSessionStatus_Request{
		ClientId:  authSession.ClientId,
		RequestId: authSession.RequestId,
	}

	data, _ := proto.Marshal(&reqBody)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	writer.WriteField("input_protobuf_encoded", base64.StdEncoding.EncodeToString(data))
	writer.Close()

	req, _ := http.NewRequest("POST", Poll, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if xe := resp.Header.Get("x-eresult"); xe != "1" {
		return nil, errors.New(xe)
	}

	b, err := io.ReadAll(resp.Body)
	if b == nil {
		return nil, err
	}

	var pollAuth pb.CAuthentication_PollAuthSessionStatus_Response
	_ = proto.Unmarshal(b, &pollAuth)

	return &pollAuth, nil
}

func (session *Session) finalizeLogin(pollAuth *pb.CAuthentication_PollAuthSessionStatus_Response) error {

	if session.sessionID == "" {
		randomBytes := make([]byte, 12)
		if _, err := rand.Read(randomBytes); err != nil {
			return err
		}

		sessionID := make([]byte, hex.EncodedLen(len(randomBytes)))
		hex.Encode(sessionID, randomBytes)
		session.sessionID = string(sessionID)
	}

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	writer.WriteField("nonce", *pollAuth.RefreshToken)
	writer.WriteField("sessionid", session.sessionID)
	writer.WriteField("redir", "https://steamcommunity.com/login/home/?goto=")
	writer.Close()

	req, _ := http.NewRequest("POST", FinalizeLogin, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	d := json.NewDecoder(resp.Body)

	var loginFinalized LoginFinalized
	if err = d.Decode(&loginFinalized); err != nil {
		return err
	}

	// Add Refresh Cookie
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "steamRefresh_steam" {
			jar.SetCookies(&url.URL{Scheme: "https", Host: "login.steampowered.com"}, []*http.Cookie{cookie})
			break
		}
	}

	// Get LoginSecure
	for _, info := range loginFinalized.TransferInfo {
		if info.URL != "https://steamcommunity.com/login/settoken" {
			continue
		}

		body = new(bytes.Buffer)
		writer = multipart.NewWriter(body)

		writer.WriteField("nonce", info.Params.Nonce)
		writer.WriteField("auth", info.Params.Auth)
		writer.WriteField("steamID", loginFinalized.SteamID.ToString())
		writer.Close()

		req, _ = http.NewRequest("POST", info.URL, body)
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: session.sessionID})
		req.Header.Set("Content-Type", writer.FormDataContentType())
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		for _, cookie := range resp.Cookies() {
			if cookie.Name == "steamLoginSecure" {
				jar.SetCookies(&url.URL{Scheme: "https", Host: "steamcommunity.com"}, []*http.Cookie{cookie, {Name: "sessionid", Value: session.sessionID, SameSite: http.SameSiteNoneMode, Secure: true, HttpOnly: true, Path: "/"}})
				break
			}
		}

		break
	}

	session.client.Jar = jar

	return nil
}

func (session *Session) Login(accountName, password, sharedSecret string, timeOffset time.Duration) error {

	key, err := getRSAKey(accountName)
	if key == nil {
		return err
	}

	crypt, err := encryptPasword(password, key)
	if err != nil {
		return err
	}

	authSession, err := beginAuthSession(crypt, accountName, key.Timestamp)
	if err != nil {
		return err
	}

	code, _ := GenerateTwoFactorCode(sharedSecret, time.Now().Add(timeOffset).Unix())

	if err = updateAuthSession(code, authSession); err != nil {
		return err
	}

	pollAuth, err := pollAuthSession(authSession)
	if err != nil {
		return err
	}

	err = session.finalizeLogin(pollAuth)
	if err != nil {
		return err
	}

	sum := md5.Sum([]byte(accountName + password))
	session.deviceID = fmt.Sprintf(
		"android:%x-%x-%x-%x-%x",
		sum[:2], sum[2:4], sum[4:6], sum[6:8], sum[8:10],
	)

	session.oauth.SteamID = SteamID(*authSession.Steamid)
	session.addMobileAuthCookies()

	return nil
}

func (session *Session) Refresh() error {

	resp, err := session.client.Get(RefreshSession)
	if err != nil {
		return err
	}

	jar := session.client.Jar
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "steamRefresh_steam" {
			jar.SetCookies(&url.URL{Scheme: "https", Host: "login.steampowered.com"}, []*http.Cookie{cookie})
			break
		}
	}

	return nil
}

func (session Session) addMobileAuthCookies() {

	cookies := []*http.Cookie{
		{Name: "mobileClientVersion", Value: "0 (2.1.3)"},
		{Name: "mobileClient", Value: "android"},
		{Name: "steamid", Value: session.oauth.SteamID.ToString()},
		{Name: "Steam_Language", Value: "english"},
		{Name: "dob", Value: ""},
	}

	session.client.Jar.SetCookies(&url.URL{Scheme: "https", Host: "steamcommunity.com"}, cookies)
}

func (session *Session) GetSteamID() SteamID {
	return session.oauth.SteamID
}

func (session *Session) SetLanguage(lang string) {
	session.language = lang
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
