package steam

import (
	"bytes"
	"errors"
	"fmt"
	browser "github.com/EDDYCJY/fake-useragent"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
)

const steamBaseUrl = "https://steamcommunity.com"

func (session *Session) Auth(realm, return_to string) (*http.Response, error) {
	url := steamBaseUrl + "/openid/login?" + url.Values{
		"openid.mode":       {"checkid_setup"},
		"openid.ns":         {"http://specs.openid.net/auth/2.0"},
		"openid.realm":      {realm},
		"openid.return_to":  {return_to},
		"openid.ns.sreg":    {"http://openid.net/extensions/sreg/1.1"},
		"openid.identity":   {"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.claimed_id": {"http://specs.openid.net/auth/2.0/identifier_select"},
	}.Encode()

	randomUA := browser.Random()

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("User-Agent", randomUA)
	req.Header.Add("Accept", "*/*")
	//req.Header.Add()

	resp, err := session.client.Do(req)

	//out, err := os.Create("login.html")
	//io.Copy(out, resp.Body)
	//out.Close()

	fmt.Println(resp.Header["Set-Cookie"])
	fmt.Println(resp.Request.Header["Cookie"])

	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	openidparams, exists := doc.Find("input[name=openidparams]").Attr("value")
	if !exists {
		return nil, errors.New("No form")
	}

	nonce, exists := doc.Find("input[name=nonce]").Attr("value")
	if !exists {
		return nil, errors.New("No form")
	}

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	fields := map[string]string{
		"action":       "steam_openid_login",
		"openid.mode":  "checkid_setup",
		"openidparams": openidparams,
		"nonce":        nonce,
	}

	for key, value := range fields {
		writer.WriteField(key, value)
	}
	writer.Close()

	req, _ = http.NewRequest("POST", steamBaseUrl+"/openid/login", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Add("User-Agent", randomUA)
	req.Header.Add("Referer", url)
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Accept-Encoding", "gzip, deflate, br")

	return session.client.Do(req)
}
