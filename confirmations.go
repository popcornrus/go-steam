package steam

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

type ConfirmationResponse struct {
	Success       bool            `json:"success"`
	Confirmations []*Confirmation `json:"conf"`
}

type Confirmation struct {
	ID           string `json:"id"`
	Type         uint8  `json:"type"`
	Creator      string `json:"creator_id"`
	Nonce        string `json:"nonce"`
	CreationTime uint64 `json:"creation"`

	// TypeName string      `json:"type_name"`
	// Cancel   string      `json:"cancel"`
	// Accept   string      `json:"accept"`
	// Icon     string      `json:"icon"`
	// Multi    bool        `json:"multi"`
	// Headline string      `json:"headline"`
	// Summary  []string    `json:"summary"`
	// Warn     interface{} `json:"warn"`
}

var (
	//ErrConfirmationsUnknownError = errors.New("unknown error occurred finding confirmation")
	ErrCannotFindConfirmations   = errors.New("unable to find confirmation")
	ErrCannotFindDescriptions    = errors.New("unable to find confirmation descriptions")
	ErrConfirmationsDescMismatch = errors.New("cannot match confirmation with their respective descriptions")
	ErrWGTokenExpired            = errors.New("WGToken expired")
)

func (session *Session) execConfirmationRequest(request, key, tag string, current int64, values map[string]string) (*http.Response, error) {
	params := url.Values{
		"p":   {session.deviceID},
		"a":   {session.oauth.SteamID.ToString()},
		"k":   {key},
		"t":   {strconv.FormatInt(current, 10)},
		"m":   {"android"},
		"tag": {tag},
	}

	for k, v := range values {
		params.Add(k, v)
	}

	return session.client.Get("https://steamcommunity.com/mobileconf/" + request + params.Encode())
}

func (session *Session) GetConfirmations(identitySecret string, current int64) ([]*Confirmation, error) {
	key, err := GenerateConfirmationCode(identitySecret, "conf", current)
	if err != nil {
		return nil, err
	}

	resp, err := session.execConfirmationRequest("getlist?", key, "conf", current, nil)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	var confirmationResponse ConfirmationResponse

	b, _ := io.ReadAll(resp.Body)

	//d := json.NewDecoder(resp.Body)
	if err = json.Unmarshal(b, &confirmationResponse); err != nil || !confirmationResponse.Success {
		return nil, err
	}

	return confirmationResponse.Confirmations, nil
}

func (session *Session) AnswerConfirmation(confirmation *Confirmation, identitySecret, answer string, current int64) error {
	key, err := GenerateConfirmationCode(identitySecret, answer, current)
	if err != nil {
		return err
	}

	op := map[string]string{
		"op":  answer,
		"cid": confirmation.ID,
		"ck":  confirmation.Nonce,
	}

	resp, err := session.execConfirmationRequest("ajaxop?", key, answer, current, op)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return err
	}

	type Response struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	if !response.Success {
		return errors.New(response.Message)
	}

	return nil
}

func (confirmation *Confirmation) Answer(session *Session, key, answer string, current int64) error {
	return session.AnswerConfirmation(confirmation, key, answer, current)
}
