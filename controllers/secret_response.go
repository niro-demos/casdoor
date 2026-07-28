package controllers

import "github.com/casdoor/casdoor/object"

type tokenResponse struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	CreatedTime  string `json:"createdTime"`
	Application  string `json:"application"`
	Organization string `json:"organization"`
	User         string `json:"user"`
	ExpiresIn    int    `json:"expiresIn"`
	Scope        string `json:"scope"`
	TokenType    string `json:"tokenType"`
	GrantType    string `json:"grantType"`
	CodeIsUsed   bool   `json:"codeIsUsed"`
	CodeExpireIn int64  `json:"codeExpireIn"`
	Resource     string `json:"resource"`
	DPoPJkt      string `json:"dPoPJkt"`
}

func toTokenResponse(token *object.Token) *tokenResponse {
	if token == nil {
		return nil
	}

	return &tokenResponse{
		Owner:        token.Owner,
		Name:         token.Name,
		CreatedTime:  token.CreatedTime,
		Application:  token.Application,
		Organization: token.Organization,
		User:         token.User,
		ExpiresIn:    token.ExpiresIn,
		Scope:        token.Scope,
		TokenType:    token.TokenType,
		GrantType:    token.GrantType,
		CodeIsUsed:   token.CodeIsUsed,
		CodeExpireIn: token.CodeExpireIn,
		Resource:     token.Resource,
		DPoPJkt:      token.DPoPJkt,
	}
}

func toTokenResponses(tokens []*object.Token) []*tokenResponse {
	res := make([]*tokenResponse, 0, len(tokens))
	for _, token := range tokens {
		res = append(res, toTokenResponse(token))
	}
	return res
}

type sessionResponse struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Application string `json:"application"`
	CreatedTime string `json:"createdTime"`
}

func toSessionResponse(session *object.Session) *sessionResponse {
	if session == nil {
		return nil
	}

	return &sessionResponse{
		Owner:       session.Owner,
		Name:        session.Name,
		Application: session.Application,
		CreatedTime: session.CreatedTime,
	}
}

func toSessionResponses(sessions []*object.Session) []*sessionResponse {
	res := make([]*sessionResponse, 0, len(sessions))
	for _, session := range sessions {
		res = append(res, toSessionResponse(session))
	}
	return res
}

func toCertResponse(certs []*object.Cert, isGlobalAdmin bool) ([]*object.Cert, error) {
	res := make([]*object.Cert, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		if !isGlobalAdmin && cert.Owner == "admin" {
			continue
		}

		certCopy := *cert
		if !isGlobalAdmin {
			object.GetMaskedCert(&certCopy)
		}
		res = append(res, &certCopy)
	}
	return res, nil
}
