package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"diffie-hellman-key-exchange/pkg/handler"
	"diffie-hellman-key-exchange/pkg/key"
)

func main() {
	k, err := key.GenerateECDH()
	if err != nil {
		panic(err)
	}

	enc, err := key.EncodeECDHPublic(k.PublicKey())
	if err != nil {
		panic(err)
	}

	cli := http.DefaultClient

	sReq := handler.SessionRequest{
		PublicKey: base64.StdEncoding.EncodeToString(enc),
	}

	sData, err := json.Marshal(sReq)
	if err != nil {
		panic(err)
	}

	sreq, err := http.NewRequest(http.MethodPost, "http://localhost:5555/session", bytes.NewBuffer(sData))
	if err != nil {
		panic(err)
	}

	sreq.Header.Set("Content-Type", "application/json")

	res, err := cli.Do(sreq)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	var sRes handler.SessionResponse
	if err := json.Unmarshal(body, &sRes); err != nil {
		panic(err)
	}

	dec, err := base64.StdEncoding.DecodeString(sRes.PublicKey)
	if err != nil {
		panic(err)
	}

	pubKey, err := key.DecodeECDHPublic(dec)
	if err != nil {
		panic(err)
	}

	sec, err := k.ECDH(pubKey)
	if err != nil {
		panic(err)
	}

	log.Printf("Secret: %x\n", sec)

	cli = &http.Client{
		Transport: NewCookiesTransport(res.Cookies()),
	}

	// 15文字以下しか利用できない ...
	pass := "0123456789abcde"

	plain := []byte(pass)

	log.Printf("Password: %s\n", pass)

	encrypted, err := key.Encrypt(plain, sec, sRes.IV)
	if err != nil {
		panic(err)
	}

	pReq := handler.PasswordRequest{
		Password: encrypted,
	}

	pData, err := json.Marshal(pReq)
	if err != nil {
		panic(err)
	}

	preq, err := http.NewRequest(http.MethodPost, "http://localhost:5555/password", bytes.NewBuffer(pData))
	if err != nil {
		panic(err)
	}

	preq.Header.Set("Content-Type", "application/json")

	if _, err := cli.Do(preq); err != nil {
		panic(err)
	}
}

type CookiesTransport struct {
	Cookies   []*http.Cookie
	Transport http.RoundTripper
}

func NewCookiesTransport(
	cookies []*http.Cookie,
) *CookiesTransport {
	return &CookiesTransport{
		Cookies:   cookies,
		Transport: http.DefaultTransport,
	}
}

func (ct *CookiesTransport) transport() http.RoundTripper {
	return ct.Transport
}

func (ct *CookiesTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, cookie := range ct.Cookies {
		req.AddCookie(cookie)
	}

	resp, err := ct.transport().RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return resp, err
}
