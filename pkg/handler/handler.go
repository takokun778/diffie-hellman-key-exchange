package handler

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"diffie-hellman-key-exchange/pkg/cache"
	"diffie-hellman-key-exchange/pkg/key"

	"github.com/google/uuid"
)

type Handler struct {
	Cache *cache.Cache
}

func New(
	cc *cache.Cache,
) *Handler {
	return &Handler{
		Cache: cc,
	}
}

type SessionRequest struct {
	PublicKey string `json:"public_key"`
}

type SessionResponse struct {
	PublicKey string `json:"public_key"`
	IV        []byte `json:"iv"`
}

func (hdl *Handler) Session(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		log.Printf("Error: %+v\n", err)

		return
	}

	dec, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		log.Printf("Error: %+v\n", err)

		return
	}

	pub, err := key.DecodeECDHPublic(dec)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		log.Printf("Error: %+v\n", err)

		return
	}

	id := uuid.New().String()

	sec, err := hdl.Cache.MasterKey.ECDH(pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		log.Printf("Error: %+v\n", err)

		return
	}

	log.Printf("Secret: %x\n", sec)

	iv, err := key.GenerateIV()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		log.Printf("Error: %+v\n", err)

		return
	}

	hdl.Cache.SetSecret(id, sec)

	hdl.Cache.SetIV(id, iv)

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    id,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(time.Minute),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	enc, err := key.EncodeECDHPublic(hdl.Cache.MasterKey.PublicKey())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		log.Printf("Error: %+v\n", err)

		return
	}

	res := SessionResponse{
		PublicKey: base64.StdEncoding.EncodeToString(enc),
		IV:        iv,
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		log.Printf("Error: %+v\n", err)

		return
	}
}

type PasswordRequest struct {
	Password []byte `json:"password"`
}

func (hdl *Handler) Password(
	w http.ResponseWriter,
	r *http.Request,
) {
	ck, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		log.Printf("Error: %+v\n", err)

		return
	}

	id := ck.Value

	sec := hdl.Cache.GetSecret(id)

	iv := hdl.Cache.GetIV(id)

	var req PasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		log.Printf("Error: %+v\n", err)

		return
	}

	decrypted, err := key.Decrypt(req.Password, sec, iv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		log.Printf("Error: %+v\n", err)

		return
	}

	log.Printf("Password: %s\n", decrypted)
}
