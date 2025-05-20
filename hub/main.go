package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const ChallengeLength = 16

func main() {
	hub := NewHub()
	http.HandleFunc("/", hub.HandleSubscribe)
	http.HandleFunc("/publish", hub.HandlePublish)
	log.Println("WebSub Hub running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

type Hub struct {
	subscribers map[string]string // callback URL -> secret
	mu          sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[string]string),
	}
}

// HandleSubscribe processes subscription requests and verifies intent.
func (h *Hub) HandleSubscribe(w http.ResponseWriter, r *http.Request) {
	parseErr := r.ParseForm()
	if parseErr != nil {
		http.Error(w, "Invalid subscription request", http.StatusBadRequest)
		return
	}
	callback := r.FormValue("hub.callback")
	topic := r.FormValue("hub.topic")
	mode := r.FormValue("hub.mode")
	secret := r.FormValue("hub.secret")
	log.Printf("Received subscription: callback=%s topic=%s mode=%s", callback, topic, mode)

	//all posts back need sign so require secret.
	if callback == "" || topic == "" || mode != "subscribe" || secret == "" || len(secret) > 199 {
		http.Error(w, "Invalid subscription request", http.StatusBadRequest)
		return
	}

	//could validate deeper
	_, URLErr := url.Parse(callback)
	if URLErr != nil {
		http.Error(w, "Invalid callback URL", http.StatusBadRequest)
		return
	}

	//generate a random challenge here
	challenge := generateRandomString(ChallengeLength)
	verifyURL := fmt.Sprintf("%s?hub.mode=subscribe&hub.topic=%s&hub.challenge=%s", callback, topic, challenge)
	// Intent verification
	resp, err := http.Get(verifyURL)
	if err != nil {
		http.Error(w, "Failed to reach subscriber", http.StatusBadGateway)
		return
	}
	//close body, free resources
	defer resp.Body.Close()

	body, bodyErr := io.ReadAll(resp.Body)
	//trimming whitespaces in body for leniency
	if resp.StatusCode != http.StatusOK || bodyErr != nil || strings.TrimSpace(string(body)) != challenge {
		http.Error(w, "Intent verification failed", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	h.subscribers[callback] = secret
	h.mu.Unlock()

	w.WriteHeader(http.StatusAccepted)
}

func (h *Hub) HandlePublish(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received publish request")
	data := map[string]string{
		"message": "Hello from WebSub Hub!",
	}
	body, _ := json.Marshal(data)

	h.mu.Lock()
	for callback, secret := range h.subscribers {
		go postToSubscriber(callback, body, secret)
	}
	h.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func postToSubscriber(callback string, body []byte, secret string) {
	req, err := http.NewRequest("POST", callback, bytes.NewReader(body))
	if err != nil {
		return
	}

	if secret != "" {
		sig := generateHMAC(body, []byte(secret))
		req.Header.Set("X-Hub-Signature", "sha256="+sig)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	//ignore response
	client.Do(req)
}

func generateHMAC(message []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	//get raw HMAC bytes and convert to hex string
	return hex.EncodeToString(mac.Sum(nil))
}

func generateRandomString(length int) string {
	Bs := make([]byte, length)
	rand.Read(Bs)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(Bs)
}
