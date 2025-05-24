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
	"mime"
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

type subscriptionKey struct {
	Callback string
	Topic    string
}
type Hub struct {
	subscribers map[subscriptionKey]string // secret
	mu          sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[subscriptionKey]string),
	}
}

// HandleSubscribe processes subscription requests and verifies intent.
func (h *Hub) HandleSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	contentType := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		log.Printf("Received request with incorrect mediaType: %s", mediaType)
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}
	// Spec requires UTF-8 but subscriber does not send it explicitly, so only check if it is included.
	if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
		log.Printf("Received request with unsupported charset: %s", charset)
		http.Error(w, "Unsupported Charset; only UTF-8 is supported", http.StatusUnsupportedMediaType)
		return
	}
	parseErr := r.ParseForm()
	if parseErr != nil {
		http.Error(w, "Invalid subscription request", http.StatusBadRequest)
		return
	}

	callback := r.FormValue("hub.callback")
	topic := r.FormValue("hub.topic")
	mode := r.FormValue("hub.mode")
	secret := r.FormValue("hub.secret")
	denialURL, URLErr := url.Parse(callback)
	log.Printf("Received subscription: callback=%s topic=%s mode=%s", callback, topic, mode)

	if URLErr != nil ||
		callback == "" ||
		topic == "" ||
		(mode != "subscribe" && mode != "unsubscribe") ||
		(mode == "subscribe" && (secret == "" || len(secret) > 199)) {
		http.Error(w, "Invalid subscription request", http.StatusBadRequest)
		if URLErr == nil {
			sendDenial(denialURL, topic)
		} else {
			log.Printf("invalid callback URL: %v", URLErr)
		}
		return
	}
	w.WriteHeader(http.StatusAccepted)
	key := subscriptionKey{Callback: callback, Topic: topic}
	if mode == "subscribe" {
		go verifySub(key, h, secret, denialURL)
	}
	if mode == "unsubscribe" {
		h.mu.Lock()
		delete(h.subscribers, key)
		h.mu.Unlock()
	}
}

func verifySub(key subscriptionKey, hub *Hub, secret string, denialURL *url.URL) {
	challenge := generateRandomString(ChallengeLength)
	format := "%s?hub.mode=subscribe&hub.topic=%s&hub.challenge=%s"
	verifyURL := fmt.Sprintf(format, key.Callback, key.Topic, challenge)
	resp, err := http.Get(verifyURL)
	if err != nil {
		log.Printf("Failed to reach subscriber on verification: %v", err)
		return
	}
	//close body, free resources
	defer resp.Body.Close()

	body, bodyErr := io.ReadAll(resp.Body)
	//trimming whitespaces in body for leniency
	if resp.StatusCode != http.StatusOK ||
		bodyErr != nil ||
		strings.TrimSpace(string(body)) != challenge {
		log.Printf("Intent verification failed: %v", err)
		sendDenial(denialURL, key.Topic)
		return
	}
	hub.mu.Lock()
	hub.subscribers[key] = secret
	hub.mu.Unlock()
}

func sendDenial(denialURL *url.URL, topic string) {
	u := *denialURL
	q := u.Query()
	q.Set("hub.mode", "denied")
	q.Set("hub.topic", topic)
	u.RawQuery = q.Encode()
	_, err := http.Get(u.String())
	if err != nil {
		log.Printf("Failed to send denial get request: %v", err)
	}
}

func (h *Hub) HandlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Printf("Received publish request")
	data := map[string]string{
		"message": "Hello from WebSub Hub!",
	}
	body, _ := json.Marshal(data)

	h.mu.Lock()
	for subKey, secret := range h.subscribers {
		go postToSubscriber(subKey, body, secret)
	}
	h.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func postToSubscriber(subKey subscriptionKey, body []byte, secret string) {
	req, err := http.NewRequest("POST", subKey.Callback, bytes.NewReader(body))
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
