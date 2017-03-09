package jwt

import (
	"sync"
	"time"
	"github.com/pkg/errors"
)

type tokenManager struct {
	bannedTokens map[string]time.Time
	m sync.Mutex
	destroyed bool
}

// For in-package jobs
var GlobalStorage *tokenManager


// Creates
func NewStorage(d time.Duration) *tokenManager {
	r := new(tokenManager)
	r.bannedTokens = make(map[string]time.Time)
	r.destroyed = false
	ticker := time.NewTicker(d)
	go r.checkAndClearStorage(ticker)
	return r
}

func (m *tokenManager) checkAndClearStorage(ticker *time.Ticker) {
	for range ticker.C {
		if m.destroyed {
			break
		}
		m.m.Lock()
		for k, v := range m.bannedTokens {
			if time.Now().After(v) {
				delete(m.bannedTokens, k)
			}
		}
		m.m.Unlock()
	}
}

// Add new value to Storage
func (m *tokenManager) Ban(what string, expires time.Time) error {
	m.m.Lock()
	if _, ok := m.bannedTokens[what]; ok {
		m.m.Unlock()
		return errors.New("Already banned")
	}
	m.bannedTokens[what] = expires
	m.m.Unlock()
	return nil
}

// true means "what" was banned, false - is clear
func (m *tokenManager) IsBanned(what string) bool {
	m.m.Lock()
	_, ok := m.bannedTokens[what]
	m.m.Unlock()
	return ok
}

func (m *tokenManager) Destroy() {
	m.m.Lock()
	m.destroyed = true
	m.m.Unlock()
}