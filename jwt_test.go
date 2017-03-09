package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var secret = "this is the secret"
var algorithms = []Algorithm{
	HmacSha256(secret),
	HmacSha384(secret),
	HmacSha512(secret),
}

func RunTest(t *testing.T, command func(Algorithm)) {
	for _, algorithm := range algorithms {
		command(algorithm)
	}
}

func TestEncodeAndValidateToken(t *testing.T) {
	RunTest(t, func(algorithm Algorithm) {
		GlobalStorage = NewStorage(time.Hour)
		payload := NewClaim()
		payload.SetTime("nbf", time.Now().Add(time.Duration(-1) * time.Hour))
		payload.SetTime("exp", time.Now().Add(time.Duration(100) * time.Hour))

		token, err := algorithm.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}

		err = algorithm.Validate(token)
		if err != nil {
			t.Fatal(err)
		}
		GlobalStorage.Destroy()
	})
}

func TestValidateToken(t *testing.T) {
	RunTest(t, func(algorithm Algorithm) {
		GlobalStorage = NewStorage(time.Hour)
		payload := NewClaim()
		err := json.Unmarshal([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`), &payload)
		if err != nil {
			t.Fatal(err)
		}

		token, err := algorithm.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}

		tokenComponents := strings.Split(token, ".")

		invalidSignature := "cBab30RMHrHDcEfxjoYZgeFONFh7Hg"
		invalidToken := tokenComponents[0] + "." + tokenComponents[1] + "." + invalidSignature

		err = algorithm.Validate(invalidToken)
		if err == nil {
			t.Fatal(err)
		}
		GlobalStorage.Destroy()
	})
}

func TestVerifyTokenExp(t *testing.T) {
	RunTest(t, func(algorithm Algorithm) {
		GlobalStorage = NewStorage(time.Hour)
		payload := NewClaim()
		payload.Set("exp", fmt.Sprintf("%d", time.Now().Add(-1*time.Hour).Unix()))

		err := json.Unmarshal([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`), &payload)
		if err != nil {
			t.Fatal(err)
		}

		token, err := algorithm.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}

		err = algorithm.Validate(token)
		if err == nil {
			t.Fatal(err)
		}
		GlobalStorage.Destroy()
	})
}

func TestVerifyTokenNbf(t *testing.T) {
	RunTest(t, func(algorithm Algorithm) {
		GlobalStorage = NewStorage(time.Hour)
		payload := NewClaim()
		payload.SetTime("nbf", time.Now().Add(time.Duration(1) * time.Hour))

		err := json.Unmarshal([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`), &payload)
		if err != nil {
			t.Fatal(err)
		}

		token, err := algorithm.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}

		err = algorithm.Validate(token)
		if err == nil {
			t.Fatal(err)
		}
		GlobalStorage.Destroy()
	})
}
