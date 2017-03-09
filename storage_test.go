package jwt

import (
	"testing"
	"time"
)

func TestStorage(t *testing.T)  {
	GlobalStorage = NewStorage(time.Second * 10)
	var secret = "this is the secret"
	algorithm := HmacSha256(secret)
	cl_time1 := time.Now().Add(time.Second * 10)
	claim := NewClaim()
	claim.Set("fruit", "apple")
	claim.SetTime("exp", cl_time1)

	token1, err := algorithm.Encode(claim)
	if err != nil {
		t.Log(err)
		t.Fatal(err)
	}

	cl_time2 := time.Now().Add(time.Second * 2)
	claim = NewClaim()
	claim.Set("fruit", "pineapple")
	claim.SetTime("exp", cl_time2)

	token2, err := algorithm.Encode(claim)
	if err != nil {
		t.Log(err)
		t.Fatal(err)
	}

	cl_time3 := time.Now().Add(time.Hour)
	claim = NewClaim()
	claim.Set("fruit", "orange")
	claim.SetTime("exp", cl_time3)

	token3, err := algorithm.Encode(claim)
	if err != nil {
		t.Fatal(err)
	}

	err = algorithm.Validate(token1)
	if err != nil {
		t.Log(err)
		t.Fatal(err)
	}
	err = algorithm.Validate(token2)
	if err != nil {
		t.Log(err)
		t.Fatal(err)
	}
	err = algorithm.Validate(token3)
	if err != nil {
		t.Log(err)
		t.Fatal(err)
	}

	GlobalStorage.Ban(token1, cl_time1)
	GlobalStorage.Ban(token2, cl_time2)

	// First is banned for 10s, should return "This token is banned"
	err = algorithm.Validate(token1)
	// !!! ==
	if err == nil {
		t.Fatal(err)
	}
	// Second is banned for 2s, should return "This token is banned"
	err = algorithm.Validate(token2)
	// !!! ==
	if err == nil {
		t.Fatal(err)
	}
	// Third is not banned, should return nil
	err = algorithm.Validate(token3)
	// !!! !=
	if err != nil {
		t.Fatal(err)
	}

	// Wait some time
	time.Sleep(time.Second*5)

	// First still banned
	err = algorithm.Validate(token1)
	// !!! ==
	if err == nil {
		t.Fatal(err)
	}
	// Second expired
	err = algorithm.Validate(token2)
	// !!! ==
	if err == nil {
		t.Fatal(err)
	}
	// Third valid
	err = algorithm.Validate(token3)
	// !!! !=
	if err != nil {
		t.Fatal(err)
	}

	// Wait, Global storage SHOULD clear First and Second tokens
	time.Sleep(time.Second * 16)

	if GlobalStorage.IsBanned(token1) {
		t.Fatal("token1 is banned, but should not")
	}

	if GlobalStorage.IsBanned(token2) {
		t.Fatal("token2 is banned, but should not")
	}

	GlobalStorage.Ban(token3, cl_time3)

	if !GlobalStorage.IsBanned(token3) {
		t.Fatal("token3 is not banned, but should be")
	}
}