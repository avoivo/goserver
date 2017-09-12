package stateToken

import "testing"

const secret = "My Secret"

func TestShouldGenerate(t *testing.T) {
	m, err := New(secret)
	if err != nil {
		t.Error(err)
		return
	}

	generatedToken, err := m.Generate()
	if err != nil {
		t.Error(err)
		return
	}

	if len(generatedToken) == 0 {
		t.Error("generatedToken is empty")
		return
	}
}

func TestShouldVerify(t *testing.T) {
	m, err := New(secret)
	if err != nil {
		t.Error(err)
		return
	}

	generatedToken, err := m.Generate()
	if err != nil {
		t.Error(err)
		return
	}

	valid, err := m.Verify(generatedToken)
	if err != nil {
		t.Error(err)
		return
	}

	if !valid {
		t.Error("generatedToken is not valid")
		return
	}
}
