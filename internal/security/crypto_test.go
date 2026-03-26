package security

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	c, err := NewStringCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	in := "my-secret"
	enc, err := c.Encrypt(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %q want %q", out, in)
	}
}
