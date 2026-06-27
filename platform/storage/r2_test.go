package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeKey(t *testing.T) {
	got, err := normalizeKey("avatars/user.png")
	require.NoError(t, err)
	require.Equal(t, "avatars/user.png", got)

	_, err = normalizeKey("../escape")
	require.Error(t, err)

	_, err = normalizeKey("")
	require.Error(t, err)
}

func TestR2URL(t *testing.T) {
	withCDN := &r2Store{bucket: "my-bucket", publicBase: "https://cdn.example.com"}
	require.Equal(t, "https://cdn.example.com/avatars/a.png", withCDN.URL("avatars/a.png"))

	noCDN := &r2Store{bucket: "my-bucket"}
	require.Equal(t, "r2://my-bucket/file.txt", noCDN.URL("file.txt"))
}

func TestR2URLRejectsInvalidKey(t *testing.T) {
	s := &r2Store{bucket: "my-bucket"}
	require.Empty(t, s.URL("../bad"))
}

func TestPutRejectsInvalidKey(t *testing.T) {
	s := &r2Store{bucket: "my-bucket", client: nil}
	err := s.Put(t.Context(), "../bad", strings.NewReader("x"), PutOptions{})
	require.Error(t, err)
}
