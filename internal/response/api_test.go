package response

import "testing"

func TestRenderMessage(t *testing.T) {
	got := RenderMessage("Hello {0}, you have {1} new messages in your {2} bucket.", "Alice", 5, "inbox")
	want := "Hello Alice, you have 5 new messages in your inbox bucket."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
