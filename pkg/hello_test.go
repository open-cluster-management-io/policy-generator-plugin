package hello

import "testing"

func TestHello(t *testing.T) {
	t.Parallel()
	want := "Hello, RedHater. Welcome!"
	if got := Hello(); got != want {
		t.Errorf("Hello() = %q, want %q", got, want)
	}
}
