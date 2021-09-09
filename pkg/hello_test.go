package hello

import "testing"

func TestHello(t *testing.T) {
	t.Parallel()
	want := "Hello, RedHatter. Welcome!"
	if got := Hello(); got != want {
		t.Errorf("Hello() = %q, want %q", got, want)
	}
}
