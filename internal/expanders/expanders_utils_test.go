package expanders

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	t.Helper()

	if a != b {
		t.Fatal(cmp.Diff(a, b))
	}
}

func assertReflectEqual(t *testing.T, a interface{}, b interface{}) {
	t.Helper()

	if !reflect.DeepEqual(a, b) {
		t.Fatal(cmp.Diff(a, b))
	}
}
