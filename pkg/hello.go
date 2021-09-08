package hello

import "fmt"

func Print(name string) string {
	return fmt.Sprintf("Hello, %v. Welcome!", name)
}

func Hello() string {
	return Print("RedHater")
}
