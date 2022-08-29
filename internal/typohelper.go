package internal

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// addFieldNotFoundHelp adds help text to errors that occur when the input config
// has a field that is not present in the Config struct (eg a typo), to assist
// the user in debugging the problem. If the input error was not from a missing
// field, then it is returned unchanged.
func addFieldNotFoundHelp(err error) error {
	re := regexp.MustCompile(`field (\S*) not found in type (\S*)`)

	repl := func(line string) string {
		match := re.FindStringSubmatch(line)

		fieldType := reflect.TypeOf(Plugin{})
		fieldTag := "PolicyGenerator"

		if match[2] != fieldType.String() {
			// Search the right type, if it's not the top-level object.
			fieldType, fieldTag = findNestedType(fieldType, match[2], "")
		}

		msg := fmt.Sprintf("field %v found but not defined", match[1])

		if fieldTag != "" {
			msg += fmt.Sprintf(" in type %v", fieldTag)
		}

		suggestion := autocorrectField(match[1], fieldType)
		if suggestion != "" {
			msg += fmt.Sprintf(" - did you mean '%v'?", suggestion)
		}

		return msg
	}

	helpMsg := re.ReplaceAllStringFunc(err.Error(), repl)

	if helpMsg == err.Error() {
		// Error was unchanged, return the original to preserve the type
		return err
	}

	return errors.New(helpMsg)
}

// autocorrectField returns the field in the containingType which most closely
// matches the input badField. It will return an empty string if no match can
// be found with sufficient confidence.
func autocorrectField(badField string, containingType reflect.Type) string {
	if containingType == nil || containingType.Kind() != reflect.Struct {
		return ""
	}

	matcher := difflib.NewMatcher(strings.Split(badField, ""), []string{""})
	bestRatio := 0.85 // require 85% or better match
	bestMatch := ""

	// iterate over all fields in the struct that have a yaml tag.
	for _, field := range reflect.VisibleFields(containingType) {
		yamlTag := strings.SplitN(field.Tag.Get("yaml"), ",", 2)[0]
		if yamlTag == "" {
			continue
		}

		matcher.SetSeq2(strings.Split(yamlTag, ""))

		ratio := matcher.Ratio()
		if ratio > bestRatio {
			bestRatio = ratio
			bestMatch = yamlTag
		}
	}

	return bestMatch
}

// findNestedType searches through the given type and nested types (recursively)
// for a type matching the wanted string. It will return the matching type if
// found, or nil if not found. It will also return the yaml tag of the field
// where the type was found.
func findNestedType(baseType reflect.Type, want string, tag string) (reflect.Type, string) {
	if baseType.String() == want {
		return baseType, tag
	}

	if baseType.Kind() == reflect.Array || baseType.Kind() == reflect.Slice || baseType.Kind() == reflect.Map {
		return findNestedType(baseType.Elem(), want, tag)
	}

	if baseType.Kind() != reflect.Struct {
		return nil, ""
	}

	// iterate over all fields in the struct that have a yaml tag.
	for _, field := range reflect.VisibleFields(baseType) {
		yamlTag := strings.SplitN(field.Tag.Get("yaml"), ",", 2)[0]

		if field.Type.String() == want {
			return field.Type, yamlTag
		}

		deeperType, deeperTag := findNestedType(field.Type, want, yamlTag)
		if deeperType != nil {
			return deeperType, deeperTag
		}
	}

	return nil, ""
}
