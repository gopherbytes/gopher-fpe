package transform

import (
	"errors"
	"fmt"
	"testing"
)

func TestApplyString(t *testing.T) {
	result, err := Apply(
		"hello",
		func(value string) (string, error) {
			return "enc:" + value, nil
		},
	)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	got, ok := result.(string)
	if !ok {
		t.Fatalf("expected string result, got %T", result)
	}

	if got != "enc:hello" {
		t.Fatalf("expected %q, got %q", "enc:hello", got)
	}
}

func TestApplySlice(t *testing.T) {
	input := []any{
		"one",
		"two",
		"three",
	}

	result, err := Apply(
		input,
		func(value string) (string, error) {
			return "enc:" + value, nil
		},
	)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	got, ok := result.([]any)
	if !ok {
		t.Fatalf("expected []any result, got %T", result)
	}

	if len(got) != len(input) {
		t.Fatalf(
			"expected result length %d, got %d",
			len(input),
			len(got),
		)
	}

	expected := []string{
		"enc:one",
		"enc:two",
		"enc:three",
	}

	for i, expectedValue := range expected {
		value, ok := got[i].(string)
		if !ok {
			t.Fatalf(
				"expected result[%d] to be string, got %T",
				i,
				got[i],
			)
		}

		if value != expectedValue {
			t.Fatalf(
				"expected result[%d] %q, got %q",
				i,
				expectedValue,
				value,
			)
		}
	}
}

func TestApplyMap(t *testing.T) {
	input := map[string]any{
		"first":  "one",
		"second": "two",
	}

	result, err := Apply(
		input,
		func(value string) (string, error) {
			return "enc:" + value, nil
		},
	)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	got, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any result, got %T", result)
	}

	if got["first"] != "enc:one" {
		t.Fatalf(
			"expected first=%q, got %#v",
			"enc:one",
			got["first"],
		)
	}

	if got["second"] != "enc:two" {
		t.Fatalf(
			"expected second=%q, got %#v",
			"enc:two",
			got["second"],
		)
	}
}

func TestApplyNestedData(t *testing.T) {
	input := map[string]any{
		"id": "123",
		"items": []any{
			"abc",
			map[string]any{
				"value": "xyz",
			},
		},
	}

	result, err := Apply(
		input,
		func(value string) (string, error) {
			return "[" + value + "]", nil
		},
	)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	got, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any result, got %T", result)
	}

	if got["id"] != "[123]" {
		t.Fatalf("expected id to be transformed, got %#v", got["id"])
	}

	items, ok := got["items"].([]any)
	if !ok {
		t.Fatalf("expected items to be []any, got %T", got["items"])
	}

	if items[0] != "[abc]" {
		t.Fatalf(
			"expected items[0]=%q, got %#v",
			"[abc]",
			items[0],
		)
	}

	nested, ok := items[1].(map[string]any)
	if !ok {
		t.Fatalf(
			"expected items[1] to be map[string]any, got %T",
			items[1],
		)
	}

	if nested["value"] != "[xyz]" {
		t.Fatalf(
			"expected nested value=%q, got %#v",
			"[xyz]",
			nested["value"],
		)
	}
}

func TestApplyLeavesNonStringsUnchanged(t *testing.T) {
	input := map[string]any{
		"number": 123,
		"bool":   true,
		"nil":    nil,
	}

	result, err := Apply(
		input,
		func(value string) (string, error) {
			return "enc:" + value, nil
		},
	)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	got, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any result, got %T", result)
	}

	if got["number"] != 123 {
		t.Fatalf("expected number to remain unchanged, got %#v", got["number"])
	}

	if got["bool"] != true {
		t.Fatalf("expected bool to remain unchanged, got %#v", got["bool"])
	}

	if got["nil"] != nil {
		t.Fatalf("expected nil to remain unchanged, got %#v", got["nil"])
	}
}

func TestApplyPropagatesStringError(t *testing.T) {
	expectedErr := errors.New("transform failed")

	_, err := Apply(
		"hello",
		func(value string) (string, error) {
			return "", expectedErr
		},
	)

	if !errors.Is(err, expectedErr) {
		t.Fatalf(
			"expected error %v, got %v",
			expectedErr,
			err,
		)
	}
}

func TestApplySlicePropagatesError(t *testing.T) {
	expectedErr := errors.New("bad value")

	input := []any{
		"one",
		"bad",
		"three",
	}

	_, err := Apply(
		input,
		func(value string) (string, error) {
			if value == "bad" {
				return "", expectedErr
			}

			return "enc:" + value, nil
		},
	)

	if !errors.Is(err, expectedErr) {
		t.Fatalf(
			"expected error %v, got %v",
			expectedErr,
			err,
		)
	}
}

func TestApplyMapPropagatesError(t *testing.T) {
	expectedErr := errors.New("bad value")

	input := map[string]any{
		"first":  "one",
		"second": "bad",
	}

	_, err := Apply(
		input,
		func(value string) (string, error) {
			if value == "bad" {
				return "", expectedErr
			}

			return "enc:" + value, nil
		},
	)

	if !errors.Is(err, expectedErr) {
		t.Fatalf(
			"expected error %v, got %v",
			expectedErr,
			err,
		)
	}
}

func TestApplyLargeSlice(t *testing.T) {
	const count = 100

	input := make([]any, count)

	for i := range count {
		input[i] = fmt.Sprintf("value-%d", i)
	}

	result, err := Apply(
		input,
		func(value string) (string, error) {
			return "enc:" + value, nil
		},
	)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	got, ok := result.([]any)
	if !ok {
		t.Fatalf("expected []any result, got %T", result)
	}

	if len(got) != count {
		t.Fatalf(
			"expected %d results, got %d",
			count,
			len(got),
		)
	}

	for i := range count {
		expected := fmt.Sprintf("enc:value-%d", i)

		value, ok := got[i].(string)
		if !ok {
			t.Fatalf(
				"expected result[%d] to be string, got %T",
				i,
				got[i],
			)
		}

		if value != expected {
			t.Fatalf(
				"expected result[%d]=%q, got %q",
				i,
				expected,
				value,
			)
		}
	}
}
