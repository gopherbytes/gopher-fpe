package transform

import "sync"

const maxParallel = 64

func Apply(data any, fn func(string) (string, error)) (any, error) {
	switch v := data.(type) {
	case string:
		return fn(v)

	case []any:
		return transformSlice(v, fn)

	case map[string]any:
		return transformMap(v, fn)

	default:
		return data, nil
	}
}

func transformSlice(items []any, fn func(string) (string, error)) ([]any, error) {
	n := len(items)
	if n == 0 {
		return items, nil
	}

	if n <= 4 {
		out := make([]any, n)

		for i, elem := range items {
			result, err := Apply(elem, fn)
			if err != nil {
				return nil, err
			}

			out[i] = result
		}

		return out, nil
	}

	out := make([]any, n)
	errs := make([]error, n)

	sem := make(chan struct{}, maxParallel)

	var wg sync.WaitGroup

	for i, elem := range items {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, value any) {
			defer func() {
				<-sem
				wg.Done()
			}()

			result, err := Apply(value, fn)
			if err != nil {
				errs[idx] = err
				return
			}

			out[idx] = result
		}(i, elem)
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

func transformMap(values map[string]any, fn func(string) (string, error)) (map[string]any, error) {
	n := len(values)
	if n == 0 {
		return values, nil
	}

	if n <= 4 {
		out := make(map[string]any, n)

		for key, elem := range values {
			result, err := Apply(elem, fn)
			if err != nil {
				return nil, err
			}

			out[key] = result
		}

		return out, nil
	}

	type pair struct {
		key   string
		value any
	}

	pairs := make([]pair, 0, n)

	for key, value := range values {
		pairs = append(pairs, pair{
			key:   key,
			value: value,
		})
	}

	results := make([]any, n)
	errs := make([]error, n)

	sem := make(chan struct{}, maxParallel)

	var wg sync.WaitGroup

	for i, p := range pairs {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, value any) {
			defer func() {
				<-sem
				wg.Done()
			}()

			result, err := Apply(value, fn)
			if err != nil {
				errs[idx] = err
				return
			}

			results[idx] = result
		}(i, p.value)
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	out := make(map[string]any, n)

	for i, p := range pairs {
		out[p.key] = results[i]
	}

	return out, nil
}
