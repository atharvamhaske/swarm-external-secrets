package jwtsource

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Source interface {
	Token(ctx context.Context) (string, error)
}

type Static struct {
	Value string
}

func (s Static) Token(context.Context) (string, error) {
	token := strings.TrimSpace(s.Value)
	if token == "" {
		return "", fmt.Errorf("static jwt is empty")
	}
	return token, nil
}

type File struct {
	Path string
}

func (f File) Token(context.Context) (string, error) {
	data, err := os.ReadFile(f.Path) // #nosec G304 -- path is explicit plugin configuration.
	if err != nil {
		return "", fmt.Errorf("read jwt file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("jwt file is empty")
	}

	return token, nil
}

type Chain struct {
	Sources []Source
}

func (c Chain) Token(ctx context.Context) (string, error) {
	var errs []error
	for _, source := range c.Sources {
		if source == nil {
			continue
		}

		token, err := source.Token(ctx)
		if err == nil {
			return token, nil
		}
		errs = append(errs, err)
	}

	if len(errs) == 0 {
		return "", fmt.Errorf("no jwt sources configured")
	}

	return "", errors.Join(errs...)
}
