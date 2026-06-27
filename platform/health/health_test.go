package health

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubChecker struct {
	name string
	err  error
}

func (s stubChecker) Name() string { return s.name }

func (s stubChecker) Check(context.Context) error { return s.err }

func TestRunAndAllOK(t *testing.T) {
	statuses := Run(context.Background(),
		stubChecker{name: "ok"},
		stubChecker{name: "bad", err: errors.New("down")},
	)
	require.Len(t, statuses, 2)
	require.True(t, statuses[0].OK)
	require.False(t, statuses[1].OK)
	require.False(t, AllOK(statuses))
	require.True(t, AllOK([]Status{{OK: true}}))
}
