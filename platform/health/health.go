package health

import "context"

// Checker verifies a dependency is reachable for health endpoints.
type Checker interface {
	Name() string
	Check(ctx context.Context) error
}

// Status is the result of a health check.
type Status struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// Run executes all checkers and returns per-component status.
func Run(ctx context.Context, checkers ...Checker) []Status {
	out := make([]Status, 0, len(checkers))
	for _, chk := range checkers {
		if chk == nil {
			continue
		}
		st := Status{Name: chk.Name(), OK: true}
		if err := chk.Check(ctx); err != nil {
			st.OK = false
			st.Message = err.Error()
		}
		out = append(out, st)
	}
	return out
}

// AllOK reports whether every status entry is healthy.
func AllOK(statuses []Status) bool {
	for _, s := range statuses {
		if !s.OK {
			return false
		}
	}
	return true
}
