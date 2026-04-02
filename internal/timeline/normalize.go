package timeline

import "time"

// SyntheticTime returns a far-future time used for sorting synthetic events.
// All synthetic events share the same base; they are differentiated by synthPriority.
var syntheticBase = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// IsSynthetic returns true if the time type indicates a non-actual timestamp.
func IsSynthetic(timeType string) bool {
	return timeType == "synthetic"
}

// NormalizeTimeType returns "actual" or "synthetic" based on the presence of a
// real timestamp.
func NormalizeTimeType(t time.Time) string {
	if t.IsZero() || t.Equal(syntheticBase) {
		return "synthetic"
	}
	return "actual"
}
