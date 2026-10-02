// Package httpconfig validates the HTTP duration syntax shared by admission and the data plane.
package httpconfig

import (
	"errors"
	"regexp"
	"time"
)

var durationPattern = regexp.MustCompile(`^([0-9]{1,5}(h|m|s|ms)){1,4}$`)

// ParseDuration accepts Gateway API duration syntax. An absent value is handled by the caller;
// explicit zero disables its timer. Errors deliberately exclude the supplied configuration.
func ParseDuration(value string) (time.Duration, error) {
	if len(value) > 32 || !durationPattern.MatchString(value) {
		return 0, errors.New("invalid HTTP duration")
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return 0, errors.New("invalid HTTP duration")
	}
	return d, nil
}
