package vals

import (
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

func IsValidEmail(email string) bool {
	exp := `^(?!\.)(?!.*\.\.)([a-z0-9_'+\-\.]*)[a-z0-9_+-]@([a-z0-9][a-z0-9\-]*\.)+[a-z]{2,}$`
	re := regexp.MustCompile(exp)
	return re.MatchString(email)
}

func NormalizeEmail(email string) string {
	email = strings.ToLower(email)
	email = norm.NFKC.String(email)
	email = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', '\b', '\x00':
			return -1
		}
		return r
	}, email)
	return email
}
