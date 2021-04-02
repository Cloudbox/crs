package util

import "strings"

func StringListContains(list []string, value string) bool {
	for _, v := range list {
		if strings.EqualFold(v, value) {
			return true
		}
	}

	return false
}
