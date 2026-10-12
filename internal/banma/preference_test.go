package banma

import "testing"

func TestServerObservedSecurityPreferenceCannotBeChangedThroughCookies(t *testing.T) {
	r := &Runner{}
	r.observeSecurityPreference(Capture{Headers: [][]string{{"Set-Cookie", "security=impossible; Path=/"}}})
	for _, headers := range []interface{}{map[string]string{"Cookie": "security=low"}, `{"Cookie":"security=low"}`, "Cookie: security=%6c%6f%77", map[string]string{"Cookie": "security="}} {
		if r.checkSecurityPreference(map[string]interface{}{"headers": headers}) == nil {
			t.Fatal("security preference change accepted")
		}
	}
	if r.checkSecurityPreference(map[string]interface{}{"cookies": "security=impossible; PHPSESSID=fixture"}) != nil {
		t.Fatal("actual server preference denied")
	}
	if r.checkSecurityPreference(map[string]interface{}{"headers": map[string]string{"X-Observation": "security=low"}}) != nil {
		t.Fatal("non-cookie observation blocked")
	}
	r.observeSecurityPreference(Capture{Headers: [][]string{{"Set-Cookie", "security=low"}}})
	if r.budget.SecurityCookie != "impossible" {
		t.Fatal("observed baseline silently replaced")
	}
}
