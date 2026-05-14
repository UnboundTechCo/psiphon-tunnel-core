/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package parameters

import "testing"

func TestFrontedMeekDialOverrideSpecs(t *testing.T) {

	overrides := FrontedMeekDialOverrideSpecs{
		&FrontedMeekDialOverride{
			OverrideID:                     "fastly",
			MatchFrontingProviderIDRegexes: []string{"(?i)fastly"},
			MatchDialAddressRegexes:        []string{`\.fastly\.net$`},
			DialAddresses:                  []string{"pypi.org"},
			SNIServerName:                  "pypi.org",
			VerifyServerNames:              []string{"pypi.org", "fastly.com"},
			VerifyPins:                     []string{"pin"},
			ALPNProtocols:                  []string{"h2", "http/1.1"},
		},
		&FrontedMeekDialOverride{
			OverrideID:              "fallback",
			MatchDialAddressRegexes: []string{".*"},
			DialAddresses:           []string{"fallback.example.org"},
			VerifyServerNames:       []string{"fallback.example.org"},
		},
	}

	err := overrides.Validate(nil)
	if err != nil {
		t.Fatalf("Validate failed: %s", err)
	}

	override, ok, err := overrides.SelectParameters(
		"FASTLY", "example.fastly.net", "front.example")
	if err != nil {
		t.Fatalf("SelectParameters failed: %s", err)
	}
	if !ok {
		t.Fatalf("missing selected override")
	}

	if override.OverrideID != "fastly" ||
		override.DialAddress != "pypi.org" ||
		override.SNIServerName != "pypi.org" ||
		len(override.VerifyServerNames) != 2 ||
		override.VerifyServerNames[0] != "pypi.org" ||
		len(override.VerifyPins) != 1 ||
		override.VerifyPins[0] != "pin" ||
		len(override.ALPNProtocols) != 2 ||
		override.ALPNProtocols[0] != "h2" {
		t.Fatalf("unexpected override: %+v", override)
	}

	override, ok, err = overrides.SelectParameters(
		"AKAMAI", "example.fastly.net", "front.example")
	if err != nil {
		t.Fatalf("SelectParameters failed: %s", err)
	}
	if !ok {
		t.Fatalf("missing fallback override")
	}
	if override.OverrideID != "fallback" ||
		override.DialAddress != "fallback.example.org" {
		t.Fatalf("unexpected fallback override: %+v", override)
	}

	strictOverrides := FrontedMeekDialOverrideSpecs{overrides[0]}
	_, ok, err = strictOverrides.SelectParameters(
		"AKAMAI", "example.fastly.net", "front.example")
	if err != nil {
		t.Fatalf("SelectParameters failed: %s", err)
	}
	if ok {
		t.Fatalf("unexpected selected override")
	}
}

func TestFrontedMeekDialOverrideSpecsSelectCandidateParameters(t *testing.T) {

	overrides := FrontedMeekDialOverrideSpecs{
		&FrontedMeekDialOverride{
			OverrideID:              "preferred",
			MatchDialAddressRegexes: []string{".*"},
			DialAddresses:           []string{"preferred-1.example.org", "preferred-2.example.org"},
			VerifyServerNames:       []string{"preferred.example.org"},
		},
		&FrontedMeekDialOverride{
			OverrideID:              "fallback",
			MatchDialAddressRegexes: []string{".*"},
			DialAddresses:           []string{"fallback.example.org"},
			VerifyServerNames:       []string{"fallback.example.org"},
		},
	}

	expected := []struct {
		candidateNumber int
		overrideID      string
		dialAddress     string
	}{
		{0, "preferred", "preferred-1.example.org"},
		{1, "preferred", "preferred-2.example.org"},
		{2, "fallback", "fallback.example.org"},
		{3, "preferred", "preferred-1.example.org"},
	}

	for _, expectedCandidate := range expected {
		override, ok, err := overrides.SelectCandidateParameters(
			"CDN", "front.example", "host.example",
			expectedCandidate.candidateNumber)
		if err != nil {
			t.Fatalf("SelectCandidateParameters failed: %s", err)
		}
		if !ok {
			t.Fatalf("missing selected override")
		}
		if override.OverrideID != expectedCandidate.overrideID ||
			override.DialAddress != expectedCandidate.dialAddress {
			t.Fatalf(
				"candidate %d selected %+v, expected %s/%s",
				expectedCandidate.candidateNumber,
				override,
				expectedCandidate.overrideID,
				expectedCandidate.dialAddress)
		}
	}
}

func TestFrontedMeekDialOverrideSpecsValidation(t *testing.T) {

	testCases := []struct {
		name      string
		overrides FrontedMeekDialOverrideSpecs
	}{
		{
			name: "missing match",
			overrides: FrontedMeekDialOverrideSpecs{
				&FrontedMeekDialOverride{
					DialAddresses: []string{"example.com"},
				},
			},
		},
		{
			name: "invalid regex",
			overrides: FrontedMeekDialOverrideSpecs{
				&FrontedMeekDialOverride{
					MatchDialAddressRegexes: []string{"["},
					DialAddresses:           []string{"example.com"},
				},
			},
		},
		{
			name: "pins without verify names",
			overrides: FrontedMeekDialOverrideSpecs{
				&FrontedMeekDialOverride{
					MatchDialAddressRegexes: []string{"example"},
					DialAddresses:           []string{"example.com"},
					VerifyPins:              []string{"pin"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		err := testCase.overrides.Validate(nil)
		if err == nil {
			t.Fatalf("unexpected success for %s", testCase.name)
		}
	}
}
