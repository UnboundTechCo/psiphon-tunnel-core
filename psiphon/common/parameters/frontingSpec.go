/*
 * Copyright (c) 2021, Psiphon Inc.
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

import (
	"net"
	"regexp"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
)

// FrontingSpecs is a list of domain fronting specs.
type FrontingSpecs []*FrontingSpec

// FrontingSpec specifies a domain fronting configuration, to be used with
// MeekConn and MeekModePlaintextRoundTrip. In MeekModePlaintextRoundTrip, the
// fronted origin is an arbitrary web server, not a Psiphon server. This
// MeekConn mode requires HTTPS and server certificate validation:
// VerifyServerName is required; VerifyPins is recommended. See also
// psiphon.MeekConfig and psiphon.MeekConn.
//
// FrontingSpec.Addresses supports the functionality of both
// ServerEntry.MeekFrontingAddressesRegex and
// ServerEntry.MeekFrontingAddresses: multiple candidates are supported, and
// each candidate may be a regex, or a static value (with regex syntax).
type FrontingSpec struct {

	// Optional/new fields use omitempty to minimize tactics tag churn.

	FrontingProviderID string
	Transports         protocol.FrontingTransports `json:",omitempty"`
	Addresses          []string
	DisableSNI         bool     `json:",omitempty"`
	SkipVerify         bool     `json:",omitempty"`
	VerifyServerName   string   `json:",omitempty"`
	VerifyPins         []string `json:",omitempty"`
	Host               string
}

// FrontedMeekDialOverrideSpecs is a list of fronted meek outer-dial override
// rules. These rules are applied after the server entry fronting address and
// host are selected and only affect the client-to-front TLS connection.
type FrontedMeekDialOverrideSpecs []*FrontedMeekDialOverride

// FrontedMeekDialOverride conditionally replaces the fronted meek TLS dial
// endpoint and related TLS settings while preserving the meek Host header.
type FrontedMeekDialOverride struct {

	// Optional/new fields use omitempty to minimize tactics tag churn.

	OverrideID string `json:",omitempty"`

	MatchFrontingProviderIDRegexes []string `json:",omitempty"`
	MatchDialAddressRegexes        []string `json:",omitempty"`
	MatchHostHeaderRegexes         []string `json:",omitempty"`

	DialAddresses     []string
	DisableSNI        bool     `json:",omitempty"`
	SNIServerName     string   `json:",omitempty"`
	VerifyServerNames []string `json:",omitempty"`
	VerifyPins        []string `json:",omitempty"`
	ALPNProtocols     []string `json:",omitempty"`
	TLSProfile        string   `json:",omitempty"`
}

// FrontedMeekDialOverrideParameters is the selected override state returned by
// FrontedMeekDialOverrideSpecs.SelectParameters.
type FrontedMeekDialOverrideParameters struct {
	OverrideID        string
	DialAddress       string
	SNIServerName     string
	VerifyServerNames []string
	VerifyPins        []string
	ALPNProtocols     []string
	TLSProfile        string
}

// SelectParameters selects fronting parameters from the given FrontingSpecs,
// first selecting a spec at random. SelectParameters is similar to
// psiphon.selectFrontingParameters, which operates on server entries.
//
// The return values are:
// - Dial Address (domain or IP address)
// - Transport (e.g., protocol.FRONTING_TRANSPORT_HTTPS)
// - SNI (which may be transformed; unless it is "", which indicates omit SNI)
// - VerifyServerName (see psiphon.CustomTLSConfig)
// - VerifyPins (see psiphon.CustomTLSConfig)
// - Host (Host header value)
func (specs FrontingSpecs) SelectParameters() (
	string, string, string, string, string, []string, string, error) {

	if len(specs) == 0 {
		return "", "", "", "", "", nil, "", errors.TraceNew("missing fronting spec")
	}

	spec := specs[prng.Intn(len(specs))]

	if len(spec.Addresses) == 0 {
		return "", "", "", "", "", nil, "", errors.TraceNew("missing fronting address")
	}

	// For backwards compatibility, the transport type defaults
	// to "FRONTED-HTTPS" when the FrontingSpec specifies no transport types.
	transport := protocol.FRONTING_TRANSPORT_HTTPS
	if len(spec.Transports) > 0 {
		transport = spec.Transports[prng.Intn(len(spec.Transports))]
	}

	frontingDialAddr, err := regen.GenerateString(
		spec.Addresses[prng.Intn(len(spec.Addresses))])
	if err != nil {
		return "", "", "", "", "", nil, "", errors.Trace(err)
	}

	SNIServerName := frontingDialAddr
	if spec.DisableSNI || net.ParseIP(frontingDialAddr) != nil {
		SNIServerName = ""
	}

	// When SkipVerify is true, VerifyServerName and VerifyPins must be empty,
	// as checked in Validate. When dialing in any mode, MeekConn will set
	// CustomTLSConfig.SkipVerify to true as long as VerifyServerName is "".
	// So SkipVerify does not need to be explicitly returned.

	return spec.FrontingProviderID,
		transport,
		frontingDialAddr,
		SNIServerName,
		spec.VerifyServerName,
		spec.VerifyPins,
		spec.Host,
		nil
}

// Validate checks that the JSON values are well-formed.
func (specs FrontingSpecs) Validate(allowSkipVerify bool) error {

	// An empty FrontingSpecs is allowed as a tactics setting, but
	// SelectParameters will fail at runtime: code that uses FrontingSpecs must
	// provide some mechanism -- or check for an empty FrontingSpecs -- to
	// enable/disable features that use FrontingSpecs.

	for _, spec := range specs {
		if len(spec.FrontingProviderID) == 0 {
			return errors.TraceNew("empty fronting provider ID")
		}
		err := spec.Transports.Validate()
		if err != nil {
			return errors.Trace(err)
		}
		if len(spec.Addresses) == 0 {
			return errors.TraceNew("missing fronting addresses")
		}
		for _, addr := range spec.Addresses {
			if len(addr) == 0 {
				return errors.TraceNew("empty fronting address")
			}
		}
		if spec.SkipVerify {
			if !allowSkipVerify {
				return errors.TraceNew("invalid skip verify")
			}
			if len(spec.VerifyServerName) != 0 {
				return errors.TraceNew("unexpected verify server name")
			}
			if len(spec.VerifyPins) != 0 {
				return errors.TraceNew("unexpected verify pins")
			}
		} else {
			if len(spec.VerifyServerName) == 0 {
				return errors.TraceNew("empty verify server name")
			}
			// An empty VerifyPins is allowed.
			for _, pin := range spec.VerifyPins {
				if len(pin) == 0 {
					return errors.TraceNew("empty verify pin")
				}
			}
		}
		if len(spec.Host) == 0 {
			return errors.TraceNew("empty fronting host")
		}
	}
	return nil
}

// SelectParameters selects a fronted meek dial override matching the original
// fronting provider, dial address, and Host header. Match groups are ANDed;
// regexes within each group are ORed.
func (overrides FrontedMeekDialOverrideSpecs) SelectParameters(
	frontingProviderID, dialAddress, hostHeader string) (*FrontedMeekDialOverrideParameters, bool, error) {

	if len(overrides) == 0 {
		return nil, false, nil
	}

	for _, override := range overrides {
		if override == nil {
			continue
		}
		matches, err := override.matches(frontingProviderID, dialAddress, hostHeader)
		if err != nil {
			return nil, false, errors.Trace(err)
		}
		if matches {
			if len(override.DialAddresses) == 0 {
				return nil, false, errors.TraceNew("missing fronted meek dial override address")
			}

			selectedDialAddress := override.DialAddresses[prng.Intn(len(override.DialAddresses))]
			if selectedDialAddress == "" {
				return nil, false, errors.TraceNew("empty fronted meek dial override address")
			}

			return makeFrontedMeekDialOverrideParameters(
				override, selectedDialAddress), true, nil
		}
	}

	return nil, false, nil
}

// SelectCandidateParameters selects from all matching overrides and dial
// addresses in config order. candidateNumber advances through that ordered
// candidate list, wrapping when all candidates have been tried.
func (overrides FrontedMeekDialOverrideSpecs) SelectCandidateParameters(
	frontingProviderID, dialAddress, hostHeader string,
	candidateNumber int) (*FrontedMeekDialOverrideParameters, bool, error) {

	if len(overrides) == 0 {
		return nil, false, nil
	}
	if candidateNumber < 0 {
		candidateNumber = 0
	}

	type candidate struct {
		override    *FrontedMeekDialOverride
		dialAddress string
	}

	candidates := make([]candidate, 0)

	for _, override := range overrides {
		if override == nil {
			continue
		}
		matches, err := override.matches(frontingProviderID, dialAddress, hostHeader)
		if err != nil {
			return nil, false, errors.Trace(err)
		}
		if !matches {
			continue
		}
		if len(override.DialAddresses) == 0 {
			return nil, false, errors.TraceNew("missing fronted meek dial override address")
		}
		for _, selectedDialAddress := range override.DialAddresses {
			if selectedDialAddress == "" {
				return nil, false, errors.TraceNew("empty fronted meek dial override address")
			}
			candidates = append(candidates, candidate{
				override:    override,
				dialAddress: selectedDialAddress,
			})
		}
	}

	if len(candidates) == 0 {
		return nil, false, nil
	}

	selectedCandidate := candidates[candidateNumber%len(candidates)]
	return makeFrontedMeekDialOverrideParameters(
		selectedCandidate.override,
		selectedCandidate.dialAddress), true, nil
}

func makeFrontedMeekDialOverrideParameters(
	override *FrontedMeekDialOverride,
	selectedDialAddress string) *FrontedMeekDialOverrideParameters {

	SNIServerName := selectedDialAddress
	if override.DisableSNI {
		SNIServerName = ""
	} else if override.SNIServerName != "" {
		SNIServerName = override.SNIServerName
	}

	return &FrontedMeekDialOverrideParameters{
		OverrideID:        override.OverrideID,
		DialAddress:       selectedDialAddress,
		SNIServerName:     SNIServerName,
		VerifyServerNames: copyStrings(override.VerifyServerNames),
		VerifyPins:        copyStrings(override.VerifyPins),
		ALPNProtocols:     copyStrings(override.ALPNProtocols),
		TLSProfile:        override.TLSProfile,
	}
}

// Validate checks that the JSON values are well-formed.
func (overrides FrontedMeekDialOverrideSpecs) Validate(customTLSProfileNames []string) error {

	for _, override := range overrides {
		if override == nil {
			return errors.TraceNew("nil fronted meek dial override")
		}

		if len(override.MatchFrontingProviderIDRegexes) == 0 &&
			len(override.MatchDialAddressRegexes) == 0 &&
			len(override.MatchHostHeaderRegexes) == 0 {
			return errors.TraceNew("missing fronted meek dial override match criteria")
		}

		if err := validateRegexes(override.MatchFrontingProviderIDRegexes); err != nil {
			return errors.Trace(err)
		}
		if err := validateRegexes(override.MatchDialAddressRegexes); err != nil {
			return errors.Trace(err)
		}
		if err := validateRegexes(override.MatchHostHeaderRegexes); err != nil {
			return errors.Trace(err)
		}

		if len(override.DialAddresses) == 0 {
			return errors.TraceNew("missing fronted meek dial override addresses")
		}
		for _, address := range override.DialAddresses {
			if address == "" {
				return errors.TraceNew("empty fronted meek dial override address")
			}
		}

		if override.DisableSNI && override.SNIServerName != "" {
			return errors.TraceNew("unexpected fronted meek dial override SNI")
		}

		for _, verifyServerName := range override.VerifyServerNames {
			if verifyServerName == "" {
				return errors.TraceNew("empty fronted meek dial override verify server name")
			}
		}
		if len(override.VerifyPins) > 0 && len(override.VerifyServerNames) == 0 {
			return errors.TraceNew("fronted meek dial override verify pins require verify server names")
		}
		for _, pin := range override.VerifyPins {
			if pin == "" {
				return errors.TraceNew("empty fronted meek dial override verify pin")
			}
		}

		for _, protocol := range override.ALPNProtocols {
			if protocol == "" {
				return errors.TraceNew("empty fronted meek dial override ALPN protocol")
			}
		}

		if override.TLSProfile != "" {
			err := protocol.TLSProfiles{override.TLSProfile}.Validate(customTLSProfileNames)
			if err != nil {
				return errors.Trace(err)
			}
		}
	}

	return nil
}

func (override *FrontedMeekDialOverride) matches(
	frontingProviderID, dialAddress, hostHeader string) (bool, error) {

	matches, err := matchesRegexes(override.MatchFrontingProviderIDRegexes, frontingProviderID)
	if err != nil || !matches {
		return matches, errors.Trace(err)
	}

	matches, err = matchesRegexes(override.MatchDialAddressRegexes, dialAddress)
	if err != nil || !matches {
		return matches, errors.Trace(err)
	}

	matches, err = matchesRegexes(override.MatchHostHeaderRegexes, hostHeader)
	if err != nil || !matches {
		return matches, errors.Trace(err)
	}

	return true, nil
}

func validateRegexes(regexes []string) error {
	for _, regex := range regexes {
		if regex == "" {
			return errors.TraceNew("empty fronted meek dial override match regex")
		}
		_, err := regexp.Compile(regex)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func matchesRegexes(regexes []string, value string) (bool, error) {
	if len(regexes) == 0 {
		return true, nil
	}
	for _, regex := range regexes {
		matches, err := regexp.MatchString(regex, value)
		if err != nil {
			return false, errors.Trace(err)
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func copyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	copiedValues := make([]string, len(values))
	copy(copiedValues, values)
	return copiedValues
}
