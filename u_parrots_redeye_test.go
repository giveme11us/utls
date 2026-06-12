package tls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
)

// Non-regression tests for the RedEye fork (giveme11us/utls) profiles.
//
// The fork's whole delta over upstream is a handful of ClientHelloIDs:
// HelloChrome_142..147 (+ HelloChrome_Auto_Latest) share the Chrome 133 spec,
// and HelloAndroid_14_OkHttp_5 carries its own Conscrypt/BoringSSL spec.
// An upstream refactor of utlsIdToSpec or of the Chrome 133 spec would break
// these silently, so we pin the JA4 fingerprints documented in u_parrots.go
// (verified against tls.peet.ws live captures). JA4 sorts extensions, so the
// assertion is invariant to ShuffleChromeTLSExtensions.

const (
	ja4RedEyeChrome  = "t13d1516h2_8daaf6152771_d8a2da3f94cd" // u_parrots.go Chrome 133/142-147 case
	ja4RedEyeOkHttp5 = "t13d1513h2_8daaf6152771_eca864cca44a" // u_parrots.go HelloAndroid_14_OkHttp_5 case
)

func TestRedEyeChromeAliasesPinJA4(t *testing.T) {
	for _, helloID := range []ClientHelloID{
		HelloChrome_133, // upstream base the aliases must keep matching
		HelloChrome_142,
		HelloChrome_143,
		HelloChrome_146,
		HelloChrome_147,
		HelloChrome_Auto_Latest,
	} {
		t.Run(helloID.Str(), func(t *testing.T) {
			ja4, err := ja4FromHelloID(helloID)
			if err != nil {
				t.Fatalf("computing JA4 for %s: %v", helloID.Str(), err)
			}
			if ja4 != ja4RedEyeChrome {
				t.Fatalf("JA4 for %s = %s, want %s (Chrome 133..147 shared spec changed)", helloID.Str(), ja4, ja4RedEyeChrome)
			}
		})
	}
}

func TestRedEyeAndroidOkHttp5PinsJA4(t *testing.T) {
	ja4, err := ja4FromHelloID(HelloAndroid_14_OkHttp_5)
	if err != nil {
		t.Fatalf("computing JA4: %v", err)
	}
	if ja4 != ja4RedEyeOkHttp5 {
		t.Fatalf("JA4 for HelloAndroid_14_OkHttp_5 = %s, want %s (empirically validated against the bol.com app)", ja4, ja4RedEyeOkHttp5)
	}
}

// ja4FromHelloID builds a ClientHello for the given preset and computes its
// JA4 fingerprint (https://github.com/FoxIO-LLC/ja4) from the wire bytes.
func ja4FromHelloID(helloID ClientHelloID) (string, error) {
	spec, err := UTLSIdToSpec(helloID)
	if err != nil {
		return "", err
	}

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return "", err
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return "", err
	}
	return ja4FromClientHello(uconn.HandshakeState.Hello.Raw)
}

// ja4FromClientHello parses a marshaled ClientHello handshake message
// (4-byte handshake header included) and computes JA4.
func ja4FromClientHello(raw []byte) (string, error) {
	errTruncated := errors.New("truncated ClientHello")

	if len(raw) < 4 || raw[0] != typeClientHello {
		return "", errors.New("not a ClientHello handshake message")
	}
	body := raw[4:]
	// legacy_version(2) + random(32)
	if len(body) < 35 {
		return "", errTruncated
	}
	pos := 34
	// session_id
	sessLen := int(body[pos])
	pos += 1 + sessLen
	if len(body) < pos+2 {
		return "", errTruncated
	}
	// cipher_suites
	cipherLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if len(body) < pos+cipherLen {
		return "", errTruncated
	}
	var ciphers []uint16
	for i := 0; i+1 < cipherLen; i += 2 {
		c := binary.BigEndian.Uint16(body[pos+i:])
		if !isGREASEUint16(c) {
			ciphers = append(ciphers, c)
		}
	}
	pos += cipherLen
	// compression_methods
	if len(body) < pos+1 {
		return "", errTruncated
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if len(body) < pos+2 {
		return "", errTruncated
	}
	// extensions
	extTotal := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if len(body) < pos+extTotal {
		return "", errTruncated
	}

	var (
		extTypes   []uint16 // all non-GREASE extension types, in order
		sigAlgs    []uint16
		alpnFirst  string
		hasSNI     bool
		maxVersion uint16
	)
	end := pos + extTotal
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos:])
		extLen := int(binary.BigEndian.Uint16(body[pos+2:]))
		extData := body[pos+4 : pos+4+extLen]
		pos += 4 + extLen
		if isGREASEUint16(extType) {
			continue
		}
		extTypes = append(extTypes, extType)
		switch extType {
		case extensionServerName:
			hasSNI = true
		case extensionSupportedVersions:
			if len(extData) >= 1 {
				for i := 1; i+1 < len(extData)+1 && i+1 <= int(extData[0])+1; i += 2 {
					if i+1 >= len(extData)+1 {
						break
					}
					v := binary.BigEndian.Uint16(extData[i:])
					if !isGREASEUint16(v) && v > maxVersion {
						maxVersion = v
					}
				}
			}
		case extensionSignatureAlgorithms:
			if len(extData) >= 2 {
				n := int(binary.BigEndian.Uint16(extData))
				for i := 2; i+1 < 2+n && i+1 < len(extData)+1; i += 2 {
					if i+2 > len(extData) {
						break
					}
					sigAlgs = append(sigAlgs, binary.BigEndian.Uint16(extData[i:]))
				}
			}
		case extensionALPN:
			if len(extData) >= 3 {
				l := int(extData[2])
				if 3+l <= len(extData) && l > 0 {
					alpnFirst = string(extData[3 : 3+l])
				}
			}
		}
	}

	// JA4_a
	version := "00"
	switch maxVersion {
	case VersionTLS13:
		version = "13"
	case VersionTLS12:
		version = "12"
	case VersionTLS11:
		version = "11"
	case VersionTLS10:
		version = "10"
	}
	sni := "i"
	if hasSNI {
		sni = "d"
	}
	alpn := "00"
	if len(alpnFirst) > 0 {
		alpn = string(alpnFirst[0]) + string(alpnFirst[len(alpnFirst)-1])
	}
	ja4a := fmt.Sprintf("t%s%s%02d%02d%s", version, sni, min(len(ciphers), 99), min(len(extTypes), 99), alpn)

	// JA4_b: sha256 of sorted cipher hex list, truncated to 12
	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	ja4b := truncatedSHA256(joinHex(sortedCiphers))

	// JA4_c: sha256 of sorted extensions (minus SNI and ALPN) + "_" + sigalgs in order
	var ja4cExts []uint16
	for _, e := range extTypes {
		if e == extensionServerName || e == extensionALPN {
			continue
		}
		ja4cExts = append(ja4cExts, e)
	}
	sort.Slice(ja4cExts, func(i, j int) bool { return ja4cExts[i] < ja4cExts[j] })
	ja4cInput := joinHex(ja4cExts)
	if len(sigAlgs) > 0 {
		ja4cInput += "_" + joinHex(sigAlgs)
	}
	ja4c := truncatedSHA256(ja4cInput)

	return ja4a + "_" + ja4b + "_" + ja4c, nil
}

func joinHex(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
