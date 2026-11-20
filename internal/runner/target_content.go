package runner

import (
	"bytes"
	"encoding/binary"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var reviewableTextExtensions = map[string]struct{}{
	".bash": {}, ".bat": {}, ".c": {}, ".cc": {}, ".cjs": {}, ".cmd": {},
	".cpp": {}, ".cs": {}, ".css": {}, ".fish": {}, ".go": {}, ".h": {},
	".hpp": {}, ".html": {}, ".java": {}, ".js": {}, ".json": {}, ".jsonc": {},
	".jsx": {}, ".kt": {}, ".kts": {}, ".lua": {}, ".markdown": {}, ".md": {},
	".mjs": {}, ".php": {}, ".pl": {}, ".ps1": {}, ".py": {}, ".pyw": {},
	".rb": {}, ".rs": {}, ".sh": {}, ".sql": {}, ".swift": {}, ".toml": {},
	".ts": {}, ".tsx": {}, ".txt": {}, ".xml": {}, ".yaml": {}, ".yml": {},
	".zsh": {},
}

type nulContentInspection struct {
	content      []byte
	alternate    []byte
	reviewable   bool
	textEncoding string
}

// inspectNULContent keeps text-like files inspectable when NUL bytes are used
// to trigger the ordinary binary-file omission path.
func inspectNULContent(path string, content []byte) (nulContentInspection, bool) {
	if bytes.IndexByte(content, 0) < 0 {
		return nulContentInspection{}, false
	}
	normalized := bytes.ReplaceAll(content, []byte{0}, nil)
	normalized = []byte(strings.ToValidUTF8(string(normalized), "\uFFFD"))
	if decoded, encoding, ok := decodeBOMText(content); ok {
		if bytes.IndexByte(decoded, 0) >= 0 {
			decoded = bytes.ReplaceAll(decoded, []byte{0}, nil)
		}
		return nulContentInspection{
			content:      decoded,
			alternate:    normalized,
			reviewable:   true,
			textEncoding: encoding,
		}, true
	}
	passiveBinary := isPassiveBinary(path, content)
	scriptLike := isReviewableTextPath(path) || bytes.HasPrefix(normalized, []byte("#!"))
	return nulContentInspection{
		content:    normalized,
		reviewable: scriptLike || !passiveBinary,
	}, true
}

func isPassiveBinary(path string, content []byte) bool {
	if strings.EqualFold(filepath.Ext(path), ".pyc") {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(http.DetectContentType(content))
	if err != nil {
		return false
	}
	for _, prefix := range []string{"image/", "audio/", "video/", "font/"} {
		if strings.HasPrefix(mediaType, prefix) {
			return true
		}
	}
	switch mediaType {
	case "application/pdf", "application/zip", "application/gzip", "application/x-gzip",
		"application/x-rar-compressed", "application/vnd.rar", "application/x-7z-compressed",
		"application/x-tar", "application/vnd.ms-fontobject":
		return true
	default:
		return false
	}
}

func decodeBOMText(content []byte) ([]byte, string, bool) {
	switch {
	case len(content) >= 4 && bytes.Equal(content[:4], []byte{0xff, 0xfe, 0x00, 0x00}):
		return decodeUTF32(content[4:], binary.LittleEndian), "UTF-32LE", len(content[4:])%4 == 0
	case len(content) >= 4 && bytes.Equal(content[:4], []byte{0x00, 0x00, 0xfe, 0xff}):
		return decodeUTF32(content[4:], binary.BigEndian), "UTF-32BE", len(content[4:])%4 == 0
	case len(content) >= 2 && bytes.Equal(content[:2], []byte{0xff, 0xfe}):
		return decodeUTF16(content[2:], binary.LittleEndian), "UTF-16LE", len(content[2:])%2 == 0
	case len(content) >= 2 && bytes.Equal(content[:2], []byte{0xfe, 0xff}):
		return decodeUTF16(content[2:], binary.BigEndian), "UTF-16BE", len(content[2:])%2 == 0
	default:
		return nil, "", false
	}
}

func decodeUTF16(content []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, len(content)/2)
	for index := range units {
		units[index] = order.Uint16(content[index*2:])
	}
	return []byte(string(utf16.Decode(units)))
}

func decodeUTF32(content []byte, order binary.ByteOrder) []byte {
	var decoded strings.Builder
	for offset := 0; offset+4 <= len(content); offset += 4 {
		value := rune(order.Uint32(content[offset:]))
		if !utf8.ValidRune(value) {
			value = utf8.RuneError
		}
		decoded.WriteRune(value)
	}
	return []byte(decoded.String())
}

func isReviewableTextPath(path string) bool {
	_, ok := reviewableTextExtensions[strings.ToLower(filepath.Ext(path))]
	return ok
}
