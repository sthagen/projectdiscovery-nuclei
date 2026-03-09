package xss

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// URL attributes whose values may contain navigable URIs.
// ping was missed initially, it fires a POST to the URL when <a> is clicked.
var urlAttrs = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"data":       {},
	"poster":     {},
	"codebase":   {},
	"cite":       {},
	"background": {},
	"manifest":   {},
	"icon":       {},
	"ping":       {},
}

// Event handler attributes that execute JavaScript.
var eventHandlers = map[string]struct{}{
	"onabort":              {},
	"onafterprint":         {},
	"onbeforeprint":        {},
	"onbeforeunload":       {},
	"onblur":               {},
	"oncancel":             {},
	"oncanplay":            {},
	"oncanplaythrough":     {},
	"onchange":             {},
	"onclick":              {},
	"onclose":              {},
	"oncontextmenu":        {},
	"oncopy":               {},
	"oncuechange":          {},
	"oncut":                {},
	"ondblclick":           {},
	"ondrag":               {},
	"ondragend":            {},
	"ondragenter":          {},
	"ondragleave":          {},
	"ondragover":           {},
	"ondragstart":          {},
	"ondrop":               {},
	"ondurationchange":     {},
	"onemptied":            {},
	"onended":              {},
	"onerror":              {},
	"onfocus":              {},
	"onfocusin":            {},
	"onfocusout":           {},
	"onhashchange":         {},
	"oninput":              {},
	"oninvalid":            {},
	"onkeydown":            {},
	"onkeypress":           {},
	"onkeyup":              {},
	"onload":               {},
	"onloadeddata":         {},
	"onloadedmetadata":     {},
	"onloadstart":          {},
	"onmessage":            {},
	"onmousedown":          {},
	"onmouseenter":         {},
	"onmouseleave":         {},
	"onmousemove":          {},
	"onmouseout":           {},
	"onmouseover":          {},
	"onmouseup":            {},
	"onoffline":            {},
	"ononline":             {},
	"onpagehide":           {},
	"onpageshow":           {},
	"onpaste":              {},
	"onpause":              {},
	"onplay":               {},
	"onplaying":            {},
	"onpopstate":           {},
	"onprogress":           {},
	"onratechange":         {},
	"onreset":              {},
	"onresize":             {},
	"onscroll":             {},
	"onsearch":             {},
	"onseeked":             {},
	"onseeking":            {},
	"onselect":             {},
	"onstalled":            {},
	"onstorage":            {},
	"onsubmit":             {},
	"onsuspend":            {},
	"ontimeupdate":         {},
	"ontoggle":             {},
	"onunload":             {},
	"onvolumechange":       {},
	"onwaiting":            {},
	"onwheel":              {},
	"onanimationstart":     {},
	"onanimationend":       {},
	"onanimationiteration": {},
	"ontransitionend":      {},
	"onpointerdown":        {},
	"onpointerup":          {},
	"onpointermove":        {},
	"onpointerover":        {},
	"onpointerout":         {},
	"onpointerenter":       {},
	"onpointerleave":       {},
	"onpointercancel":      {},
	"ongotpointercapture":  {},
	"onlostpointercapture": {},
	"ontouchstart":         {},
	"ontouchend":           {},
	"ontouchmove":          {},
	"ontouchcancel":        {},
	// added after review, these are newer DOM events that were missing
	"onauxclick":           {},
	"onbeforeinput":        {},
	"onformdata":           {},
	"onslotchange":         {},
	"onsecuritypolicyviolation": {},
}

// Script MIME types that browsers actually execute.
// Empty string covers <script> with no type attribute.
var executableScriptTypes = map[string]struct{}{
	"":                          {},
	"text/javascript":           {},
	"application/javascript":    {},
	"text/ecmascript":           {},
	"application/ecmascript":    {},
	"module":                    {},
	"text/jscript":              {},
	"text/livescript":           {},
	"text/x-ecmascript":        {},
	"text/x-javascript":        {},
	"application/x-javascript":  {},
	"application/x-ecmascript":  {},
}

// AnalyzeReflectionContext determines the HTML context where the given marker
// is reflected in the response body. Uses golang.org/x/net/html tokenizer
// for parsing. Returns ContextUnknown if the marker is not found.
func AnalyzeReflectionContext(responseBody, marker string) (XSSContext, error) {
	if responseBody == "" || marker == "" {
		return ContextUnknown, nil
	}

	markerLower := strings.ToLower(marker)

	// bail early if the marker isn't anywhere in the body
	if !strings.Contains(strings.ToLower(responseBody), markerLower) {
		return ContextUnknown, nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(responseBody))

	var (
		inScript     bool
		inStyle      bool
		scriptIsExec bool
	)

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			// EOF is expected (end of doc), but surface real parse errors
			if err := tokenizer.Err(); err != nil && err != io.EOF {
				return ContextUnknown, err
			}
			return ContextUnknown, nil

		case html.CommentToken:
			if containsMarker(tokenizer.Token().Data, markerLower) {
				return ContextComment, nil
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagName := strings.ToLower(string(tn))

			// Important: TagAttr() is a forward-only iterator. If we checked
			// script type and marker in separate loops, the second loop would
			// see no attributes (already consumed). So we do both in one pass.
			if hasAttr {
				ctx, found, scriptType := scanAttributes(tokenizer, markerLower, tagName)
				if found {
					return ctx, nil
				}
				if tt == html.StartTagToken && tagName == "script" {
					inScript = true
					scriptIsExec = isScriptTypeExecutable(scriptType)
				}
			} else if tt == html.StartTagToken && tagName == "script" {
				inScript = true
				scriptIsExec = true // no attrs = executable
			}

			if tt == html.StartTagToken && tagName == "style" {
				inStyle = true
			}

		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			switch strings.ToLower(string(tn)) {
			case "script":
				inScript = false
			case "style":
				inStyle = false
			}

		case html.TextToken:
			if containsMarker(tokenizer.Token().Data, markerLower) {
				if inScript {
					if scriptIsExec {
						return ContextScript, nil
					}
					return ContextScriptData, nil
				}
				if inStyle {
					return ContextStyle, nil
				}
				return ContextHTMLBody, nil
			}
		}
	}
}

// scanAttributes walks all attributes in one pass. We need this because
// the tokenizer's TagAttr() is consumable, once you iterate through,
// the attributes are gone. Earlier version had a bug where checking the
// script type first would eat all the attrs before we could check for
// the marker, so <script src="MARKER"> would silently miss the reflection.
func scanAttributes(tokenizer *html.Tokenizer, markerLower, tagName string) (XSSContext, bool, string) {
	var markerCtx XSSContext
	markerFound := false
	scriptType := ""

	for {
		key, val, more := tokenizer.TagAttr()
		attrName := strings.ToLower(string(key))
		attrValue := string(val)

		if attrName == "type" {
			scriptType = strings.ToLower(strings.TrimSpace(attrValue))
		}

		if !markerFound {
			if containsMarker(attrValue, markerLower) {
				markerCtx = classifyAttributeContext(attrName, attrValue, tagName)
				markerFound = true
			} else if containsMarker(attrName, markerLower) {
				markerCtx = ContextHTMLAttribute
				markerFound = true
			}
		}

		if !more {
			break
		}
	}

	return markerCtx, markerFound, scriptType
}

// isScriptTypeExecutable returns true if the type value is something
// browsers will actually run (or empty, meaning no type was set).
// Strips MIME parameters first, browsers still execute
// "text/javascript; charset=utf-8" but the raw string wouldn't match
// the lookup table without this.
func isScriptTypeExecutable(scriptType string) bool {
	if i := strings.IndexByte(scriptType, ';'); i != -1 {
		scriptType = strings.TrimSpace(scriptType[:i])
	}
	_, isExec := executableScriptTypes[scriptType]
	return isExec
}

// classifyAttributeContext maps an attribute name to the right XSS context.
func classifyAttributeContext(attrName, attrValue, tagName string) XSSContext {
	if _, ok := eventHandlers[attrName]; ok {
		return ContextHTMLAttributeEvent
	}

	if attrName == "style" {
		return ContextStyle
	}

	if attrName == "srcdoc" {
		return ContextHTMLBody
	}

	if _, ok := urlAttrs[attrName]; ok {
		trimmed := strings.TrimSpace(strings.ToLower(attrValue))
		// also catch data:application/xhtml+xml as it renders and executes
		// script the same way data:text/html does in iframes. Missed this one
		// on the first pass.
		if strings.HasPrefix(trimmed, "javascript:") ||
			strings.HasPrefix(trimmed, "data:text/html") ||
			strings.HasPrefix(trimmed, "data:application/xhtml+xml") {
			return ContextScript
		}
		return ContextHTMLAttributeURL
	}

	return ContextHTMLAttribute
}

// containsMarker does a case-insensitive substring check.
// markerLower must already be lowercased by the caller.
func containsMarker(text, markerLower string) bool {
	return strings.Contains(strings.ToLower(text), markerLower)
}
