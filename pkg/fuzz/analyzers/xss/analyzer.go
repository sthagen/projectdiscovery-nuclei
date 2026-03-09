package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// URL attributes whose values may contain navigable URIs.
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
			return ContextUnknown, nil

		case html.CommentToken:
			if containsMarker(tokenizer.Token().Data, markerLower) {
				return ContextComment, nil
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagName := strings.ToLower(string(tn))

			if tt == html.StartTagToken {
				switch tagName {
				case "script":
					inScript = true
					scriptIsExec = isExecutableScript(tokenizer, hasAttr)
				case "style":
					inStyle = true
				}
			}

			if hasAttr {
				if ctx, found := checkAttributes(tokenizer, markerLower, tagName); found {
					return ctx, nil
				}
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

// isExecutableScript checks whether the current <script> tag has a type
// that browsers will execute. No type attr = executable.
func isExecutableScript(tokenizer *html.Tokenizer, hasAttr bool) bool {
	if !hasAttr {
		return true
	}

	foundType := false
	typeValue := ""

	for {
		key, val, more := tokenizer.TagAttr()
		if strings.ToLower(string(key)) == "type" {
			foundType = true
			typeValue = strings.ToLower(strings.TrimSpace(string(val)))
		}
		if !more {
			break
		}
	}

	if !foundType {
		return true
	}

	_, isExec := executableScriptTypes[typeValue]
	return isExec
}

// checkAttributes walks the attributes of the current tag looking for
// the marker in any attribute value (or name).
func checkAttributes(tokenizer *html.Tokenizer, markerLower, tagName string) (XSSContext, bool) {
	for {
		key, val, more := tokenizer.TagAttr()
		attrName := strings.ToLower(string(key))
		attrValue := string(val)

		if containsMarker(attrValue, markerLower) {
			return classifyAttributeContext(attrName, attrValue, tagName), true
		}
		if containsMarker(attrName, markerLower) {
			return ContextHTMLAttribute, true
		}
		if !more {
			break
		}
	}
	return ContextUnknown, false
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
		if strings.HasPrefix(trimmed, "javascript:") || strings.HasPrefix(trimmed, "data:text/html") {
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
