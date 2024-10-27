package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
)

var htmlTags = []string{"a", "abbr", "acronym", "address", "area", "article", "aside", "audio", "b", "base", "bdi", "bdo", "big", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite", "code", "col", "colgroup", "data", "datalist", "dd", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt", "em", "embed", "fencedframe", "fieldset", "figcaption", "figure", "font", "footer", "form", "frame", "frameset", "h1", "head", "header", "hgroup", "hr", "html", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main", "map", "mark", "marquee", "math", "menu", "meta", "meter", "nav", "nobr", "noembed", "noframes", "noscript", "object", "ol", "optgroup", "option", "output", "p", "param", "picture", "plaintext", "portal", "pre", "progress", "q", "rb", "rp", "rt", "rtc", "ruby", "s", "samp", "script", "search", "section", "select", "slot", "small", "source", "span", "strike", "strong", "style", "sub", "summary", "sup", "svg", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track", "tt", "u", "ul", "var", "video", "wbr", "xmp"}

// List of void elements in HTML5
var voidElements = map[string]bool{
	"area":   true,
	"base":   true,
	"br":     true,
	"col":    true,
	"embed":  true,
	"hr":     true,
	"img":    true,
	"input":  true,
	"link":   true,
	"meta":   true,
	"param":  true,
	"source": true,
	"track":  true,
	"wbr":    true,
}

func main() {
	// Find the package root directory
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
		os.Exit(1)
	}

	// The generator should be run from the package root via go:generate
	outputPath := filepath.Join(dir, "tags_gen.go")

	var buf bytes.Buffer

	// Write package and imports
	buf.WriteString(`// Code generated by html_simple generator; DO NOT EDIT.

package html_simple

// Tag methods for HTML elements
`)

	// Write methods for each tag
	for _, tag := range htmlTags {
		methodName := strings.Title(tag) // Capitalize first letter for method name

		if voidElements[tag] {
			fmt.Fprintf(&buf, `
// %s creates a void <%s> element and adds it to the current element.
func (e *Element) %s() *Element {
    return e.AddVoid(VoidTag("%s"))
}
`, methodName, tag, methodName, tag)
		} else {
			fmt.Fprintf(&buf, `
// %s creates a <%s> element and adds it to the current element.
func (e *Element) %s() *Element {
    return e.Add(NormalTag("%s"))
}
`, methodName, tag, methodName, tag)
		}
	}

	// Format the generated code
	formattedBytes, err := format.Source(buf.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting code: %v\n", err)
		os.Exit(1)
	}

	// Write to tags_gen.go
	err = os.WriteFile(outputPath, formattedBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated %s\n", outputPath)
}