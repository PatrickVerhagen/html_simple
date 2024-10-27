package main

import (
	"fmt"
	h "html_simple"
)

func main() {
	generator := h.New(nil)

	// Build a sample HTML structure
	outerDiv := generator.Root.Div().WithAttrs(
		h.KV("class", "container"),
		h.KV("id", "main"),
		h.KV("style", "color: red; background-color: #f0f0f0;"),
		h.KV("onclick", "alert('Hello!')"), // This will be prefixed with "data-"
	)

	innerDiv := outerDiv.Div().WithAttrs(
		h.KV("class", "content"),
		h.KV("data-id", "inner"),
	)

	innerDiv.Br().Attr("class", "clearfix").Attr("class", "secondclass")

	childDiv := innerDiv.Div()
	childDiv.AddString("I AM THE CHILD CHILD")

	link := innerDiv.A().WithAttrs(
		h.KV("href", "https://example.com?param=value&another=test"),
		h.KV("style", "color: blue; font-weight: bold;"),
	)
	link.AddString("Click me")

	innerDiv.Img().WithAttrs(
		h.KV("src", "https://example.com/image.jpg"),
		h.KV("alt", "Example Image"),
	)

	maliciousLink := innerDiv.A().WithAttrs(
		h.KV("href", "javascript:alert('XSS')"),
	)
	maliciousLink.AddString("Don't click me")

	// Generate and print the sanitized HTML
	fmt.Println(generator.Generate())
}
