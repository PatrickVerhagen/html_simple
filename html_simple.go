// Package html_simple provides a safe and ergonomic HTML generation library
// with built-in XSS protection and compile-time HTML structure validation.
package html_simple

import (
	"html"
	"net/url"
	"strings"
)

// Tag interface represents an HTML tag with a name.
type Tag interface {
	name() string
}

// NormalTag represents standard HTML tags that can have children and content.
type NormalTag string

func (t NormalTag) name() string { return string(t) }

// VoidTag represents self-closing HTML tags that cannot have children or content.
type VoidTag string

func (t VoidTag) name() string { return string(t) }

// Attributes represents a map of HTML attribute key-value pairs.
type Attributes map[string][]string

// KeyValue is a helper struct for setting attributes.
type KeyValue struct {
	Key   string
	Value string
}

// KV creates a KeyValue pair.
func KV(key, value string) KeyValue {
	return KeyValue{Key: key, Value: value}
}

type elementI interface {
	generateHtml(*strings.Builder)
}

// SanitizeFunc defines a function type for sanitizing attribute values.
type sanitizeFunc func(string) string

type attributeConfig struct {
	allowed      bool
	sanitizeFunc sanitizeFunc
}

// Attribute represents a custom allowed attribute configuration.
type Attribute struct {
	Name string
}

// Generator is responsible for generating sanitized HTML.
type Generator struct {
	Root              *Element
	allowedAttributes map[string]attributeConfig
}

// Element represents an HTML element with tag, attributes, children, and content.
type Element struct {
	Tag        Tag
	Attributes Attributes
	Children   []elementI
	Parent     *Element
	Content    string
	generator  *Generator
}

// New initializes a new Generator with default allowed attributes and sanitization functions.
func New(allowedAttributesCustom []Attribute) *Generator {
	g := &Generator{
		allowedAttributes: make(map[string]attributeConfig),
	}

	defaultAllowed := []string{
		"accept", "accept-charset", "accesskey", "allow", "alt", "as", "async",
		"autocapitalize", "autocomplete", "autoplay", "background", "bgcolor", "border",
		"capture", "charset", "checked", "cite", "class", "color", "cols", "colspan",
		"content", "contenteditable", "controls", "coords", "crossorigin", "data", "data-*",
		"datetime", "decoding", "default", "defer", "dir", "dirname", "disabled", "download",
		"draggable", "enctype", "enterkeyhint", "for", "form", "formenctype",
		"formmethod", "formnovalidate", "formtarget", "headers", "height", "hidden", "high",
		"hreflang", "http-equiv", "id", "integrity", "inputmode", "ismap", "itemprop",
		"kind", "label", "lang", "loading", "list", "loop", "low", "max", "maxlength",
		"minlength", "media", "method", "min", "multiple", "muted", "name", "novalidate",
		"open", "optimum", "pattern", "placeholder", "playsinline",
		"preload", "readonly", "referrerpolicy", "rel", "required", "reversed", "role",
		"rows", "rowspan", "sandbox", "scope", "selected", "shape", "size", "sizes",
		"slot", "span", "spellcheck", "srcdoc", "srclang", "start", "step",
		"style", "tabindex", "target", "title", "translate", "type", "usemap", "value",
		"width", "wrap",
	}

	defaultAllowedUrl := []string{
		"href", "src", "action", "formaction", "srcset", "ping", "poster",
	}

	defaultAllowedHtmx := []string{
		"hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete",
	}
	defaultAllowedUrl = append(defaultAllowedUrl, defaultAllowedHtmx...)

	for _, attr := range defaultAllowed {
		if allowedAttributesCustom != nil {
			if _, exists := g.allowedAttributes[attr]; exists {
				continue
			}
		}
		g.allowedAttributes[attr] = attributeConfig{allowed: true, sanitizeFunc: html.EscapeString}
	}
	urlSanitizeFunc := func(s string) string {
		u, err := url.Parse(s)
		if err != nil {
			return "#"
		}
		if u.Scheme == "javascript" {
			return "#"
		}
		if u.Scheme == "" && !strings.HasPrefix(u.Path, "/") {
			return "#"
		}
		return html.EscapeString(u.String())
	}

	for _, attr := range defaultAllowedUrl {
		if allowedAttributesCustom != nil {
			if _, exists := g.allowedAttributes[attr]; exists {
				continue
			}
			if allowedAttributesCustom != nil {
				if _, exists := g.allowedAttributes[attr]; exists {
					continue
				}
			}
			g.allowedAttributes[attr] = attributeConfig{allowed: true, sanitizeFunc: urlSanitizeFunc}
		}

		for _, attribute := range allowedAttributesCustom {
			g.allowedAttributes[attribute.Name] = attributeConfig{allowed: true, sanitizeFunc: html.EscapeString}
		}

	}

	g.Root = &Element{
		Tag:        NormalTag(""),
		Children:   []elementI{},
		Attributes: make(Attributes),
		generator:  g,
	}

	return g
}

func (g *Generator) _allowAttribute(name string, sanitizeFunc sanitizeFunc) {
	g.allowedAttributes[name] = attributeConfig{allowed: true, sanitizeFunc: sanitizeFunc}
}

// Add creates and adds a child NormalTag element to the current element.
func (e *Element) Add(tag NormalTag) *Element {
	child := &Element{
		Tag:        tag,
		Attributes: make(Attributes),
		Children:   []elementI{},
		Parent:     e,
		generator:  e.generator,
	}
	e.Children = append(e.Children, child)
	return child
}

// AddVoid creates and adds a child VoidTag element to the current element.
func (e *Element) AddVoid(tag VoidTag) *Element {
	child := &Element{
		Tag:        tag,
		Attributes: make(Attributes),
		Parent:     e,
		generator:  e.generator,
	}
	e.Children = append(e.Children, child)
	return child
}

// Attr sets a single attribute on the current element.
// For 'class' and 'style' attributes, values are concatenated:
// - 'class' values are space-separated
// - 'style' values are semicolon-separated (if no semicolon is added, it will be added for you)
// For other attributes, the value is replaced.
//
// Examples:
//
//	element.Attr("class", "btn").Attr("class", "primary")
//	// Results in: class="btn primary"
//
//	element.Attr("style", "color: red").Attr("style", "font-size: 12px")
//	// Results in: style="color: red; font-size: 12px;"
//
//	element.Attr("id", "btn1").Attr("id", "btn2")
//	// Results in: id="btn2"
func (e *Element) Attr(key, value string) *Element {
	e.setAttribute(key, value)
	return e
}

// WithAttrs sets multiple attributes on the current element using KeyValue pairs.
// For 'class' and 'style' attributes, values are concatenated:
// - 'class' values are space-separated
// - 'style' values are semicolon-separated (if no semicolon is added, it will be added for you)
// For other attributes, the value is replaced.
//
// Example:
//
//	element.WithAttrs(
//	  KV("class", "btn"),
//	  KV("class", "primary"),
//	  KV("style", "color: red"),
//	  KV("style", "font-size: 12px"),
//	  KV("id", "myButton"),
//	)
//	// Results in: class="btn primary" style="color: red; font-size: 12px;" id="myButton"
func (e *Element) WithAttrs(attrs ...KeyValue) *Element {
	for _, attr := range attrs {
		e.setAttribute(attr.Key, attr.Value)
	}
	return e
}

// setAttribute handles attribute setting with special behavior for certain attributes:
//   - 'class' attributes are concatenated (space-separated)
//     Example: .Attr("class", "btn").Attr("class", "primary") results in class="btn primary"
//   - 'style' attributes are appended
//     Example: .Attr("style", "color: red;").Attr("style", "font-size: 12px;") results in style="color: red; font-size: 12px;"
//   - Other attributes are replaced entirely
//     Example: .Attr("id", "btn1").Attr("id", "btn2") results in id="btn2"
//
// Non-allowed attributes are prefixed with 'data-' for safety
//
//	Example: .Attr("onclick", "alert('Hi')") results in data-onclick="alert('Hi')"
func (e *Element) setAttribute(key, value string) {
	config, exists := e.generator.allowedAttributes[key]
	if exists && config.allowed {
		sanitizedValue := value
		if config.sanitizeFunc != nil {
			sanitizedValue = config.sanitizeFunc(value)
		} else {
			sanitizedValue = html.EscapeString(value)
		}

		switch key {
		case "class":
			e.Attributes[key] = append(e.Attributes[key], strings.Fields(sanitizedValue)...)
		case "style":
			e.Attributes[key] = append(e.Attributes[key], sanitizedValue)
		default:
			e.Attributes[key] = []string{sanitizedValue}
		}
	} else if strings.HasPrefix(key, "js-") { // allowing support for js hook syntax
		e.Attributes[key] = []string{html.EscapeString(value)}
	} else if strings.HasPrefix(key, "data-") {
		e.Attributes[key] = []string{html.EscapeString(value)}
	} else {
		e.Attributes["data-"+key] = []string{html.EscapeString(value)}
	}
}

// AddString adds sanitized text content to the current element.
func (e *Element) AddString(content string) *Element {
	e.Content += html.EscapeString(content)
	return e
}

func (e *Element) generateHtml(builder *strings.Builder) {
	if e.Tag.name() == "" {
		for _, child := range e.Children {
			child.generateHtml(builder)
		}
		return
	}

	builder.WriteString("<")
	builder.WriteString(e.Tag.name())

	for k, v := range e.Attributes {
		builder.WriteString(" ")
		builder.WriteString(k)
		builder.WriteString(`="`)
		switch k {
		case "class":
			builder.WriteString(strings.Join(v, " "))
		default:
			builder.WriteString(strings.Join(v, " "))
		}
		builder.WriteString(`"`)
	}

	if _, isVoid := e.Tag.(VoidTag); isVoid {
		builder.WriteString(" />")
		return
	}

	builder.WriteString(">")

	if e.Content != "" {
		builder.WriteString(e.Content)
	}

	for _, child := range e.Children {
		child.generateHtml(builder)
	}

	builder.WriteString("</")
	builder.WriteString(e.Tag.name())
	builder.WriteString(">")
}

// Generate returns the complete sanitized HTML string.
func (g *Generator) Generate() string {
	var builder strings.Builder
	g.Root.generateHtml(&builder)
	return builder.String()
}
