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

var htmlTags = []string{"a", "abbr", "acronym", "address", "area", "article", "aside", "audio", "b", "base", "bdi", "bdo", "big", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite", "code", "col", "colgroup", "data", "datalist", "dd", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt", "em", "embed", "fencedframe", "fieldset", "figcaption", "figure", "font", "footer", "form", "frame", "frameset", "h1", "head", "header", "hgroup", "hr", "html", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main", "map", "mark", "marquee", "math", "menu", "meta", "meter", "nav", "nobr", "noembed", "noframes", "noscript", "object", "ol", "optgroup", "option", "output", "p", "param", "picture", "plaintext", "portal", "pre", "progress", "q", "rb", "rp", "rt", "rtc", "ruby", "s", "samp", "script", "search", "section", "select", "slot", "small", "source", "span", "strike", "strong", "style", "sub", "summary", "sup", "svg", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track", "tt", "u", "ul", "var", "video", "wbr", "xmp"}

// Attributes represents a map of HTML attribute key-value pairs.
type Attributes map[string]string

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
func New(allowedAttributes []Attribute) *Generator {
	g := &Generator{
		allowedAttributes: make(map[string]attributeConfig),
	}

	defaultAllowed := []string{"class", "id", "alt", "title", "style"}
	for _, attr := range defaultAllowed {
		g.allowedAttributes[attr] = attributeConfig{allowed: true, sanitizeFunc: html.EscapeString}
	}

	if allowedAttributes != nil {
		for _, attribute := range allowedAttributes {
			g.allowedAttributes[attribute.Name] = attributeConfig{allowed: true, sanitizeFunc: html.EscapeString}
		}
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
	g.allowedAttributes["href"] = attributeConfig{allowed: true, sanitizeFunc: urlSanitizeFunc}
	g.allowedAttributes["src"] = attributeConfig{allowed: true, sanitizeFunc: urlSanitizeFunc}

	g.Root = &Element{
		Tag:        NormalTag(""),
		Children:   []elementI{},
		Attributes: make(Attributes),
		generator:  g,
	}

	return g
}

func (g *Generator) allowAttribute(name string, sanitizeFunc sanitizeFunc) {
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
func (e *Element) Attr(key, value string) *Element {
	e.setAttribute(key, value)
	return e
}

// WithAttrs sets multiple attributes on the current element using KeyValue pairs.
func (e *Element) WithAttrs(attrs ...KeyValue) *Element {
	for _, attr := range attrs {
		e.setAttribute(attr.Key, attr.Value)
	}
	return e
}

func (e *Element) setAttribute(key, value string) {
	config, exists := e.generator.allowedAttributes[key]
	if exists && config.allowed {
		if config.sanitizeFunc != nil {
			e.Attributes[key] = config.sanitizeFunc(value)
		} else {
			e.Attributes[key] = html.EscapeString(value)
		}
	} else if strings.HasPrefix(key, "data-") {
		e.Attributes[key] = html.EscapeString(value)
	} else {
		e.Attributes["data-"+key] = html.EscapeString(value)
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
		builder.WriteString(v)
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
