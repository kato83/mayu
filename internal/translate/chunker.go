package translate

import (
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

const (
	defaultMaxChars = 500

	strategyAuto     = "auto"
	strategySentence = "sentence"
	strategyMarkdown = "markdown"
)

// Chunker splits text into smaller pieces suitable for small LLM translation.
type Chunker struct {
	strategy string
	maxChars int
}

// NewChunker creates a new Chunker with the given strategy and max character limit.
func NewChunker(strategy string, maxChars int) *Chunker {
	if strategy == "" {
		strategy = strategyAuto
	}
	if maxChars <= 0 {
		maxChars = defaultMaxChars
	}
	return &Chunker{strategy: strategy, maxChars: maxChars}
}

// Chunk represents a piece of text with metadata about whether it should be translated.
type Chunk struct {
	// Text is the chunk content.
	Text string
	// Translatable indicates whether this chunk should be sent to the LLM.
	// Code blocks and empty chunks are marked as non-translatable.
	Translatable bool
}

// Split divides the input text into chunks based on the configured strategy.
func (c *Chunker) Split(text string) []Chunk {
	if text == "" {
		return nil
	}

	switch c.strategy {
	case strategyMarkdown:
		return c.splitMarkdown(text)
	case strategySentence:
		return c.splitSentences(text)
	case strategyAuto:
		if looksLikeMarkdown(text) {
			return c.splitMarkdown(text)
		}
		return c.splitSentences(text)
	default:
		return c.splitSentences(text)
	}
}

// Join reassembles translated chunks into a single string.
func Join(chunks []Chunk) string {
	var sb strings.Builder
	for _, ch := range chunks {
		sb.WriteString(ch.Text)
	}
	return sb.String()
}

// looksLikeMarkdown performs a heuristic check for markdown content.
func looksLikeMarkdown(text string) bool {
	indicators := 0
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") || strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
			indicators++
		}
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "1. ") {
			indicators++
		}
		if strings.HasPrefix(trimmed, "```") {
			indicators += 2
		}
		if strings.Contains(trimmed, "](") || strings.Contains(trimmed, "**") {
			indicators++
		}
	}
	return indicators >= 2
}

// splitMarkdown splits text using goldmark AST parsing.
// Each AST node is categorized as translatable or non-translatable.
//
// Non-translatable nodes (kept as-is):
//   - FencedCodeBlock: ```...```
//   - CodeBlock: indented code blocks (4 spaces / 1 tab)
//   - CodeSpan: inline `code`
//   - AutoLink: <http://...>
//   - RawHTML: inline raw HTML
//   - HTMLBlock: block-level raw HTML
//   - ThematicBreak: ---, ***, ___
//   - Link destination/title (link text IS translated)
//   - Image destination/title/alt
//
// Translatable nodes (sent to LLM):
//   - Text (paragraph content, heading content, etc.)
//   - Emphasis / Strong content
//   - Link text
//   - ListItem text content
//   - Blockquote text content
func (c *Chunker) splitMarkdown(input string) []Chunk {
	source := []byte(input)

	// Parse markdown into AST
	md := goldmark.New()
	reader := text.NewReader(source)
	doc := md.Parser().Parse(reader)

	// Walk the AST and build a list of spans with translatable flags.
	type mdSegment struct {
		start        int
		stop         int
		translatable bool
	}

	var segments []mdSegment

	// collectLines extracts lines (byte segments) from a block node that has Lines().
	collectLines := func(n ast.Node) (int, int) {
		lines := n.Lines()
		if lines.Len() == 0 {
			return -1, -1
		}
		first := lines.At(0)
		last := lines.At(lines.Len() - 1)
		return first.Start, last.Stop
	}

	// Walk the AST at block level first to get non-translatable blocks.
	// Then handle inline elements within translatable blocks.
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		switch n.Kind() {
		case ast.KindFencedCodeBlock:
			// Include fence markers: use node position for the opening fence
			// and find the closing fence after the content lines.
			fcb := n.(*ast.FencedCodeBlock)
			// The node's Pos() gives the start of the opening fence line.
			start := fcb.Pos()
			// End: after the last content line, the closing fence follows.
			// We need to find the closing ``` line.
			end := start
			if fcb.Lines().Len() > 0 {
				lastLine := fcb.Lines().At(fcb.Lines().Len() - 1)
				end = lastLine.Stop
			}
			// Scan forward from end to include the closing fence line.
			for end < len(source) && source[end] != '\n' {
				end++
			}
			if end < len(source) && source[end] == '\n' {
				end++ // include the newline after closing fence
			}
			// If start is -1, try to find it from lines
			if start < 0 && fcb.Lines().Len() > 0 {
				start = fcb.Lines().At(0).Start
			}
			if start >= 0 {
				segments = append(segments, mdSegment{start: start, stop: end, translatable: false})
			}
			return ast.WalkSkipChildren, nil

		case ast.KindCodeBlock:
			// Indented code block
			start, stop := collectLines(n)
			if start >= 0 {
				segments = append(segments, mdSegment{start: start, stop: stop, translatable: false})
			}
			return ast.WalkSkipChildren, nil

		case ast.KindHTMLBlock:
			start, stop := collectLines(n)
			if start >= 0 {
				segments = append(segments, mdSegment{start: start, stop: stop, translatable: false})
			}
			return ast.WalkSkipChildren, nil

		case ast.KindCodeSpan:
			// Inline code: find the backtick-delimited span in source.
			// CodeSpan children are Text nodes with the code content.
			// We need the full `...` including backticks.
			// Use Pos() to find start, then scan to find the complete span.
			pos := n.Pos()
			if pos >= 0 {
				// Find the end of the code span (matching closing backticks).
				end := findCodeSpanEnd(source, pos)
				segments = append(segments, mdSegment{start: pos, stop: end, translatable: false})
			}
			return ast.WalkSkipChildren, nil

		case ast.KindAutoLink:
			pos := n.Pos()
			if pos >= 0 {
				// AutoLink is <url>, find closing >
				end := pos
				for end < len(source) && source[end] != '>' {
					end++
				}
				if end < len(source) {
					end++ // include >
				}
				segments = append(segments, mdSegment{start: pos, stop: end, translatable: false})
			}
			return ast.WalkSkipChildren, nil

		case ast.KindRawHTML:
			pos := n.Pos()
			if pos >= 0 {
				// Find end of raw HTML tag
				end := pos
				for end < len(source) && source[end] != '>' {
					end++
				}
				if end < len(source) {
					end++ // include >
				}
				segments = append(segments, mdSegment{start: pos, stop: end, translatable: false})
			}
			return ast.WalkSkipChildren, nil

		case ast.KindImage:
			// Entire image syntax is non-translatable: ![alt](url "title")
			pos := n.Pos()
			if pos >= 0 {
				end := findLinkEnd(source, pos)
				segments = append(segments, mdSegment{start: pos, stop: end, translatable: false})
			}
			return ast.WalkSkipChildren, nil
		}

		return ast.WalkContinue, nil
	})

	// If no non-translatable segments found, treat whole text as translatable
	if len(segments) == 0 {
		var chunks []Chunk
		for _, sub := range c.splitByMaxChars(input) {
			chunks = append(chunks, Chunk{Text: sub, Translatable: true})
		}
		return chunks
	}

	// Sort segments by start position
	for i := 1; i < len(segments); i++ {
		key := segments[i]
		j := i - 1
		for j >= 0 && segments[j].start > key.start {
			segments[j+1] = segments[j]
			j--
		}
		segments[j+1] = key
	}

	var chunks []Chunk
	pos := 0
	for _, seg := range segments {
		if seg.start < pos {
			// Overlapping segment, skip
			continue
		}
		// Text before this non-translatable segment is translatable
		if seg.start > pos {
			t := string(source[pos:seg.start])
			if t != "" {
				for _, sub := range c.splitByMaxChars(t) {
					chunks = append(chunks, Chunk{Text: sub, Translatable: true})
				}
			}
		}
		// The non-translatable segment itself
		chunks = append(chunks, Chunk{Text: string(source[seg.start:seg.stop]), Translatable: false})
		pos = seg.stop
	}

	// Remaining text after the last non-translatable segment
	if pos < len(source) {
		t := string(source[pos:])
		if t != "" {
			for _, sub := range c.splitByMaxChars(t) {
				chunks = append(chunks, Chunk{Text: sub, Translatable: true})
			}
		}
	}

	return chunks
}

// findCodeSpanEnd finds the end position of a code span starting at pos.
// pos should point to the opening backtick(s).
func findCodeSpanEnd(source []byte, pos int) int {
	if pos >= len(source) || source[pos] != '`' {
		return pos
	}
	// Count opening backticks
	openCount := 0
	i := pos
	for i < len(source) && source[i] == '`' {
		openCount++
		i++
	}
	// Find matching closing backticks
	for i < len(source) {
		if source[i] == '`' {
			closeCount := 0
			j := i
			for j < len(source) && source[j] == '`' {
				closeCount++
				j++
			}
			if closeCount == openCount {
				return j
			}
			i = j
		} else {
			i++
		}
	}
	return i
}

// findLinkEnd finds the end position of a link or image syntax starting at pos.
// Handles [text](url) and [text](url "title") patterns.
func findLinkEnd(source []byte, pos int) int {
	i := pos
	// Skip ![ or [
	if i < len(source) && source[i] == '!' {
		i++
	}
	if i >= len(source) || source[i] != '[' {
		return pos + 1
	}
	// Find matching ]
	bracketDepth := 0
	for i < len(source) {
		if source[i] == '[' {
			bracketDepth++
		} else if source[i] == ']' {
			bracketDepth--
			if bracketDepth == 0 {
				i++
				break
			}
		}
		i++
	}
	// Check for (url) or (url "title")
	if i < len(source) && source[i] == '(' {
		parenDepth := 0
		for i < len(source) {
			if source[i] == '(' {
				parenDepth++
			} else if source[i] == ')' {
				parenDepth--
				if parenDepth == 0 {
					i++
					break
				}
			}
			i++
		}
	}
	return i
}

// splitSentences splits text on sentence boundaries.
func (c *Chunker) splitSentences(text string) []Chunk {
	var chunks []Chunk
	var current strings.Builder

	flushCurrent := func() {
		if current.Len() > 0 {
			chunks = append(chunks, Chunk{Text: current.String(), Translatable: true})
			current.Reset()
		}
	}

	// Split on paragraph breaks first
	paragraphs := strings.Split(text, "\n\n")
	for pi, para := range paragraphs {
		if pi > 0 {
			// Preserve paragraph separator
			flushCurrent()
			current.WriteString("\n\n")
		}

		sentences := c.splitIntoSentences(para)
		for _, sent := range sentences {
			if current.Len()+len(sent) > c.maxChars && current.Len() > 0 {
				flushCurrent()
			}
			current.WriteString(sent)
		}
	}

	flushCurrent()
	return chunks
}

// splitIntoSentences splits a paragraph into sentences.
// Splits on ". ", "! ", "? " followed by uppercase or newline.
func (c *Chunker) splitIntoSentences(text string) []string {
	if text == "" {
		return nil
	}

	var sentences []string
	var current strings.Builder
	runes := []rune(text)

	for i := 0; i < len(runes); i++ {
		current.WriteRune(runes[i])

		// Check for sentence ending punctuation followed by space and uppercase
		if (runes[i] == '.' || runes[i] == '!' || runes[i] == '?') && i+1 < len(runes) {
			next := runes[i+1]
			switch next {
			case ' ', '\n':
				// Look ahead for uppercase letter or end of text
				if i+2 < len(runes) {
					afterSpace := runes[i+2]
					if unicode.IsUpper(afterSpace) || afterSpace == '\n' || afterSpace == '-' || afterSpace == '*' {
						sentences = append(sentences, current.String())
						current.Reset()
					}
				} else {
					// End of text after punctuation + space
					sentences = append(sentences, current.String())
					current.Reset()
				}
			}
		} else if runes[i] == '\n' && i+1 < len(runes) && runes[i+1] != '\n' {
			// Single newline within paragraph — possible sentence break if long enough
			if current.Len() > c.maxChars/2 {
				sentences = append(sentences, current.String())
				current.Reset()
			}
		}
	}

	if current.Len() > 0 {
		sentences = append(sentences, current.String())
	}

	return sentences
}

// splitByMaxChars splits text that exceeds maxChars into smaller pieces at sentence or line boundaries.
func (c *Chunker) splitByMaxChars(text string) []string {
	if len(text) <= c.maxChars {
		return []string{text}
	}

	// Try splitting on newlines first
	lines := strings.Split(text, "\n")
	if len(lines) > 1 {
		var result []string
		var current strings.Builder
		for i, line := range lines {
			if current.Len()+len(line)+1 > c.maxChars && current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			current.WriteString(line)
			if i < len(lines)-1 {
				current.WriteByte('\n')
			}
		}
		if current.Len() > 0 {
			result = append(result, current.String())
		}
		return result
	}

	// Try splitting on sentences
	sentences := c.splitIntoSentences(text)
	if len(sentences) > 1 {
		var result []string
		var current strings.Builder
		for _, sent := range sentences {
			if current.Len()+len(sent) > c.maxChars && current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			current.WriteString(sent)
		}
		if current.Len() > 0 {
			result = append(result, current.String())
		}
		return result
	}

	// Last resort: split at maxChars boundary on space
	var result []string
	remaining := text
	for len(remaining) > c.maxChars {
		cutPoint := c.maxChars
		// Find last space before cutPoint
		for cutPoint > c.maxChars/2 {
			if remaining[cutPoint] == ' ' {
				break
			}
			cutPoint--
		}
		if cutPoint <= c.maxChars/2 {
			cutPoint = c.maxChars // No good break point, force cut
		}
		result = append(result, remaining[:cutPoint])
		remaining = remaining[cutPoint:]
	}
	if len(remaining) > 0 {
		result = append(result, remaining)
	}
	return result
}
