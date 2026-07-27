package translate

import (
	"strings"
	"unicode"
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

// splitMarkdown splits text along markdown block boundaries.
// Code blocks (fenced) are kept intact and marked non-translatable.
func (c *Chunker) splitMarkdown(text string) []Chunk {
	var chunks []Chunk
	lines := strings.Split(text, "\n")

	var currentBlock strings.Builder
	inCodeBlock := false
	var codeBlockContent strings.Builder

	flushCurrent := func() {
		if currentBlock.Len() > 0 {
			content := currentBlock.String()
			// Further split if too long
			for _, sub := range c.splitByMaxChars(content) {
				chunks = append(chunks, Chunk{Text: sub, Translatable: true})
			}
			currentBlock.Reset()
		}
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Handle fenced code blocks
		if strings.HasPrefix(trimmed, "```") {
			if inCodeBlock {
				// End of code block
				codeBlockContent.WriteString(line)
				if i < len(lines)-1 {
					codeBlockContent.WriteByte('\n')
				}
				chunks = append(chunks, Chunk{Text: codeBlockContent.String(), Translatable: false})
				codeBlockContent.Reset()
				inCodeBlock = false
			} else {
				// Start of code block — flush current translatable text first
				flushCurrent()
				inCodeBlock = true
				codeBlockContent.WriteString(line)
				codeBlockContent.WriteByte('\n')
			}
			continue
		}

		if inCodeBlock {
			codeBlockContent.WriteString(line)
			if i < len(lines)-1 {
				codeBlockContent.WriteByte('\n')
			}
			continue
		}

		// Block boundaries: empty lines, headings
		isBlockBreak := trimmed == "" ||
			strings.HasPrefix(trimmed, "# ") ||
			strings.HasPrefix(trimmed, "## ") ||
			strings.HasPrefix(trimmed, "### ") ||
			strings.HasPrefix(trimmed, "#### ")

		if isBlockBreak && currentBlock.Len() > 0 {
			flushCurrent()
		}

		currentBlock.WriteString(line)
		if i < len(lines)-1 {
			currentBlock.WriteByte('\n')
		}
	}

	// Flush remaining
	if inCodeBlock {
		// Unclosed code block — treat as non-translatable
		chunks = append(chunks, Chunk{Text: codeBlockContent.String(), Translatable: false})
	} else {
		flushCurrent()
	}

	return chunks
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
