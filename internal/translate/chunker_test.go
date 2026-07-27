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
