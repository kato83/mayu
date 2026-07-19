package fetcher

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/model"
)

const (
	// epssAPIBaseURL is the base URL for the FIRST EPSS REST API.
	epssAPIBaseURL = "https://api.first.org/data/v1/epss"

	// epssCSVBaseURL is the base URL for EPSS bulk CSV downloads.
	epssCSVBaseURL = "https://epss.cyentia.com"

	// epssAPIDefaultLimit is the default number of results per API page.
	epssAPIDefaultLimit = 100

	// epssAPIMaxLimit is the maximum number of results per API page.
	epssAPIMaxLimit = 1000
)

// FetchEPSSByCSV downloads the current day's EPSS scores as a gzipped CSV file
// and returns parsed EPSSScore entries. This is the bulk import method suitable
// for full imports (200,000+ CVEs).
//
// The CSV file is downloaded from: https://epss.cyentia.com/epss_scores-current.csv.gz
// Format: first line is a comment with model version and score date,
// second line is the CSV header, subsequent lines are data rows.
func (f *Fetcher) FetchEPSSByCSV(ctx context.Context) ([]*model.EPSSScore, error) {
	u := fmt.Sprintf("%s/epss_scores-current.csv.gz", epssCSVBaseURL)
	return f.fetchEPSSCSV(ctx, u)
}

// FetchEPSSByCSVDate downloads EPSS scores for a specific date as a gzipped CSV.
// Date format: YYYY-MM-DD.
func (f *Fetcher) FetchEPSSByCSVDate(ctx context.Context, date string) ([]*model.EPSSScore, error) {
	u := fmt.Sprintf("%s/epss_scores-%s.csv.gz", epssCSVBaseURL, date)
	return f.fetchEPSSCSV(ctx, u)
}

// FetchEPSSByCVEs fetches EPSS scores for specific CVE IDs via the FIRST API.
// This is useful for targeted lookups (e.g., enriching search results).
// Maximum ~100 CVEs per request recommended by the API.
func (f *Fetcher) FetchEPSSByCVEs(ctx context.Context, cves []string) (*model.EPSSAPIResponse, error) {
	if len(cves) == 0 {
		return &model.EPSSAPIResponse{Status: "OK", Data: nil}, nil
	}

	u := fmt.Sprintf("%s?cve=%s", epssAPIBaseURL, strings.Join(cves, ","))
	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS by CVEs: %w", err)
	}

	return model.ParseEPSSAPIResponse(data)
}

// FetchEPSSAll fetches all EPSS scores via the FIRST API with pagination.
// This method iterates through all pages until all data is retrieved.
// For bulk imports, FetchEPSSByCSV is more efficient.
func (f *Fetcher) FetchEPSSAll(ctx context.Context) ([]*model.EPSSScore, error) {
	var allScores []*model.EPSSScore
	offset := 0
	limit := epssAPIMaxLimit

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		u := fmt.Sprintf("%s?offset=%d&limit=%d", epssAPIBaseURL, offset, limit)
		data, err := f.download(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("fetch EPSS page at offset %d: %w", offset, err)
		}

		resp, err := model.ParseEPSSAPIResponse(data)
		if err != nil {
			return nil, fmt.Errorf("parse EPSS page at offset %d: %w", offset, err)
		}

		for i := range resp.Data {
			score, err := resp.Data[i].ParseEPSSScore()
			if err != nil {
				// Skip invalid entries but continue
				continue
			}
			allScores = append(allScores, score)
		}

		// Check if we've retrieved all data
		if len(resp.Data) < limit || offset+len(resp.Data) >= resp.Total {
			break
		}

		offset += len(resp.Data)
	}

	return allScores, nil
}

// fetchEPSSCSV downloads and parses a gzipped EPSS CSV file.
func (f *Fetcher) fetchEPSSCSV(ctx context.Context, url string) ([]*model.EPSSScore, error) {
	compressed, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download EPSS CSV from %s: %w", url, err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader for EPSS CSV: %w", err)
	}
	defer func() { _ = gr.Close() }()

	// Limit decompressed size
	limited := io.LimitReader(gr, MaxResponseSize+1)

	return parseEPSSCSV(limited)
}

// parseEPSSCSV parses EPSS CSV content from a reader.
// The CSV format is:
//
//	#model_version:v2025.03.05,score_date:2026-07-19T00:00:00+0000
//	cve,epss,percentile
//	CVE-2014-6271,0.97544,0.99998
//	CVE-2023-38831,0.94218,0.99923
//	...
func parseEPSSCSV(r io.Reader) ([]*model.EPSSScore, error) {
	scanner := bufio.NewScanner(r)

	// Increase scanner buffer for potentially long lines
	const maxLineSize = 1024 * 1024 // 1MB
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	var scoreDate time.Time
	headerFound := false
	var scores []*model.EPSSScore

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse comment line (first line) containing model version and score date
		if strings.HasPrefix(line, "#") {
			date, err := extractEPSSScoreDate(line)
			if err == nil {
				scoreDate = date
			}
			continue
		}

		// Skip CSV header line
		if !headerFound {
			if strings.HasPrefix(strings.ToLower(line), "cve,") {
				headerFound = true
				continue
			}
			// If it doesn't look like a header, try to parse as data
			headerFound = true
		}

		// Parse data line
		score, err := model.ParseEPSSCSVLine(line, scoreDate)
		if err != nil {
			// Skip invalid lines (e.g., malformed entries)
			continue
		}

		scores = append(scores, score)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan EPSS CSV: %w", err)
	}

	if len(scores) == 0 {
		return nil, fmt.Errorf("no valid EPSS scores found in CSV")
	}

	return scores, nil
}

// extractEPSSScoreDate extracts the score_date from an EPSS CSV comment line.
// Example: #model_version:v2025.03.05,score_date:2026-07-19T00:00:00+0000
func extractEPSSScoreDate(commentLine string) (time.Time, error) {
	// Remove leading # and spaces
	line := strings.TrimPrefix(commentLine, "#")
	line = strings.TrimSpace(line)

	// Look for score_date field
	parts := strings.Split(line, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "score_date:") {
			dateStr := strings.TrimPrefix(part, "score_date:")
			dateStr = strings.TrimSpace(dateStr)

			// Try parsing with various formats
			formats := []string{
				"2006-01-02T15:04:05+0000",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05-07:00",
				"2006-01-02",
			}
			for _, format := range formats {
				t, err := time.Parse(format, dateStr)
				if err == nil {
					return t, nil
				}
			}
			return time.Time{}, fmt.Errorf("cannot parse score_date %q", dateStr)
		}
	}

	return time.Time{}, fmt.Errorf("score_date not found in comment line")
}

// EPSSCSVScoreDate returns the score date string for the EPSS CSV files,
// formatted for use in the download URL.
func EPSSCSVScoreDate(t time.Time) string {
	return t.Format("2006-01-02")
}

// ParseEPSSCSVReader parses EPSS CSV content from a reader. This is exported
// for use by the ingest layer when processing already-downloaded CSV data.
func ParseEPSSCSVReader(r io.Reader) ([]*model.EPSSScore, error) {
	return parseEPSSCSV(r)
}

// EPSSScoreDateFromFilename extracts the score date from an EPSS CSV filename.
// Filename patterns:
//   - epss_scores-current.csv.gz → returns empty (use today's date)
//   - epss_scores-2026-07-19.csv.gz → returns "2026-07-19"
func EPSSScoreDateFromFilename(filename string) string {
	// Remove extension(s)
	name := strings.TrimSuffix(filename, ".gz")
	name = strings.TrimSuffix(name, ".csv")

	// Extract date part after "epss_scores-"
	prefix := "epss_scores-"
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	datePart := strings.TrimPrefix(name, prefix)
	if datePart == "current" {
		return ""
	}

	// Validate it looks like a date
	if len(datePart) == 10 {
		if _, err := strconv.Atoi(datePart[:4]); err == nil {
			return datePart
		}
	}
	return ""
}
