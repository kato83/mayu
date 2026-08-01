package fetcher

import "context"

const (
	// DefaultNVDSourceURL is the NVD Source API endpoint.
	DefaultNVDSourceURL = "https://services.nvd.nist.gov/rest/json/source/2.0"
)

// WithNVDSourceURL sets a custom URL for the NVD Source API (useful for testing).
func WithNVDSourceURL(url string) Option {
	return func(f *Fetcher) {
		f.nvdSourceURL = url
	}
}

// FetchNVDSources downloads the NVD source organization list from the Source API.
// Returns the raw JSON response body.
func (f *Fetcher) FetchNVDSources(ctx context.Context) ([]byte, error) {
	url := f.nvdSourceURL
	if url == "" {
		url = DefaultNVDSourceURL
	}
	return f.download(ctx, url)
}
