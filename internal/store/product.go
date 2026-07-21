package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/model"
)

// UpsertProductIdentifiers stores product identifiers for vulnerabilities.
// It replaces all existing identifiers for each unique (vulnerability_id, source)
// combination found in the input and inserts the new ones.
//
// This approach ensures that re-imports correctly replace stale data without
// affecting identifiers contributed by other sources.
func (s *PostgresStore) UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error {
	if len(identifiers) == 0 {
		return nil
	}

	// Group identifiers by (vulnerability_id, source) for batch deletion + insertion
	type key struct {
		vulnID string
		source string
	}
	grouped := make(map[key][]*model.ProductIdentifier)
	for _, pi := range identifiers {
		k := key{vulnID: pi.VulnerabilityID, source: pi.Source}
		grouped[k] = append(grouped[k], pi)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for k, pis := range grouped {
		// Delete existing identifiers for this (vulnerability_id, source) combo
		_, err := tx.ExecContext(ctx,
			`DELETE FROM product_identifiers WHERE vulnerability_id = $1 AND source = $2`,
			k.vulnID, k.source)
		if err != nil {
			return fmt.Errorf("delete product_identifiers for %s/%s: %w", k.vulnID, k.source, err)
		}

		// Bulk insert new identifiers
		if err := bulkInsertProductIdentifiers(ctx, tx, pis); err != nil {
			return fmt.Errorf("insert product_identifiers for %s/%s: %w", k.vulnID, k.source, err)
		}
	}

	return tx.Commit()
}

// bulkInsertProductIdentifiers inserts a batch of product identifiers within a transaction.
func bulkInsertProductIdentifiers(ctx context.Context, tx *sql.Tx, pis []*model.ProductIdentifier) error {
	if len(pis) == 0 {
		return nil
	}

	// Insert in sub-batches to avoid exceeding PostgreSQL parameter limits (max 65535)
	const maxParams = 60000
	const colsPerRow = 24
	maxRowsPerBatch := maxParams / colsPerRow

	for i := 0; i < len(pis); i += maxRowsPerBatch {
		end := i + maxRowsPerBatch
		if end > len(pis) {
			end = len(pis)
		}
		if err := bulkInsertProductIdentifiersChunk(ctx, tx, pis[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func bulkInsertProductIdentifiersChunk(ctx context.Context, tx *sql.Tx, pis []*model.ProductIdentifier) error {
	if len(pis) == 0 {
		return nil
	}

	query := `INSERT INTO product_identifiers (
		vulnerability_id, source,
		purl_type, purl_namespace, purl_name, purl_version, purl_qualifiers, purl_subpath,
		cpe_part, cpe_vendor, cpe_product, cpe_version, cpe_update, cpe_edition,
		cpe_language, cpe_sw_edition, cpe_target_sw, cpe_target_hw, cpe_other,
		ecosystem, name, vendor, product, version_constraint
	) VALUES `

	args := make([]interface{}, 0, len(pis)*24)
	var valueStrings []string

	for i, pi := range pis {
		base := i*24 + 1
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base, base+1, base+2, base+3, base+4, base+5, base+6, base+7,
			base+8, base+9, base+10, base+11, base+12, base+13,
			base+14, base+15, base+16, base+17, base+18,
			base+19, base+20, base+21, base+22, base+23,
		))
		args = append(args,
			pi.VulnerabilityID, pi.Source,
			nullIfEmpty(pi.PurlType), nullIfEmpty(pi.PurlNamespace), nullIfEmpty(pi.PurlName),
			nullIfEmpty(pi.PurlVersion), nullIfEmpty(pi.PurlQualifiers), nullIfEmpty(pi.PurlSubpath),
			nullIfEmpty(pi.CPEPart), nullIfEmpty(pi.CPEVendor), nullIfEmpty(pi.CPEProduct),
			nullIfEmpty(pi.CPEVersion), nullIfEmpty(pi.CPEUpdate), nullIfEmpty(pi.CPEEdition),
			nullIfEmpty(pi.CPELanguage), nullIfEmpty(pi.CPESWEdition), nullIfEmpty(pi.CPETargetSW),
			nullIfEmpty(pi.CPETargetHW), nullIfEmpty(pi.CPEOther),
			nullIfEmpty(pi.Ecosystem), nullIfEmpty(pi.Name),
			nullIfEmpty(pi.Vendor), nullIfEmpty(pi.Product),
			nullableRawJSON(pi.VersionConstraint),
		)
	}

	query += strings.Join(valueStrings, ", ")
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}
