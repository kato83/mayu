package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

// UpsertEOLProduct upserts a product from endoflife.date.
func (s *PostgresStore) UpsertEOLProduct(ctx context.Context, product EOLProduct) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO eol_products (name, label, category, tags, version_command, last_modified_at, raw_json, last_synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (name) DO UPDATE SET
			label = EXCLUDED.label,
			category = EXCLUDED.category,
			tags = EXCLUDED.tags,
			version_command = EXCLUDED.version_command,
			last_modified_at = EXCLUDED.last_modified_at,
			raw_json = EXCLUDED.raw_json,
			last_synced_at = NOW()`,
		product.Name, product.Label, product.Category,
		pq.Array(product.Tags), product.VersionCommand, product.LastModifiedAt, product.RawJSON)
	if err != nil {
		return fmt.Errorf("upsert eol_product %s: %w", product.Name, err)
	}
	return nil
}

// UpsertEOLRelease upserts a release cycle from endoflife.date.
func (s *PostgresStore) UpsertEOLRelease(ctx context.Context, release EOLRelease) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO eol_releases (
			product_name, release_name, label, codename, release_date,
			is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_eoes, eoes_from, is_maintained, latest_version, latest_version_date, latest_version_link
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (product_name, release_name) DO UPDATE SET
			label = EXCLUDED.label,
			codename = EXCLUDED.codename,
			release_date = EXCLUDED.release_date,
			is_lts = EXCLUDED.is_lts,
			lts_from = EXCLUDED.lts_from,
			is_eoas = EXCLUDED.is_eoas,
			eoas_from = EXCLUDED.eoas_from,
			is_eol = EXCLUDED.is_eol,
			eol_from = EXCLUDED.eol_from,
			is_eoes = EXCLUDED.is_eoes,
			eoes_from = EXCLUDED.eoes_from,
			is_maintained = EXCLUDED.is_maintained,
			latest_version = EXCLUDED.latest_version,
			latest_version_date = EXCLUDED.latest_version_date,
			latest_version_link = EXCLUDED.latest_version_link`,
		release.ProductName, release.ReleaseName, release.Label,
		release.Codename, release.ReleaseDate,
		release.IsLts, release.LtsFrom,
		release.IsEoas, release.EoasFrom,
		release.IsEol, release.EolFrom,
		release.IsEoes, release.EoesFrom,
		release.IsMaintained,
		release.LatestVersion, release.LatestVersionDate, release.LatestVersionLink)
	if err != nil {
		return fmt.Errorf("upsert eol_release %s/%s: %w", release.ProductName, release.ReleaseName, err)
	}
	return nil
}

// UpsertEOLIdentifier upserts a product identifier (purl/cpe) mapping.
func (s *PostgresStore) UpsertEOLIdentifier(ctx context.Context, ident EOLIdentifier) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO eol_identifiers (product_name, identifier_type, identifier)
		VALUES ($1, $2, $3)
		ON CONFLICT (identifier_type, identifier) DO UPDATE SET
			product_name = EXCLUDED.product_name`,
		ident.ProductName, ident.IdentifierType, ident.Identifier)
	if err != nil {
		return fmt.Errorf("upsert eol_identifier %s/%s: %w", ident.IdentifierType, ident.Identifier, err)
	}
	return nil
}

// GetEOLByProduct returns EOL info for a product name.
func (s *PostgresStore) GetEOLByProduct(ctx context.Context, productName string) (*EOLProductDetail, error) {
	var name, label string
	var category, versionCommand sql.NullString
	var tags []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT name, label, category, tags, version_command FROM eol_products WHERE name = $1`,
		productName).Scan(&name, &label, &category, &tags, &versionCommand)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query eol_products: %w", err)
	}

	detail := &EOLProductDetail{
		Name:           name,
		Label:          label,
		Category:       category.String,
		VersionCommand: versionCommand.String,
	}
	if tags != nil {
		detail.Tags = parseTextArray(string(tags))
	}

	// Fetch releases
	releases, err := s.fetchEOLReleases(ctx, productName)
	if err != nil {
		return nil, err
	}
	detail.Releases = releases

	return detail, nil
}

// GetEOLByIdentifier finds EOL info by a purl or cpe identifier.
func (s *PostgresStore) GetEOLByIdentifier(ctx context.Context, identifierType, identifier string) (*EOLProductDetail, error) {
	var productName string
	err := s.db.QueryRowContext(ctx,
		`SELECT product_name FROM eol_identifiers WHERE identifier_type = $1 AND identifier = $2`,
		identifierType, identifier).Scan(&productName)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query eol_identifiers: %w", err)
	}
	return s.GetEOLByProduct(ctx, productName)
}

// fetchEOLReleases retrieves all releases for a product.
func (s *PostgresStore) fetchEOLReleases(ctx context.Context, productName string) ([]EOLReleaseInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT release_name, label, codename, release_date,
		       is_lts, is_eol, eol_from, is_eoas, eoas_from,
		       is_maintained, latest_version
		FROM eol_releases
		WHERE product_name = $1
		ORDER BY release_date DESC NULLS LAST`,
		productName)
	if err != nil {
		return nil, fmt.Errorf("query eol_releases: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var releases []EOLReleaseInfo
	for rows.Next() {
		var r EOLReleaseInfo
		var codename, releaseDate, eolFrom, eoasFrom, latestVersion sql.NullString
		var isLts, isEol, isEoas, isMaintained sql.NullBool
		if err := rows.Scan(&r.Name, &r.Label, &codename, &releaseDate,
			&isLts, &isEol, &eolFrom, &isEoas, &eoasFrom,
			&isMaintained, &latestVersion); err != nil {
			return nil, fmt.Errorf("scan eol_release: %w", err)
		}
		r.Codename = codename.String
		r.ReleaseDate = releaseDate.String
		if isLts.Valid {
			r.IsLts = &isLts.Bool
		}
		if isEol.Valid {
			r.IsEol = &isEol.Bool
		}
		r.EolFrom = eolFrom.String
		if isEoas.Valid {
			r.IsEoas = &isEoas.Bool
		}
		r.EoasFrom = eoasFrom.String
		if isMaintained.Valid {
			r.IsMaintained = &isMaintained.Bool
		}
		r.LatestVersion = latestVersion.String
		releases = append(releases, r)
	}
	return releases, rows.Err()
}
