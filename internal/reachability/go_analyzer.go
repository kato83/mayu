package reachability

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// GoAnalyzer performs reachability analysis by parsing Go source files
// and checking for references to vulnerable symbols via AST inspection.
//
// The analysis is conservative: it detects syntactic references to symbols
// (import + usage), not full call-graph reachability. A symbol is considered
// "reachable" if the package is imported and the symbol name appears in a
// selector expression (e.g., http.Get) or a method call on a matching type.
type GoAnalyzer struct{}

// NewGoAnalyzer creates a new GoAnalyzer instance.
func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{}
}

// Analyze scans Go source files in projectDir for references to the given
// vulnerable symbols. It groups results by (VulnID, Package) combination.
func (a *GoAnalyzer) Analyze(ctx context.Context, projectDir string, symbols []VulnSymbol) ([]Result, error) {
	if len(symbols) == 0 {
		return nil, nil
	}

	// Group symbols by package for efficient lookup.
	// Key: import path → list of VulnSymbol
	pkgSymbols := make(map[string][]VulnSymbol)
	for _, s := range symbols {
		pkgSymbols[s.Package] = append(pkgSymbols[s.Package], s)
	}

	// Collect all .go files in the project directory (recursive).
	goFiles, err := collectGoFiles(projectDir)
	if err != nil {
		return nil, err
	}

	if len(goFiles) == 0 {
		return buildResults(symbols, nil), nil
	}

	// Parse all Go files and analyze imports + symbol usage.
	fset := token.NewFileSet()
	var allEvidence []evidenceEntry

	for _, filePath := range goFiles {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		evidence, err := analyzeFile(fset, filePath, projectDir, pkgSymbols)
		if err != nil {
			// Skip files that cannot be parsed (e.g., generated code with syntax errors).
			continue
		}
		allEvidence = append(allEvidence, evidence...)
	}

	return buildResults(symbols, allEvidence), nil
}

// evidenceEntry is an internal struct pairing a VulnSymbol with its Evidence.
type evidenceEntry struct {
	vulnID string
	pkg    string
	symbol string
	file   string
	line   int
}

// analyzeFile parses a single Go file and checks for references to vulnerable symbols.
func analyzeFile(fset *token.FileSet, filePath, projectDir string, pkgSymbols map[string][]VulnSymbol) ([]evidenceEntry, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		return nil, err
	}

	// Build a map of import path → local name (alias or last segment of path).
	importMap := buildImportMap(file)

	// Find which vulnerable packages are imported in this file.
	// Key: local name → import path
	localToPath := make(map[string]string)
	for path, localName := range importMap {
		if _, ok := pkgSymbols[path]; ok {
			localToPath[localName] = path
		}
	}

	if len(localToPath) == 0 {
		return nil, nil
	}

	relPath, err := filepath.Rel(projectDir, filePath)
	if err != nil {
		relPath = filePath
	}

	// Walk the AST looking for selector expressions that match vulnerable symbols.
	var evidence []evidenceEntry
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// Check if the selector's X is an identifier matching an imported vulnerable package.
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			// Could be a chained selector like pkg.Type.Method — check nested.
			if innerSel, ok := sel.X.(*ast.SelectorExpr); ok {
				if innerIdent, ok := innerSel.X.(*ast.Ident); ok {
					importPath, exists := localToPath[innerIdent.Name]
					if exists {
						// This matches pkg.Type.Method pattern.
						typeName := innerSel.Sel.Name
						methodName := sel.Sel.Name
						compositeName := typeName + "." + methodName

						vulnSyms := pkgSymbols[importPath]
						for _, vs := range vulnSyms {
							if vs.Symbol == compositeName {
								pos := fset.Position(sel.Pos())
								evidence = append(evidence, evidenceEntry{
									vulnID: vs.VulnID,
									pkg:    vs.Package,
									symbol: vs.Symbol,
									file:   relPath,
									line:   pos.Line,
								})
							}
						}
					}
				}
			}
			return true
		}

		importPath, exists := localToPath[ident.Name]
		if !exists {
			return true
		}

		// Match the selector name against vulnerable symbols.
		selectorName := sel.Sel.Name
		vulnSyms := pkgSymbols[importPath]
		for _, vs := range vulnSyms {
			// Direct function match: e.g., http.Get → symbol "Get"
			if vs.Symbol == selectorName {
				pos := fset.Position(sel.Pos())
				evidence = append(evidence, evidenceEntry{
					vulnID: vs.VulnID,
					pkg:    vs.Package,
					symbol: vs.Symbol,
					file:   relPath,
					line:   pos.Line,
				})
				continue
			}

			// Type constructor/field match: symbol "Client.Do" matches http.Client usage.
			// When we see http.Client, that's a reference to the type; the method call
			// is on the instance (client.Do), which we cannot resolve without type info.
			// However, we match "Type" from "Type.Method" when we see pkg.Type.
			parts := strings.SplitN(vs.Symbol, ".", 2)
			if len(parts) == 2 && parts[0] == selectorName {
				// pkg.Type seen — record as evidence since the type is used.
				pos := fset.Position(sel.Pos())
				evidence = append(evidence, evidenceEntry{
					vulnID: vs.VulnID,
					pkg:    vs.Package,
					symbol: vs.Symbol,
					file:   relPath,
					line:   pos.Line,
				})
			}
		}

		return true
	})

	return evidence, nil
}

// buildImportMap creates a mapping from import path to local name.
// If an alias is specified, it uses the alias; otherwise it uses the last
// path segment (e.g., "net/http" → "http").
func buildImportMap(file *ast.File) map[string]string {
	m := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var localName string
		if imp.Name != nil && imp.Name.Name != "." && imp.Name.Name != "_" {
			localName = imp.Name.Name
		} else if imp.Name != nil && imp.Name.Name == "_" {
			// Blank import — skip, no symbols are used.
			continue
		} else if imp.Name != nil && imp.Name.Name == "." {
			// Dot import — symbols are used without qualifier.
			// We handle this as a special case: use "." as the local name.
			localName = "."
			m[path] = localName
			continue
		} else {
			// Use last segment of the import path.
			parts := strings.Split(path, "/")
			localName = parts[len(parts)-1]
		}
		m[path] = localName
	}
	return m
}

// collectGoFiles recursively finds all .go files in dir, excluding:
// - testdata directories
// - vendor directories
// - _* and .* directories
// - *_test.go files (to focus on production code reachability)
func collectGoFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "testdata" || strings.HasPrefix(base, "_") || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

// buildResults aggregates evidence entries into Result objects grouped by (VulnID, Package).
func buildResults(symbols []VulnSymbol, evidence []evidenceEntry) []Result {
	// Build unique (vulnID, pkg) keys from the input symbols.
	type key struct{ vulnID, pkg string }
	keySet := make(map[key]bool)
	for _, s := range symbols {
		keySet[key{s.VulnID, s.Package}] = true
	}

	// Group evidence by key.
	evidenceMap := make(map[key][]Evidence)
	for _, e := range evidence {
		k := key{e.vulnID, e.pkg}
		evidenceMap[k] = append(evidenceMap[k], Evidence{
			Symbol: e.pkg + "." + e.symbol,
			File:   e.file,
			Line:   e.line,
		})
	}

	// Deduplicate evidence (same symbol+file+line may appear multiple times).
	for k, evList := range evidenceMap {
		evidenceMap[k] = deduplicateEvidence(evList)
	}

	// Build results for all keys.
	results := make([]Result, 0, len(keySet))
	for k := range keySet {
		ev := evidenceMap[k]
		results = append(results, Result{
			VulnID:    k.vulnID,
			Package:   k.pkg,
			Reachable: len(ev) > 0,
			Evidence:  ev,
		})
	}

	return results
}

// deduplicateEvidence removes duplicate evidence entries.
func deduplicateEvidence(evidence []Evidence) []Evidence {
	type evKey struct {
		symbol string
		file   string
		line   int
	}
	seen := make(map[evKey]bool)
	var result []Evidence
	for _, e := range evidence {
		k := evKey{e.Symbol, e.File, e.Line}
		if !seen[k] {
			seen[k] = true
			result = append(result, e)
		}
	}
	return result
}
