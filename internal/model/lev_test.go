package model

import (
	"math"
	"testing"
	"time"
)

func TestP30ToP1(t *testing.T) {
	tests := []struct {
		name string
		p30  float64
		want float64
	}{
		{"zero probability", 0.0, 0.0},
		{"full probability", 1.0, 1.0},
		{"negative clamp", -0.1, 0.0},
		{"above one clamp", 1.5, 1.0},
		{
			"typical low EPSS (0.003)",
			0.003,
			// P1 = 1 - (1-0.003)^(1/30) ≈ 0.0001001
			1 - math.Pow(1-0.003, 1.0/30.0),
		},
		{
			"high EPSS (0.9)",
			0.9,
			// P1 = 1 - (1-0.9)^(1/30) = 1 - 0.1^(1/30)
			1 - math.Pow(0.1, 1.0/30.0),
		},
		{
			"medium EPSS (0.5)",
			0.5,
			1 - math.Pow(0.5, 1.0/30.0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p30ToP1(tt.p30)
			if math.Abs(got-tt.want) > 1e-10 {
				t.Errorf("p30ToP1(%f) = %f, want %f", tt.p30, got, tt.want)
			}
		})
	}
}

func TestP30ToP1_Consistency(t *testing.T) {
	// Verify that converting P1 back to P30 gives the original value.
	// P30 = 1 - (1-P1)^30
	originalP30 := 0.05
	p1 := p30ToP1(originalP30)
	reconstructedP30 := 1 - math.Pow(1-p1, 30)

	if math.Abs(reconstructedP30-originalP30) > 1e-10 {
		t.Errorf("round-trip failed: original P30=%f, P1=%f, reconstructed P30=%f",
			originalP30, p1, reconstructedP30)
	}
}

func TestComputeLEV_InKEV(t *testing.T) {
	input := LEVInput{
		CVEID: "CVE-2023-12345",
		InKEV: true,
		EPSSScores: []EPSSDailyScore{
			{Date: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), P30: 0.5},
		},
	}

	result := ComputeLEV(input)

	if result.LEV != 1.0 {
		t.Errorf("ComputeLEV with InKEV=true: got LEV=%f, want 1.0", result.LEV)
	}
	if !result.InKEV {
		t.Error("ComputeLEV with InKEV=true: InKEV should be true")
	}
	if result.CVEID != "CVE-2023-12345" {
		t.Errorf("ComputeLEV: CVEID = %q, want %q", result.CVEID, "CVE-2023-12345")
	}
	if result.EPSSScoreCount != 1 {
		t.Errorf("ComputeLEV: EPSSScoreCount = %d, want 1", result.EPSSScoreCount)
	}
}

func TestComputeLEV_InKEV_NoEPSS(t *testing.T) {
	input := LEVInput{
		CVEID:      "CVE-2023-99999",
		InKEV:      true,
		EPSSScores: nil,
	}

	result := ComputeLEV(input)

	if result.LEV != 1.0 {
		t.Errorf("ComputeLEV with InKEV=true, no EPSS: got LEV=%f, want 1.0", result.LEV)
	}
	if result.FirstEPSSDate != nil {
		t.Error("ComputeLEV with no EPSS: FirstEPSSDate should be nil")
	}
}

func TestComputeLEV_NoData(t *testing.T) {
	input := LEVInput{
		CVEID:      "CVE-2024-00001",
		InKEV:      false,
		EPSSScores: nil,
	}

	result := ComputeLEV(input)

	if result.LEV != 0.0 {
		t.Errorf("ComputeLEV with no data: got LEV=%f, want 0.0", result.LEV)
	}
	if result.EPSSScoreCount != 0 {
		t.Errorf("ComputeLEV with no data: EPSSScoreCount = %d, want 0", result.EPSSScoreCount)
	}
}

func TestComputeLEV_SingleDay(t *testing.T) {
	// With a single day of EPSS=0.5:
	// P1 = 1 - (1-0.5)^(1/30) = 1 - 0.5^(1/30) ≈ 0.02284
	// LEV = 1 - (1 - P1) = P1 ≈ 0.02284
	p30 := 0.5
	expectedP1 := 1 - math.Pow(1-p30, 1.0/30.0)
	expectedLEV := expectedP1 // single day: LEV = P1

	input := LEVInput{
		CVEID: "CVE-2024-00002",
		InKEV: false,
		EPSSScores: []EPSSDailyScore{
			{Date: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), P30: p30},
		},
	}

	result := ComputeLEV(input)

	if math.Abs(result.LEV-expectedLEV) > 1e-10 {
		t.Errorf("ComputeLEV single day (P30=0.5): got LEV=%f, want %f", result.LEV, expectedLEV)
	}
	if result.EPSSScoreCount != 1 {
		t.Errorf("ComputeLEV: EPSSScoreCount = %d, want 1", result.EPSSScoreCount)
	}
}

func TestComputeLEV_MultipleDays_Constant(t *testing.T) {
	// 30 days of constant P30=0.5:
	// P1 = 1 - 0.5^(1/30) for each day
	// LEV = 1 - (1-P1)^30 = 1 - (0.5^(1/30))^30 = 1 - 0.5 = 0.5
	p30 := 0.5
	days := 30
	expectedLEV := 0.5 // exactly P30 for 30 days of constant score

	var scores []EPSSDailyScore
	baseDate := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < days; i++ {
		scores = append(scores, EPSSDailyScore{
			Date: baseDate.AddDate(0, 0, i),
			P30:  p30,
		})
	}

	input := LEVInput{
		CVEID:      "CVE-2024-00003",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	if math.Abs(result.LEV-expectedLEV) > 1e-10 {
		t.Errorf("ComputeLEV 30 days constant P30=0.5: got LEV=%f, want %f", result.LEV, expectedLEV)
	}
}

func TestComputeLEV_MultipleDays_HighScore(t *testing.T) {
	// 60 days of P30=0.9 (very high EPSS):
	// P1 = 1 - 0.1^(1/30) ≈ 0.0741
	// LEV = 1 - (1 - P1)^60 = 1 - (0.1^(1/30))^60 = 1 - 0.1^2 = 1 - 0.01 = 0.99
	p30 := 0.9
	days := 60
	p1 := 1 - math.Pow(1-p30, 1.0/30.0)
	expectedLEV := 1 - math.Pow(1-p1, float64(days))

	var scores []EPSSDailyScore
	baseDate := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < days; i++ {
		scores = append(scores, EPSSDailyScore{
			Date: baseDate.AddDate(0, 0, i),
			P30:  p30,
		})
	}

	input := LEVInput{
		CVEID:      "CVE-2024-00004",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	if math.Abs(result.LEV-expectedLEV) > 1e-6 {
		t.Errorf("ComputeLEV 60 days P30=0.9: got LEV=%f, want %f", result.LEV, expectedLEV)
	}
	if result.LEV < 0.98 {
		t.Errorf("ComputeLEV 60 days P30=0.9: LEV should be > 0.98, got %f", result.LEV)
	}
}

func TestComputeLEV_MultipleDays_LowScore(t *testing.T) {
	// 365 days of P30=0.001 (very low EPSS):
	// P1 = 1 - (1-0.001)^(1/30) ≈ 0.001/30 ≈ 0.0000333
	// LEV = 1 - (1-P1)^365 which is small
	p30 := 0.001
	days := 365
	p1 := 1 - math.Pow(1-p30, 1.0/30.0)
	expectedLEV := 1 - math.Pow(1-p1, float64(days))

	var scores []EPSSDailyScore
	baseDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < days; i++ {
		scores = append(scores, EPSSDailyScore{
			Date: baseDate.AddDate(0, 0, i),
			P30:  p30,
		})
	}

	input := LEVInput{
		CVEID:      "CVE-2024-00005",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	if math.Abs(result.LEV-expectedLEV) > 1e-6 {
		t.Errorf("ComputeLEV 365 days P30=0.001: got LEV=%f, want %f", result.LEV, expectedLEV)
	}
	// With very low EPSS for a year, LEV should still be modest
	if result.LEV > 0.05 {
		t.Errorf("ComputeLEV 365 days P30=0.001: LEV should be < 0.05, got %f", result.LEV)
	}
}

func TestComputeLEV_VaryingScores(t *testing.T) {
	// Test with varying EPSS scores across days
	scores := []EPSSDailyScore{
		{Date: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), P30: 0.01},
		{Date: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC), P30: 0.05},
		{Date: time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC), P30: 0.10},
		{Date: time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC), P30: 0.50},
		{Date: time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC), P30: 0.90},
	}

	// Manual computation
	var logProduct float64
	for _, s := range scores {
		p1 := 1 - math.Pow(1-s.P30, 1.0/30.0)
		logProduct += math.Log(1 - p1)
	}
	expectedLEV := 1 - math.Exp(logProduct)

	input := LEVInput{
		CVEID:      "CVE-2024-00006",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	if math.Abs(result.LEV-expectedLEV) > 1e-10 {
		t.Errorf("ComputeLEV varying scores: got LEV=%f, want %f", result.LEV, expectedLEV)
	}

	// Verify monotonicity: more days → higher LEV
	if result.LEV <= 0 {
		t.Error("ComputeLEV varying scores: LEV should be > 0")
	}
}

func TestComputeLEV_ZeroScores(t *testing.T) {
	// All EPSS scores are 0 → P1 = 0 for each day → LEV = 0
	scores := []EPSSDailyScore{
		{Date: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), P30: 0.0},
		{Date: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC), P30: 0.0},
		{Date: time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC), P30: 0.0},
	}

	input := LEVInput{
		CVEID:      "CVE-2024-00007",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	if result.LEV != 0.0 {
		t.Errorf("ComputeLEV all zeros: got LEV=%f, want 0.0", result.LEV)
	}
	if result.EPSSScoreCount != 3 {
		t.Errorf("ComputeLEV all zeros: EPSSScoreCount = %d, want 3", result.EPSSScoreCount)
	}
}

func TestComputeLEV_Dates(t *testing.T) {
	// Verify first/last date tracking
	scores := []EPSSDailyScore{
		{Date: time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC), P30: 0.1},
		{Date: time.Date(2024, 6, 20, 0, 0, 0, 0, time.UTC), P30: 0.2},
		{Date: time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC), P30: 0.3},
	}

	input := LEVInput{
		CVEID:      "CVE-2024-00008",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	if result.FirstEPSSDate == nil {
		t.Fatal("ComputeLEV: FirstEPSSDate should not be nil")
	}
	if result.LastEPSSDate == nil {
		t.Fatal("ComputeLEV: LastEPSSDate should not be nil")
	}
	expectedFirst := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	expectedLast := time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC)
	if !result.FirstEPSSDate.Equal(expectedFirst) {
		t.Errorf("ComputeLEV: FirstEPSSDate = %v, want %v", result.FirstEPSSDate, expectedFirst)
	}
	if !result.LastEPSSDate.Equal(expectedLast) {
		t.Errorf("ComputeLEV: LastEPSSDate = %v, want %v", result.LastEPSSDate, expectedLast)
	}
}

func TestComputeLEV_Monotonicity(t *testing.T) {
	// More days of exposure → higher LEV (with same EPSS score)
	p30 := 0.1
	baseDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	var prevLEV float64
	for days := 1; days <= 365; days += 30 {
		var scores []EPSSDailyScore
		for i := 0; i < days; i++ {
			scores = append(scores, EPSSDailyScore{
				Date: baseDate.AddDate(0, 0, i),
				P30:  p30,
			})
		}

		input := LEVInput{
			CVEID:      "CVE-2024-MONO",
			InKEV:      false,
			EPSSScores: scores,
		}

		result := ComputeLEV(input)

		if result.LEV < prevLEV {
			t.Errorf("ComputeLEV monotonicity violated: %d days LEV=%f < previous LEV=%f",
				days, result.LEV, prevLEV)
		}
		prevLEV = result.LEV
	}
}

func TestComputeLEV_ApproximationComparison(t *testing.T) {
	// Verify that our rigorous approach gives a higher LEV than the
	// P30/30 approximation for high EPSS scores (where approximation underestimates).
	p30 := 0.9
	days := 30

	var scores []EPSSDailyScore
	baseDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < days; i++ {
		scores = append(scores, EPSSDailyScore{
			Date: baseDate.AddDate(0, 0, i),
			P30:  p30,
		})
	}

	input := LEVInput{
		CVEID:      "CVE-2024-APPROX",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	// Approximation: P1_approx = P30/30, LEV_approx = 1 - (1 - P30/30)^30
	p1Approx := p30 / 30.0
	levApprox := 1 - math.Pow(1-p1Approx, float64(days))

	// For high EPSS scores, rigorous should give higher LEV than approximation
	if result.LEV <= levApprox {
		t.Errorf("Rigorous LEV (%f) should be > approximate LEV (%f) for high P30=%f",
			result.LEV, levApprox, p30)
	}

	t.Logf("P30=%.1f, 30 days: rigorous LEV=%.6f, approx LEV=%.6f (diff=%.6f)",
		p30, result.LEV, levApprox, result.LEV-levApprox)
}

func TestComputeLEV_LongHistory(t *testing.T) {
	// Simulate ~2 years (730 days) of moderate EPSS (0.05)
	// LEV should be substantial but not 1.0
	p30 := 0.05
	days := 730

	var scores []EPSSDailyScore
	baseDate := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < days; i++ {
		scores = append(scores, EPSSDailyScore{
			Date: baseDate.AddDate(0, 0, i),
			P30:  p30,
		})
	}

	input := LEVInput{
		CVEID:      "CVE-2023-LONG",
		InKEV:      false,
		EPSSScores: scores,
	}

	result := ComputeLEV(input)

	// With P30=0.05 over 730 days:
	// P1 = 1 - (0.95)^(1/30) ≈ 0.001711
	// LEV = 1 - (1-P1)^730 ≈ 1 - (0.998289)^730 ≈ 0.714
	if result.LEV < 0.5 || result.LEV > 0.95 {
		t.Errorf("ComputeLEV 730 days P30=0.05: expected LEV in [0.5, 0.95], got %f", result.LEV)
	}

	t.Logf("730 days P30=0.05: LEV=%.6f", result.LEV)
}
