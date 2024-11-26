package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
)

// main is the entry point of the program. It runs the main logic and handles fatal errors.
func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	log.SetPrefix(time.Now().Format("2006-01-02T15:04:05-07:00") + "\tDEBUG\t")

	log.Println("Starting trivy-plugin-epss...")
	if err := run(); err != nil {
		log.Fatal(err)
	}
	log.Println("Plugin execution completed successfully")
}

// run executes the main logic of the plugin:
// - reads vulnerability report from stdin
// - fetches EPSS scores for CVEs
// - enriches report with scores
// - outputs enriched report to stdout
func run() error {
	// Read report from stdin
	log.Println("Reading vulnerability report from stdin...")
	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return err
	}

	// Initialize maps to store EPSS data
	epssScores := make(map[string]float64)
	epssPercentiles := make(map[string]float64)
	epssDates := make(map[string]string)

	// Collect all unique CVEs from the report
	log.Println("Collecting unique CVEs from report...")
	cveSet := make(map[string]struct{})
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			cveSet[vuln.VulnerabilityID] = struct{}{}
		}
	}

	// Convert set to slice for batch processing
	cves := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cves = append(cves, cve)
	}
	log.Printf("Found %d unique CVEs to process", len(cves))

	// Fetch EPSS scores for all CVEs
	log.Println("Fetching EPSS scores from FIRST.org API...")
	if err := fetchBulkEPSSScores(cves, epssScores, epssPercentiles, epssDates); err != nil {
		log.Printf("failed to fetch EPSS scores: %v", err)
		return err
	}

	// Update vulnerabilities with their EPSS scores
	log.Println("Enriching vulnerability report with EPSS scores...")
	for _, result := range report.Results {
		for i := range result.Vulnerabilities {
			vuln := &result.Vulnerabilities[i]
			if score, ok := epssScores[vuln.VulnerabilityID]; ok {
				percentile := epssPercentiles[vuln.VulnerabilityID]
				date := epssDates[vuln.VulnerabilityID]

				// Create map to store EPSS score as custom data
				customData := map[string]interface{}{
					"epss_score":      score,
					"epss_percentile": percentile,
					"epss_date":       date,
					"epss_source":     "FIRST.org",
				}
				vuln.Custom = customData
			}
		}
	}

	// Write updated report to stdout
	log.Println("Writing enriched report to stdout...")
	return json.NewEncoder(os.Stdout).Encode(report)
}

// fetchBulkEPSSScores retrieves EPSS scores for a list of CVEs using the FIRST.org API.
// It processes CVEs in batches to respect API limits.
// Parameters:
// - cves: slice of CVE IDs to fetch scores for
// - epssScores: map to store the scores
// - epssPercentiles: map to store the percentiles
// - epssDates: map to store the dates
func fetchBulkEPSSScores(cves []string, epssScores map[string]float64, epssPercentiles map[string]float64, epssDates map[string]string) error {
	// Define batch size
	const batchSize = 100

	// Process CVEs in batches
	for i := 0; i < len(cves); i += batchSize {
		end := i + batchSize
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[i:end]

		log.Printf("Processing batch %d-%d of %d CVEs", i, end, len(cves))

		// Build comma-separated list of CVEs
		cveList := strings.Join(batch, ",")

		// Make request to EPSS API
		log.Printf("Sending request to EPSS API for %d CVEs", len(batch))
		resp, err := http.Get("https://api.first.org/data/v1/epss?cve=" + cveList)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		// Define response structure
		var bulkResp struct {
			Status string `json:"status"`
			Data   []struct {
				Cve        string `json:"cve"`
				Epss       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
			return err
		}

		// Store data in maps
		log.Printf("Received EPSS scores for %d CVEs", len(bulkResp.Data))
		for _, item := range bulkResp.Data {
			score, err := strconv.ParseFloat(item.Epss, 64)
			if err != nil {
				log.Printf("Error parsing EPSS score for %s: %v", item.Cve, err)
				continue
			}
			percentile, err := strconv.ParseFloat(item.Percentile, 64)
			if err != nil {
				log.Printf("Error parsing EPSS percentile for %s: %v", item.Cve, err)
				continue
			}
			epssScores[item.Cve] = score
			epssPercentiles[item.Cve] = percentile
			epssDates[item.Cve] = item.Date
		}

		// Add delay between batches to respect API rate limits
		if end < len(cves) {
			log.Println("Waiting before processing next batch...")
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil
}
