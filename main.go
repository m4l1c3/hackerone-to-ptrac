package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/uber-go/hackeroni/h1"
)

type Flaw struct {
	Title           string
	Severity        string
	Description     string
	Recommendations string
	Status          string
	AffectedAssets  string
	References      string
}

func AppendFlaws(flaws []Flaw, report h1.Report) []Flaw {
	title := *report.Title
	description := *report.VulnerabilityInformation
	score := GetSeverityFromScore(report.Severity.Score)

	return append(flaws, Flaw{
		Title:           title,
		Severity:        score,
		Description:     description,
		Recommendations: "",
		Status:          "Open",
		AffectedAssets:  "",
		References:      "",
	})
}

func GetJSON(value interface{}) []byte {
	data, error := json.Marshal(value)

	if error != nil {
		fmt.Printf("Error marshalling to json: %s\n", error)
		return nil
	}

	return data
}

func GetSeverityFromScore(score *float64) string {
	if score == nil {
		return "Low"
	}
	if *score > 7 {
		return "High"
	} else if *score > 4 {
		return "Medium"
	}
	return "Low"
}

func WriteOutput(index string, data []byte) {
	outputFile, err := os.Create(fmt.Sprintf("./%s-%s", index, "output.json"))
	if err != nil {
		fmt.Printf("Error writing output: %s\n")
		return
	}
	defer outputFile.Close()

	_, error := outputFile.WriteString(fmt.Sprintf("%s", string(data)))
	if error != nil {
		fmt.Printf("Error writing file %s\n", err)
		return
	}
	outputFile.Sync()
}

func main() {
	var flaws []Flaw

	tp := h1.APIAuthTransport{
		APIIdentifier: os.Getenv("hackeroneapiidentifier"),
		APIToken:      os.Getenv("hackeroneapitoken"),
	}
	var listOpts h1.ListOptions
	client := h1.NewClient(tp.Client())

	reports, _, err := client.Report.List(h1.ReportListFilter{
		Program: []string{os.Getenv("hackeroneprogramname")},
	}, &listOpts)

	if err != nil {
		panic(err)
	}

	for _, report := range reports {
		if *report.Reporter.Name != os.Getenv("hackeroneapiignoreuser") {
			flaws = AppendFlaws(flaws, report)
		}
	}
	if len(flaws) > 0 {
		for i, v := range flaws {
			WriteOutput(strconv.Itoa(i), GetJSON(&v))
		}
	}
}
