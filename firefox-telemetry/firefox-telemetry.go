/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Reads Certificate JSON files from https://censys.io/data/certificates

package firefoxtelemetry

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const TelemetryDateFormat = "20060102"

type TelemetryClient struct {
	baseURL string
}

type AggregateDateBody struct {
	Date      string
	Count     int
	Sum       int
	Label     string
	Histogram []int
}

type AggregateBody struct {
	Buckets []int
	Data    []AggregateDateBody
}

type BuildVersionDate struct {
	Date    string
	Version string
}

func makeHttpError(resp *http.Response) error {
	body := "(body too large)"
	if buffer, err := ioutil.ReadAll(resp.Body); err == nil {
		body = string(buffer)
	}
	return fmt.Errorf("Status: %s\nURI: %s\nBody: %s\n-------------\n", resp.Status, resp.Request.URL, body)
}

func NewClient() (*TelemetryClient, error) {
	client := TelemetryClient{
		baseURL: "https://aggregates.telemetry.mozilla.org",
	}
	return &client, nil
}

func (tc *TelemetryClient) GetVersions(channel string) ([]BuildVersionDate, error) {
	uri := fmt.Sprintf("%s/aggregates_by/submission_date/channels/%s/dates/", tc.baseURL, channel)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 399 {
		return nil, makeHttpError(resp)
	}

	data := []BuildVersionDate{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	return data, err
}

func (tc *TelemetryClient) GetAggregates(measure string, channel string, dates []time.Time, version string) (*AggregateBody, error) {
	uri := fmt.Sprintf("%s/aggregates_by/submission_date/channels/%s", tc.baseURL, channel)

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("version", version)

	dateStrings := []string{}
	for _, t := range dates {
		dateStrings = append(dateStrings, t.Format(TelemetryDateFormat))
	}

	q.Add("dates", strings.Join(dateStrings, ","))
	q.Add("metric", measure)
	req.URL.RawQuery = q.Encode()
	// fmt.Printf("URI: %s\n\n", req.URL)

	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 399 {
		return nil, makeHttpError(resp)
	}

	data := &AggregateBody{}
	err = json.NewDecoder(resp.Body).Decode(data)
	return data, err
}
