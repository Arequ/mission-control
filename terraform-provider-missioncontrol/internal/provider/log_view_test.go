package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogViewClientRoundTripHidesKey(t *testing.T) {
	var stored logViewAPI
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/log-views", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mission-Control-Client") != "terraform" {
			t.Errorf("missing terraform header")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"elastic_api_key":"super-secret"`) {
			t.Errorf("create did not send the key: %s", body)
		}
		_ = json.Unmarshal(body, &stored)
		stored.ID = "lv1"
		stored.ElasticAPIKey = ""
		stored.HasElasticAPIKey = true
		writeView(w, http.StatusCreated, stored)
	})
	mux.HandleFunc("GET /api/v1/log-views/{id}", func(w http.ResponseWriter, r *http.Request) {
		pub := stored
		pub.ElasticAPIKey = ""
		writeView(w, http.StatusOK, pub)
	})
	mux.HandleFunc("GET /api/v1/log-views", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != stored.Name {
			t.Errorf("name query %q", r.URL.Query().Get("name"))
		}
		pub := stored
		pub.ElasticAPIKey = ""
		_ = json.NewEncoder(w).Encode(map[string]any{"views": []logViewAPI{pub}})
	})
	mux.HandleFunc("PUT /api/v1/log-views/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"elastic_api_key"`) {
			t.Errorf("empty update sent a key: %s", body)
		}
		var in logViewAPI
		_ = json.Unmarshal(body, &in)
		stored.Description = in.Description
		pub := stored
		pub.ElasticAPIKey = ""
		writeView(w, http.StatusOK, pub)
	})
	mux.HandleFunc("DELETE /api/v1/log-views/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{Base: srv.URL, Token: "tok", HTTP: srv.Client()}
	created, err := c.CreateLogView(context.Background(), logViewAPI{
		Name: "Munki install log", Description: "one mac", DefaultWindow: "1h", MaxLines: 100,
		DeviceScoped: true, TimeZone: "UTC", ElasticURL: "https://elastic.example",
		ElasticAPIKey: "super-secret",
		Sources: []logSourceAPI{{
			Label: "Munki", Color: "#ff9f0a", IndexPattern: "logs-munki-*",
			KQL: "host.serial: {{serial}}", MessageField: "message", TimestampField: "@timestamp",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ElasticAPIKey != "" || !created.HasElasticAPIKey || created.ID != "lv1" {
		t.Fatalf("%+v", created)
	}
	got, err := c.GetLogView(context.Background(), created.ID)
	if err != nil || got.ElasticAPIKey != "" {
		t.Fatalf("%v %+v", err, got)
	}
	listed, err := c.ListLogViews(context.Background(), "Munki install log")
	if err != nil || len(listed) != 1 || listed[0].ElasticAPIKey != "" {
		t.Fatalf("%v %+v", err, listed)
	}
	updated, err := c.UpdateLogView(context.Background(), created.ID, logViewAPI{
		Name: stored.Name, Description: "renamed", DefaultWindow: "1h", MaxLines: 100,
		DeviceScoped: true, TimeZone: "UTC", ElasticURL: stored.ElasticURL, Sources: stored.Sources,
	})
	if err != nil || updated.Description != "renamed" || updated.ElasticAPIKey != "" {
		t.Fatalf("%v %+v", err, updated)
	}
	if err := c.DeleteLogView(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
}

func writeView(w http.ResponseWriter, status int, v logViewAPI) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
