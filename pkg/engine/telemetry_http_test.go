package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSink_SendBatch(t *testing.T) {
	var got DonationPayload
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Construct directly with the test server's client (bypasses the TLS bootstrap).
	sink := &HTTPSink{endpoint: srv.URL, client: srv.Client()}

	reports := []AnonReport{
		{Target: "twitter.com", SNIBlocked: true, BlockMethod: "TCP RST"},
		{Target: "youtube.com", TLSBlocked: true},
	}
	if err := sink.SendBatch(context.Background(), reports); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}

	if contentType != "application/json" {
		t.Errorf("content-type = %q", contentType)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", got.SchemaVersion, SchemaVersion)
	}
	if len(got.Reports) != 2 || got.Reports[0].Target != "twitter.com" || !got.Reports[0].SNIBlocked {
		t.Errorf("bad payload: %+v", got.Reports)
	}
}

func TestHTTPSink_SendBatch_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := &HTTPSink{endpoint: srv.URL, client: srv.Client()}
	if err := sink.SendBatch(context.Background(), nil); err == nil {
		t.Error("expected error on 500, got nil")
	}
}
