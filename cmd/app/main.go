package main

import (
	"context"
	"encoding/json"
	"time"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/k0ssk0ss-ai/netprobe/pkg/engine"
)

// ─── Collector config ────────────────────────────────────────────────────────
// A fork operator fills these in with their own server. bootstrapIP lets the
// upload survive a blocked/hijacked collector domain: we dial this IP directly
// and do the TLS handshake with collectorSNI (same trick as DoH bootstrap).
// Point bootstrapIP at any Cloudflare edge IP if the collector sits behind CF.
// If collectorEndpoint is left empty, the app runs in "preview only" mode and
// the donate button is disabled — you can still copy the JSON out manually.
const (
	collectorEndpoint    = "" // e.g. "https://collector.yourdomain.com/ingest"
	collectorBootstrapIP = "" // e.g. "104.16.132.229" (Cloudflare edge)
	collectorSNI         = "" // e.g. "collector.yourdomain.com"
)

// donationDomains is the set a "donate a test" scans. Kept small and public so
// the preview a user sees is easy to reason about.
var donationDomains = []string{
	"youtube.com", "web.telegram.org", "discord.com", "instagram.com", "twitter.com",
}

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("NetProbe — donate a test")

	statusLabel := widget.NewLabel("Press RUN TEST. Nothing is sent until you confirm.")
	resultEntry := widget.NewMultiLineEntry()
	resultEntry.Wrapping = 0 // fyne.TextWrapOff

	// preview holds the anonymized reports produced by RUN TEST; it is the exact
	// payload the donate button would upload. Kept in a closure var so the two
	// buttons share it.
	var preview []engine.AnonReport

	donateBtn := widget.NewButton("DONATE TO SERVER", func() {})
	donateBtn.Disable() // enabled only after a preview exists (and a collector is set)

	runBtn := widget.NewButton("RUN TEST (preview)", func() {})
	runBtn.OnTapped = func() {
		statusLabel.SetText("Scanning… up to ~10s. This sends NOTHING yet.")
		runBtn.Disable()
		donateBtn.Disable()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			// RunDonation scans all domains concurrently and returns only the
			// anonymized signal (no IPs, no error strings — see engine.Anonymize).
			preview = engine.RunDonation(ctx, donationDomains)

			b, err := json.MarshalIndent(preview, "", "  ")
			if err != nil {
				resultEntry.SetText("Error: " + err.Error())
				statusLabel.SetText("Failed to build preview.")
				runBtn.Enable()
				return
			}
			resultEntry.SetText(string(b))

			if collectorEndpoint == "" {
				statusLabel.SetText("Preview ready. No collector configured — copy it out manually.")
			} else {
				statusLabel.SetText("Preview ready. This is EXACTLY what will be sent. Review, then DONATE.")
				donateBtn.Enable()
			}
			runBtn.Enable()
		}()
	}

	donateBtn.OnTapped = func() {
		if len(preview) == 0 || collectorEndpoint == "" {
			return
		}
		statusLabel.SetText("Sending…")
		donateBtn.Disable()
		runBtn.Disable()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			sink := engine.NewHTTPSink(collectorEndpoint, collectorBootstrapIP, collectorSNI)
			if err := sink.SendBatch(ctx, preview); err != nil {
				statusLabel.SetText("Send failed: " + err.Error())
				donateBtn.Enable()
			} else {
				statusLabel.SetText("Thank you — donated anonymously. ✔")
			}
			runBtn.Enable()
		}()
	}

	copyBtn := widget.NewButton("Copy preview to clipboard", func() {
		myWindow.Clipboard().SetContent(resultEntry.Text)
		statusLabel.SetText("Copied. You can paste it anywhere (e.g. Telegram).")
	})

	myWindow.SetContent(container.NewBorder(
		container.NewVBox(statusLabel, runBtn, donateBtn, copyBtn), // top
		nil,         // bottom
		nil,         // left
		nil,         // right
		resultEntry, // center
	))

	myWindow.ShowAndRun()
}
