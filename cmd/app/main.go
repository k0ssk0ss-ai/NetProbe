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

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("NetProbe Crowdsource")

	statusLabel := widget.NewLabel("Ready to scan.")
	resultEntry := widget.NewMultiLineEntry()
	resultEntry.Wrapping = 0 // fyne.TextWrapOff

	runBtn := widget.NewButton("RUN TEST", func() {}) // forward declaration
	
	runBtn.OnTapped = func() {
		statusLabel.SetText("Scanning... Please wait up to 5 seconds.")
		runBtn.Disable()
		
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			// We scan youtube to get realistic DPI stats on mobile networks
			target := "youtube.com"
			report := engine.RunEngineScans(ctx, target)
			
			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				resultEntry.SetText("Error: " + err.Error())
			} else {
				resultEntry.SetText(string(b))
			}
			
			statusLabel.SetText("Scan complete! Please copy and send this.")
			runBtn.Enable()
		}()
	}

	copyBtn := widget.NewButton("Copy to Clipboard", func() {
		myWindow.Clipboard().SetContent(resultEntry.Text)
		statusLabel.SetText("Copied! Now paste it in Telegram.")
	})

	myWindow.SetContent(container.NewBorder(
		container.NewVBox(statusLabel, runBtn, copyBtn), // top
		nil, // bottom
		nil, // left
		nil, // right
		resultEntry, // center
	))

	myWindow.ShowAndRun()
}
