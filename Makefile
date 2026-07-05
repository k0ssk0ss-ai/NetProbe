# NetProbe build entry points.
.PHONY: build test vet probe bind-android clean

# Build + test the core engine (no GUI, no CGO).
build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

# Standalone CLI / scanner binary.
probe:
	go build -o probe ./cmd/probe

# Android gomobile binding (requires the Android NDK + gomobile).
bind-android:
	./integration/bind.sh android

clean:
	rm -f probe probe.exe netprobe.aar
	rm -rf NetProbe.xcframework
