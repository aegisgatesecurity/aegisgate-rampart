# AegisGate Rampart — Icon Assets

Official AegisGate shield logo icons for use in the application.

## Source

Icons are from the AegisGate Lens extension (`lens-cws-v0.2.0/icons/`).

## Usage

| File | Size | Used By |
|------|------|---------|
| `rampart-shield-16.png` | 16×16 | System tray icon (`internal/tray/`) |
| `rampart-shield-32.png` | 32×32 | Future: macOS menu bar, Windows taskbar |
| `rampart-shield-48.png` | 48×48 | Future: Windows app icon, Linux desktop file |
| `rampart-shield-128.png` | 128×128 | Future: macOS app icon, Windows installer, Linux app store |

## Embedded Icons

The following icons are embedded into the binary via `go:embed`:

- `internal/tray/rampart-shield-16.png` — System tray
- `internal/notify/rampart-shield-64.png` — Desktop notifications (resized from 128px source)

To update embedded icons:
1. Replace the source file in this directory
2. Copy to the appropriate package directory
3. Rebuild: `go build ./...`

## Notification Icon

The 64×64 notification icon is resized from the 128×128 source for optimal quality:

```bash
python3 -c "from PIL import Image; img = Image.open('assets/rampart-shield-128.png'); img64 = img.resize((64, 64), Image.Resampling.LANCZOS); img64.save('internal/notify/rampart-shield-64.png', 'PNG')"
```
