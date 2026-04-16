# GEO-SURVEILLANCE FEED  ·  v0.1

> Public OSINT Edition — Test Build for Kali Linux

---

## Quick Start (Kali Linux)

```bash
# 1. Make the installer executable and run it
chmod +x install_kali.sh && bash install_kali.sh

# 2. Launch the app
python3 gsf_v01.py

# 3. Open your browser
http://127.0.0.1:8050
```

---

## What's Live in v0.1

| Layer | Source | Notes |
|---|---|---|
| ✈ ADS-B Aircraft | OpenSky Network | ~400 live targets, no API key |
| ⚡ Earthquakes M2.5+ | USGS Feed | Last 24h, auto-refreshes |
| 📹 Public Camera | Open MJPEG streams | Auto-fallback if offline |

---

## UI Features

- **Flat map** or **Orthographic globe** toggle (tabs)
- Aircraft colored by **altitude** (dark green → bright cyan)
- Earthquakes sized and colored by **magnitude**
- **Signal intel log** — top 60 aircraft by altitude
- Live **UTC clock** and stat counters
- Camera with **UTC timestamp overlay** and LIVE badge
- Scanline CRT aesthetic

---

## Roadmap (next versions)

- [ ] v0.2 — AIS maritime ship tracking (aisstream.io WebSocket)
- [ ] v0.3 — NASA FIRMS active wildfire layer
- [ ] v0.4 — Weather radar overlay (Open-Meteo)
- [ ] v0.5 — GDELT event heatmap
- [ ] v0.6 — Time slider / playback
- [ ] v1.0 — CesiumJS 3D globe migration + Gaussian Splat terrain

---

## Notes

- All data sources are **public domain / unauthenticated** free tiers
- OpenSky may rate-limit after ~10 req/min without an account
- Camera streams are public OSINT sources; they go offline randomly — the app auto-retries
- Tested on: Kali Linux 2024.x, Python 3.11+
