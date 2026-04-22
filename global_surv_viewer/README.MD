# Geo-Surveillance Feed  v1.0.0

A dark, Dash-based global OSINT dashboard that ingests live public feeds for aircraft, earthquakes, fires, air quality, ships, the ISS, and conflict events, then fuses them into a single interactive tile-map terminal with alerts, geofences, anomaly detection, and a versioned JSON API.

```
╔═══════════════════════════════════════════════════════════╗
║   GEO-SURVEILLANCE FEED  ·  VERSION 1.0  — ADVANCED      ║
║   Global Vision Platform — Public OSINT Edition           ║
╠═══════════════════════════════════════════════════════════╣
║  🗺  PRIMARY VIEW: Scattermapbox tile map                ║
║      CartoDB Dark · zoomable · pannable · street-level   ║
║  🌍  SECONDARY: Scattergeo globe overview                ║
║  🌡  DENSITY:   Flights · seismic · fire heatmaps        ║
║  ⚡  LIVE SOURCES: OpenSky · USGS · FIRMS · OpenAQ       ║
║  📰  EVENTS: GDELT geo conflict/disaster feed            ║
║  🛰  SPACE: ISS position + pass predictor                ║
║  🔲  GEOFENCE: named boxes + ingress/egress alerts       ║
║  🤖  ANOMALY: rolling z-score spike detector             ║
║  🔗  CONVERGENCE: 3+ hazard layers in same cell          ║
║  📋  API: /api/v1/ · /api/stream · /healthz · /metrics   ║
║  🚀  RUN: python3 gsf_v10.py                             ║
║  PROD: gunicorn -w 1 -b 0.0.0.0:8050 gsf_v10:application  ║
╚═══════════════════════════════════════════════════════════╝
```

---

## Features

- **2D tile map first**: primary Scattermapbox view with real tiles and fast zoom from global to street level
- **Secondary views**: globe overview and density mode for quick spatial comparison
- **Live public feeds**: OpenSky aircraft, USGS earthquakes, NASA FIRMS fires, OpenAQ air quality, GDELT geo events, ISS telemetry, and optional AIS ship tracking
- **Layer controls**: toggle flights, quakes, fires, ships, Starlink, ISS, air quality, events, threat scores, geofences, and trails
- **Geofencing engine**: define bounding boxes and receive enter/exit alerts
- **Anomaly detection**: rolling z-score monitoring over the latest frame buffer
- **Convergence detector**: flags cells where multiple hazard classes overlap
- **Threat scoring**: weighted hazard map built from seismic, air quality, conflict, and fire intensity
- **ISS pass prediction**: computes upcoming passes for a chosen latitude/longitude
- **SSE live stream**: push updates to the dashboard without polling
- **GeoJSON export**: download the current fused dataset for external tooling
- **Prometheus-style metrics**: lightweight `/metrics` endpoint for service counters
- **Config-driven setup**: all keys and intervals live in `gsf.ini`

---

## Install

### 1. Clone or extract

```bash
git clone https://github.com/yourname/geo-surveillance-feed.git
cd geo-surveillance-feed
```

### 2. Install dependencies

```bash
pip install dash dash-bootstrap-components pandas plotly requests opencv-python numpy websocket-client sgp4 --break-system-packages
```

If your environment does not need the system-packages flag, leave it off.

### 3. Optional API keys

The app runs with defaults, but some layers improve with keys:

- `AIS_API_KEY` for live ship tracking
- `FIRMS_MAP_KEY` for NASA FIRMS fire data
- `OPENAQ_API_KEY` for higher-limit air quality access

You can set them as environment variables or in `gsf.ini`.

---

## Configure

Generate the config file first:

```bash
python3 gsf_v10.py --init-config
```

That creates `gsf.ini`. Edit the `[keys]` section and any intervals, thresholds, or camera URLs you want to change.

Main config groups:

- **[gsf]**: host, port, debug
- **[keys]**: API keys
- **[cameras]**: up to 4 camera sources
- **[limits]**: row caps, ring buffer size, trail lengths
- **[intervals]**: refresh cadence per data source
- **[alerts]**: thresholds for earthquakes, AQ, GDELT, anomaly z-score, convergence
- **[threat]**: hazard weights and grid size

---

## Run

```bash
python3 gsf_v10.py
```

### Production WSGI

```bash
gunicorn -w 1 -b 0.0.0.0:8050 gsf_v10:application
```

### URLs

- **Main app**: `http://127.0.0.1:8050`
- **WebGL view**: `http://127.0.0.1:8050/deck`
- **API index**: `http://127.0.0.1:8050/api/v1/`
- **Health**: `http://127.0.0.1:8050/healthz`
- **Metrics**: `http://127.0.0.1:8050/metrics`

---

## API

### Versioned endpoints

- `GET /api/v1/`
- `GET /api/v1/snapshot`
- `GET /api/v1/alerts`
- `GET /api/v1/flights`
- `GET /api/v1/earthquakes`
- `GET /api/v1/ships`
- `GET /api/v1/threat`
- `GET /api/v1/anomaly`
- `GET /api/v1/iss/position`
- `GET /api/v1/iss/passes?lat=48.85&lon=2.35&n=5`
- `GET /api/v1/geofences`
- `POST /api/v1/geofences`
- `DELETE /api/v1/geofences/<name>`

### Utility endpoints

- `GET /api/stream` — server-sent events feed
- `GET /api/export.geojson` — fused dataset export
- `GET /api/trail/<icao>` — aircraft trail history
- `GET /api/frames/list` — ring buffer frame index
- `GET /api/frame/<idx>` — retrieve a stored frame
- `GET /api/weather?lat=&lon=` — short-term weather for a point

---

## Interface layout

- **Top bar**: live counters, UTC clock, quick links
- **Left panel**: map controls, view toggles, layer toggles
- **Center**: tile map, globe view, or density heatmap
- **Right panel**: inspection, geofences, telemetry, and threat leaderboard
- **Bottom bar**: quick route buttons, live SSE status, WebGL toggles

### Map layers

- Flights
- Quakes
- Fires
- Ships
- Starlink satellites
- ISS track
- Air quality
- GDELT events
- Threat heatmap
- Geofence outlines
- Trails

---

## Project layout

```text
gsf_v10.py                 # Single-file Dash + Flask app
gsf.ini                    # External config created by --init-config
README.md                  # Project overview and usage
```

This version is intentionally packaged as a single Python entry point, with the full UI, fetchers, API routes, and alert engines inside `gsf_v10.py`.

---

## Data sources

- **OpenSky Network** for aircraft state data
- **USGS** for earthquake feeds
- **NASA FIRMS** for fire detections
- **OpenAQ** for air quality measurements
- **GDELT** for conflict/disaster geo events
- **Where The ISS At / Celestrak** for ISS data and TLEs
- **AIS Stream** for ship telemetry
- **Open-Meteo** for point weather queries
- **RainViewer** for radar metadata
- **OpenStreetMap / CartoDB tiles** for map rendering

---

## Notes

- The dashboard is optimized for a dark terminal-style look.
- The tile map is the primary interface; the globe is secondary.
- If `sgp4` is unavailable, ISS pass prediction is disabled.
- If `websocket-client` is unavailable, AIS ship streaming is disabled.
- If API keys are missing, the app still runs with reduced data coverage.
- The live feeds are rate-limited by the configured refresh intervals.

---

## Roadmap (v1.1+)

- [ ] Persist ring-buffer frames to disk or SQLite
- [ ] Export threat layers as GeoJSON/CSV on demand
- [ ] Editable geofences from the UI
- [ ] Better anomaly baselines per layer
- [ ] Per-source retry/backoff and outage detection
- [ ] More robust ship and camera management
- [ ] Historical playback timeline
- [ ] Multi-user auth and role separation
- [ ] Containerized deployment docs
- [ ] More detailed per-layer analytics and inspection panels
