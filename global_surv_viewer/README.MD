# 🌍 Global Vision Feed – Viewing Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)
[![Cesium](https://img.shields.io/badge/CesiumJS-1.113+-brightgreen.svg)](https://cesium.com/platform/cesiumjs/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg)](https://www.typescriptlang.org/)

> **The most advanced open‑source 3D Earth viewer.**  
> Real‑time satellite imagery, 3D terrain, global building models, street‑level photos, thermal overlays, and more—combined into a single, high‑performance geospatial intelligence platform.

---

## 🎯 **Vision & Mission**

This project began as a simple 3D globe script with basic camera controls and rough location data. The goal is to evolve it into a **full‑fledged, insanely detailed digital twin of Earth**—a "global thermal sonar live feed" that aggregates and visualizes virtually every free and public geospatial data source available.

We aim to democratize access to planetary‑scale situational awareness by providing an open, extensible platform that rivals commercial offerings like Google Earth and Google Maps, but with deeper integration of real‑time environmental data, crowdsourced imagery, and scientific overlays.

---

## ⚙️ **Core Capabilities**

### 🌐 **3D Earth Visualization Engine**

- **High‑Performance Rendering:** Built on CesiumJS, an industry‑standard WebGL engine optimized for streaming massive geospatial datasets.
- **Global 3D Terrain:** Realistic elevation data sourced from NASA SRTM and ASTER GDEM, providing accurate mountain ranges, valleys, and bathymetry.
- **Smooth Navigation:** Free‑form camera controls including pan, zoom, rotate, tilt, and fly‑to animations. Users can seamlessly transition from a global view down to street level.

### 🏢 **Worldwide 3D Building Models**

- **OpenStreetMap Integration:** Over 350 million building footprints are extruded into 3D models using height and level data from OSM.
- **Dynamic Loading:** Buildings stream efficiently as 3D Tiles, ensuring smooth performance even in dense urban areas.
- **Future Enhancement:** Support for high‑resolution city‑scale 3D models (e.g., Project PLATEAU, Microsoft Building Footprints).

### 🛰️ **Multi‑Source Satellite Imagery**

- **Daily Global Coverage:** True‑color imagery from NASA GIBS (MODIS Terra/Aqua, VIIRS) updated every 24 hours.
- **High‑Resolution Mosaics:** Sentinel‑2 cloudless composites (10m resolution) via public tile services.
- **Historical Basemaps:** Access to Landsat archives and other time‑series imagery layers.
- **Custom WMS/WMTS Support:** Add any OGC‑compliant web map service as an overlay.

### 🚶 **Street‑Level Immersion**

- **Mapillary Integration:** Seamlessly fetch and display geotagged street‑view photos from the world's largest crowdsourced imagery platform.
- **Click‑to‑Explore:** Users can click any road or location to view the nearest ground‑level 360° photo.
- **KartaView Compatibility:** Optional integration with KartaView (formerly OpenStreetCam) for additional coverage.

### 🌡️ **Real‑Time Environmental Overlays**

- **Thermal Infrared "Live Feed":** Near‑real‑time infrared imagery from geostationary weather satellites (e.g., Meteosat, GOES) via the Geosatellite API, updated every 10–60 minutes.
- **Active Fire Detection:** NASA FIRMS and MODIS thermal anomaly layers showing current wildfire hotspots.
- **Flood & Disaster Monitoring:** Overlays from NASA GIBS and Copernicus Emergency Management Service for floods, storms, and other events.
- **Weather Radar & Precipitation:** Animated weather radar and precipitation maps (future integration).

### 🔍 **Global Search & Geocoding**

- **Nominatim Geocoder:** Free, OpenStreetMap‑based global place search supporting addresses, landmarks, and coordinates.
- **Reverse Geocoding:** Click anywhere on the globe to retrieve the nearest address or point of interest.
- **Smart Suggestions:** Autocomplete and fuzzy matching for rapid location discovery.

### 🧩 **Extensible Data Layer System**

- **Modular Overlay Architecture:** Add, remove, and reorder imagery and data layers at runtime.
- **Vector Data Support:** Display GeoJSON, KML, and CZML data for custom annotations, boundaries, and dynamic objects.
- **3D Tiles Streaming:** Efficiently stream massive point clouds, photogrammetry meshes, and BIM models.

### 🎛️ **Advanced UI & Controls**

- **Layer Manager Panel:** Toggle visibility, adjust opacity, and reorder all active data layers.
- **Time‑Dynamic Playback:** (In development) Scrub through historical satellite imagery and sensor data.
- **Measurement Tools:** Calculate distances, areas, and volumes directly on the 3D globe.
- **Customizable Basemap:** Switch between satellite, terrain, street map, and custom tile providers.

### 🔐 **Backend & Data Aggregation (Optional)**

- **API Proxy Service:** A lightweight Node.js or Python backend handles API key management, request aggregation, caching, and rate‑limit compliance for third‑party services.
- **Data Fusion Pipeline:** Pre‑process and combine disparate data formats into Cesium‑compatible 3D Tiles or imagery layers.
- **Offline Caching:** Support for local storage of tiles and data for disconnected operation.

---

## 📡 **Data Sources & Integration Details**

| Category               | Provider                          | Data Type                                    | Update Frequency   |
|------------------------|-----------------------------------|----------------------------------------------|--------------------|
| **3D Terrain**         | Cesium ion / SRTM / ASTER         | Global elevation mesh                        | Static (annual)    |
| **3D Buildings**       | OpenStreetMap (via Cesium OSM)    | Extruded building footprints                 | Weekly             |
| **Satellite Imagery**  | NASA GIBS                         | MODIS, VIIRS true color & science layers     | Daily              |
| **High‑Res Imagery**   | Sentinel‑2 (EOX Cloudless)        | 10m cloud‑free mosaic                        | ~5 days            |
| **Street‑Level Photos**| Mapillary                         | Geotagged 360° photos                        | Real‑time (crowd)  |
| **Thermal Infrared**   | Geosatellite API (Yr)             | Geostationary IR imagery                     | 10–60 minutes      |
| **Active Fires**       | NASA FIRMS                        | Thermal anomaly points & perimeters          | 3 hours            |
| **Flood Monitoring**   | Copernicus EMS / NASA GIBS        | Flood extent polygons & imagery              | Event‑driven       |
| **Geocoding**          | OpenStreetMap Nominatim           | Place search & reverse geocoding             | Daily              |
| **Vector Boundaries**  | Natural Earth / OSM               | Country/state borders, coastlines            | Quarterly          |

---

## 🏗️ **Architecture Overview**

The application is structured as a single‑page web app (SPA) with a modular, service‑oriented design.

- **Frontend:** React + TypeScript provides a robust, maintainable UI layer. CesiumJS is integrated via a custom React component that manages the 3D scene lifecycle.
- **State Management:** React Context or a lightweight state library manages layer visibility, camera position, and user preferences.
- **Data Services:** A set of TypeScript classes abstract the fetching and rendering of each data source (e.g., `MapillaryService`, `GIBSImageryProvider`).
- **Backend (Optional):** A simple Express.js or Flask server handles third‑party API secrets and can pre‑process large datasets into Cesium‑friendly formats.

---

## 🗺️ **Roadmap & Future Enhancements**

### ✅ **Completed**
- Core CesiumJS 3D globe with terrain and camera controls
- OSM Buildings global layer
- NASA GIBS true‑color and fire layers
- Mapillary street‑view photo fetch on click
- Basic search via Nominatim

### 🚧 **In Progress**
- Thermal overlay integration (Geosatellite API proxy)
- Sentinel‑2 cloudless basemap
- Improved layer management UI
- Time‑dynamic playback for historical imagery

### 🔮 **Planned**
- **Vector Tile Layers:** Roads, labels, and POIs from OpenStreetMap rendered as high‑performance vector tiles.
- **3D City Models:** Integration of open 3D city datasets (e.g., Project PLATEAU, NYC 3D Buildings).
- **Maritime & Air Traffic:** Real‑time vessel positions (AIS) and flight tracking (ADS‑B) overlays.
- **Air Quality & Pollution:** Overlays from Copernicus Atmosphere Monitoring Service (CAMS).
- **Desktop Application:** Package as an Electron app for offline use and deeper OS integration.
- **Mobile‑Responsive UI:** Optimize for tablets and smartphones.
- **Plugin System:** Allow third‑party developers to add custom data sources and tools.


This project is licensed under the MIT License – see the [LICENSE](./LICENSE) file for details.  
You are free to use, modify, and distribute this software for any purpose, personal or commercial.

- **[Cesium](https://cesium.com/)** – For the phenomenal open‑source 3D globe engine and the Cesium ion platform.
- **[NASA GIBS](https://earthdata.nasa.gov/gibs)** – For making daily, full‑resolution satellite imagery available to the public.
- **[ESA Copernicus](https://scihub.copernicus.eu/)** – For the Sentinel satellite constellation and free data access.
- **[OpenStreetMap](https://www.openstreetmap.org/)** – The incredible volunteer community building the most detailed open map of the world.
- **[Mapillary](https://www.mapillary.com/)** – For democratizing street‑level imagery through crowdsourcing.
- **[Yr Geosatellite API](https://developer.yr.no/)** – For providing near‑real‑time weather satellite data.
