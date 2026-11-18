"use client";

import "leaflet/dist/leaflet.css";
import { useEffect, useRef } from "react";
import type { Map as LMap, CircleMarker } from "leaflet";

export interface Pin {
  lat: number;
  lng: number;
}

/**
 * OpenStreetMap map with one pin. Pass `onPick` to let people tap the map to place the pin;
 * without it the map is read-only. Tiles are served by this site's own cache of OpenStreetMap.
 */
export default function PlaceMap({
  pin,
  onPick,
  height = 240,
}: {
  pin: Pin | null;
  onPick?: (p: Pin) => void;
  height?: number;
}) {
  const el = useRef<HTMLDivElement>(null);
  const map = useRef<LMap | null>(null);
  const marker = useRef<CircleMarker | null>(null);
  const pick = useRef(onPick);
  pick.current = onPick;
  const first = useRef(pin);

  useEffect(() => {
    let dead = false;
    (async () => {
      const L = (await import("leaflet")).default;
      if (dead || !el.current) return;
      const start = first.current;
      const m = L.map(el.current, {
        center: start ? [start.lat, start.lng] : [20, 0],
        zoom: start ? 14 : 2,
        scrollWheelZoom: !!pick.current,
      });
      // Tiles are fetched through this site, so the map provider never sees a reader's address.
      L.tileLayer("/tiles/{z}/{x}/{y}.png", {
        maxZoom: 16,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      }).addTo(m);
      const style = { radius: 9, weight: 3, color: "#8a5a12", fillColor: "#e0a64a", fillOpacity: 0.9 };
      if (start) marker.current = L.circleMarker([start.lat, start.lng], style).addTo(m);
      m.on("click", (ev) => {
        if (!pick.current) return;
        const { lat, lng } = ev.latlng;
        if (marker.current) marker.current.setLatLng(ev.latlng);
        else marker.current = L.circleMarker(ev.latlng, style).addTo(m);
        pick.current({ lat, lng: ((((lng + 180) % 360) + 360) % 360) - 180 });
      });
      map.current = m;
    })();
    return () => {
      dead = true;
      map.current?.remove();
      map.current = null;
      marker.current = null;
    };
  }, []);

  // Keep the pin in step when it is set from outside (e.g. "use my location").
  useEffect(() => {
    const m = map.current;
    if (!m || !pin) return;
    (async () => {
      const L = (await import("leaflet")).default;
      if (!map.current) return;
      if (marker.current) marker.current.setLatLng([pin.lat, pin.lng]);
      else
        marker.current = L.circleMarker([pin.lat, pin.lng], {
          radius: 9,
          weight: 3,
          color: "#8a5a12",
          fillColor: "#e0a64a",
          fillOpacity: 0.9,
        }).addTo(map.current);
      if (!map.current.getBounds().contains([pin.lat, pin.lng]))
        map.current.setView([pin.lat, pin.lng], Math.max(map.current.getZoom(), 13));
    })();
  }, [pin]);

  return (
    <div
      ref={el}
      className="map"
      style={{ height }}
      role="application"
      aria-label={onPick ? "Map: tap to place the pin" : "Map showing the place"}
    />
  );
}
