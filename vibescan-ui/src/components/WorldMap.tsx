import { useEffect, useMemo, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { FeatureCollection, Geometry } from "geojson";
import "./WorldMap.css";

const W = 960;
const H = 480;

export interface MapPoint {
  ip: string;
  port: number;
  lat: number;
  lon: number;
  insecure: boolean;
}

export default function WorldMap({ points }: { points: MapPoint[] }) {
  const [land, setLand] = useState<FeatureCollection<Geometry> | null>(null);

  useEffect(() => {
    let alive = true;
    fetch("/world-110m.json")
      .then((r) => r.json())
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .then((topo: any) => {
        if (alive) setLand(feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry>);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const { paths, project } = useMemo(() => {
    const projection = geoNaturalEarth1();
    if (land) projection.fitSize([W, H], land);
    else projection.scale(170).translate([W / 2, H / 2]);
    const pathGen = geoPath(projection);
    const paths = land ? land.features.map((f) => pathGen(f) || "") : [];
    const project = (lon: number, lat: number) => projection([lon, lat]) ?? [0, 0];
    return { paths, project };
  }, [land]);

  return (
    <div className="worldmap">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="Signal origins worldwide">
        <defs>
          <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(56,225,255,0.9)" />
            <stop offset="100%" stopColor="rgba(56,225,255,0)" />
          </radialGradient>
        </defs>
        <g className="wm-land">
          {paths.map((d, i) => (
            <path key={i} d={d} />
          ))}
        </g>
        <g className="wm-points">
          {points.map((p, i) => {
            const [x, y] = project(p.lon, p.lat);
            if (!x || !y) return null;
            const color = p.insecure ? "var(--red)" : "var(--cyan)";
            return (
              <g key={`${p.ip}:${p.port}:${i}`} transform={`translate(${x},${y})`}>
                <circle className="wm-ping" r="5" style={{ fill: color, transformOrigin: "center" }} />
                <circle r="1.8" style={{ fill: color }} />
              </g>
            );
          })}
        </g>
      </svg>
      <div className="wm-legend mono">
        <span><i className="dot cyan" /> HTTPS</span>
        <span><i className="dot red" /> HTTP</span>
        <span className="dim">{points.length} origins</span>
      </div>
    </div>
  );
}
