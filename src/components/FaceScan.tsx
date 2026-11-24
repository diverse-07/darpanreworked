import { useEffect, useRef, useState } from 'react';
import portraitUrl from '../assets/synthetic-face-turntable.png';

const columns = 4;
const rows = 3;
export const scanViewCount = columns * rows;
const degreesPerView = 360 / scanViewCount;
const landmarkViews: [number, number][][] = [
  [[.414,.436],[.603,.438],[.513,.551],[.511,.628],[.511,.782]],
  [[.568,.436],[.691,.435],[.682,.539],[.661,.624],[.607,.771]],
  [[.671,.425],[.78,.514],[.733,.608],[.658,.746]],
  [[.824,.421],[.891,.523],[.829,.598],[.744,.715]],
  [], [], [], [], [],
  [[.235,.431],[.13,.517],[.179,.605],[.255,.719]],
  [[.347,.435],[.247,.513],[.292,.608],[.413,.762]],
  [[.44,.434],[.588,.434],[.397,.55],[.406,.624],[.49,.78]],
];

interface FaceScanProps {
  playing: boolean;
  angle: number;
  scanAngle: { current: number };
}

export function FaceScan({ playing, angle, scanAngle }: FaceScanProps) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const readout = useRef<HTMLOutputElement>(null);
  const [atlas, setAtlas] = useState<HTMLImageElement | null>(null);
  const [loadError,setLoadError] = useState(false);

  useEffect(() => {
    const image = new Image();
    image.onload = () => setAtlas(image);
    image.onerror = () => setLoadError(true);
    image.src = portraitUrl;
    return () => { image.onload = null; image.onerror = null; };
  }, []);

  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext('2d');
    if (!element || !context || !atlas) return;
    const frameWidth = atlas.naturalWidth / columns;
    const frameHeight = atlas.naturalHeight / rows;

    function draw() {
      if (!element || !context || !atlas) return;
      const width = element.clientWidth;
      const height = element.clientHeight;
      if (!width || !height) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      if (element.width !== Math.round(width * dpr) || element.height !== Math.round(height * dpr)) {
        element.width = Math.round(width * dpr);
        element.height = Math.round(height * dpr);
      }
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      context.clearRect(0, 0, width, height);

      const run = scanAngle.current / degreesPerView;
      const view = Math.floor(run) % scanViewCount;
      const next = (view + 1) % scanViewCount;
      const blend = Math.max(0, (run % 1 - .76) / .24);
      const size = Math.min(width * .82, height - 22);
      const x = (width - size) / 2;
      const y = (height - size) / 2;
      const drawView = (index: number) => context.drawImage(atlas,
        index % columns * frameWidth, Math.floor(index / columns) * frameHeight,
        frameWidth, frameHeight, x, y, size, size);
      drawView(view);
      if (blend > 0) {
        context.globalAlpha = blend;
        drawView(next);
        context.globalAlpha = 1;
      }

      context.strokeStyle = '#8ed9ef66';
      context.lineWidth = 1;
      const left = x + size * .17, right = x + size * .85;
      const top = y + size * .12, bottom = y + size * .83;
      const corner = 12;
      for (const [cx,cy,dx,dy] of [[left,top,1,1],[right,top,-1,1],[left,bottom,1,-1],[right,bottom,-1,-1]]) {
        context.beginPath();
        context.moveTo(cx + corner * dx,cy);
        context.lineTo(cx,cy);
        context.lineTo(cx,cy + corner * dy);
        context.stroke();
      }

      const scanY = y + size * (.15 + .66 * (1 - Math.abs(1 - (scanAngle.current % 180) / 90)));
      if (playing) {
        const glow = context.createLinearGradient(0, scanY - 18, 0, scanY + 1);
        glow.addColorStop(0, '#52dfff00');
        glow.addColorStop(1, '#52dfff3d');
        context.fillStyle = glow;
        context.fillRect(left, scanY - 18, right - left, 18);
        context.strokeStyle = '#78eaffce';
        context.beginPath();
        context.moveTo(left, scanY);
        context.lineTo(right, scanY);
        context.stroke();
      }

      for (const [fx,fy] of landmarkViews[blend > .5 ? next : view]) {
        const px = x + fx * size, py = y + fy * size;
        const active = playing && Math.abs(scanY - py) < 11;
        context.beginPath();
        context.arc(px,py,active ? 3.4 : 2.15,0,2*Math.PI);
        context.fillStyle = active ? '#ffffff' : '#84efff';
        context.fill();
      }
      if (readout.current) readout.current.value = String(Math.floor(scanAngle.current)).padStart(3, '0') + '°';
    }

    let frame = 0;
    let last = 0;
    let drawn = 0;
    const animate = (now: number) => {
      if (last) scanAngle.current = (scanAngle.current + Math.min(now - last, 50) * .067) % 360;
      last = now;
      if (now - drawn > 27) { draw(); drawn = now; }
      frame = requestAnimationFrame(animate);
    };
    draw();
    if (playing) frame = requestAnimationFrame(animate);
    const observer = new ResizeObserver(draw);
    observer.observe(element);
    return () => { cancelAnimationFrame(frame); observer.disconnect(); };
  }, [atlas, playing, angle, scanAngle]);

  return (
    <>
      <canvas ref={canvas} className="lab-face-canvas" role="img" aria-label="Photorealistic synthetic portrait with twelve views around a full rotation" />
      {loadError && <p className="lab-portrait-error" role="status">The portrait could not be loaded.</p>}
      <output ref={readout} className="lab-angle" aria-label="Rotation angle" aria-live="off">000°</output>
    </>
  );
}
