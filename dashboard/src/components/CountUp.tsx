"use client";

import { useEffect, useRef, useState } from "react";
import { useInView } from "./useInView";

interface CountUpProps {
  to: number;
  duration?: number;
  className?: string;
  style?: React.CSSProperties;
}

const easeOutExpo = (t: number) => (t === 1 ? 1 : 1 - Math.pow(2, -10 * t));

/**
 * Counts from 0 up to `to` the first time it scrolls into view. Respects
 * prefers-reduced-motion (snaps straight to the value). Tabular figures so the
 * width doesn't jitter while ticking.
 */
export default function CountUp({ to, duration = 1300, className = "", style }: CountUpProps) {
  const { ref, inView } = useInView<HTMLSpanElement>(0.2);
  const [value, setValue] = useState(0);
  const started = useRef(false);

  useEffect(() => {
    if (!inView || started.current) return;
    started.current = true;

    const reduce =
      typeof matchMedia !== "undefined" &&
      matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setValue(to);
      return;
    }

    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration);
      setValue(Math.round(easeOutExpo(p) * to));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, to, duration]);

  return (
    <span ref={ref} className={className} style={{ fontVariantNumeric: "tabular-nums", ...style }}>
      {value}
    </span>
  );
}
