"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Fires once when the element scrolls into view. Uses getBoundingClientRect on a
 * throttled scroll/resize listener rather than IntersectionObserver — it's a
 * hair more work per scroll but bulletproof across environments (some sandboxed
 * webviews never fire IO callbacks) and it self-heals: if the element is already
 * on screen at mount, it reveals immediately instead of waiting for a scroll.
 *
 * `amount` is how much of the viewport height the element top must cross before
 * it counts as "in view" (0 = as soon as the top edge enters, 0.2 = a fifth in).
 */
export function useInView<T extends HTMLElement = HTMLDivElement>(amount = 0.15) {
  const ref = useRef<T | null>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    let raf = 0;
    let done = false;

    const check = () => {
      raf = 0;
      if (done || !ref.current) return;
      const r = ref.current.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      // visible if any part is on screen, past the `amount` trigger line
      const triggerLine = vh * (1 - amount);
      if (r.top <= triggerLine && r.bottom >= 0) {
        done = true;
        setInView(true);
        window.removeEventListener("scroll", onScroll);
        window.removeEventListener("resize", onScroll);
      }
    };

    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(check);
    };

    check(); // reveal immediately if already in view (above the fold)
    if (!done) {
      window.addEventListener("scroll", onScroll, { passive: true });
      window.addEventListener("resize", onScroll, { passive: true });
    }

    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [amount]);

  return { ref, inView };
}
