"use client";

import { type ElementType, type ReactNode } from "react";
import { useInView } from "./useInView";

type Variant = "up" | "down" | "left" | "right" | "scale" | "blur" | "mask";

interface RevealProps {
  children: ReactNode;
  as?: ElementType;
  variant?: Variant;
  /** stagger in ms — added as transition-delay */
  delay?: number;
  /** how far into the viewport before firing (0–1) */
  threshold?: number;
  className?: string;
  style?: React.CSSProperties;
  /** forwarded to the rendered element (e.g. href when as={Link}) */
  [key: string]: unknown;
}

/**
 * Scroll-triggered reveal. Starts hidden and transitions in when it scrolls into
 * view (see .reveal-init in globals.css). Under prefers-reduced-motion the CSS
 * neutralizes the transform so content is simply present.
 */
export default function Reveal({
  children,
  as,
  variant = "up",
  delay = 0,
  threshold = 0.15,
  className = "",
  style,
  ...rest
}: RevealProps) {
  const Tag = (as ?? "div") as ElementType;
  const { ref, inView } = useInView<HTMLElement>(threshold);

  return (
    <Tag
      ref={ref}
      className={`reveal-init rv-${variant} ${inView ? "in-view" : ""} ${className}`}
      style={{ transitionDelay: delay ? `${delay}ms` : undefined, ...style }}
      {...rest}
    >
      {children}
    </Tag>
  );
}
