import { startTransition, useEffect, useLayoutEffect, useRef, useState, type CSSProperties } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from './ui';
import { isTourCompleted, markTourCompleted, tourSteps, type TourPlacement, type TourStep } from '../lib/tour';

interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

interface TourGuideProps {
  open: boolean;
  onClose: () => void;
}

function visibleTourTarget(selector: string): Element | null {
  const matches = [...document.querySelectorAll(selector)];
  return (
    matches.find((element) => {
      if (!(element instanceof HTMLElement)) return false;
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
    }) ?? null
  );
}

function padRect(rect: DOMRect, pad = 8): Rect {
  return {
    top: Math.max(0, rect.top - pad),
    left: Math.max(0, rect.left - pad),
    width: rect.width + pad * 2,
    height: rect.height + pad * 2,
  };
}

function measureTarget(selector: string | undefined): Rect | null {
  if (!selector) return null;
  const el = visibleTourTarget(selector);
  return el ? padRect(el.getBoundingClientRect()) : null;
}

function popoverStyle(step: TourStep, highlight: Rect | null): CSSProperties {
  const placement: TourPlacement = step.placement ?? 'right';
  const gap = 14;
  const width = 340;
  if (!highlight || placement === 'center') {
    return {
      position: 'fixed',
      top: '50%',
      left: '50%',
      transform: 'translate(-50%, -50%)',
      width,
    };
  }
  if (placement === 'right') {
    return {
      position: 'fixed',
      top: Math.min(highlight.top, window.innerHeight - 280),
      left: Math.min(highlight.left + highlight.width + gap, window.innerWidth - width - 16),
      width,
    };
  }
  if (placement === 'left') {
    return {
      position: 'fixed',
      top: Math.min(highlight.top, window.innerHeight - 280),
      left: Math.max(16, highlight.left - width - gap),
      width,
    };
  }
  if (placement === 'top') {
    return {
      position: 'fixed',
      top: Math.max(16, highlight.top - 220),
      left: Math.min(Math.max(16, highlight.left), window.innerWidth - width - 16),
      width,
    };
  }
  return {
    position: 'fixed',
    top: Math.min(highlight.top + highlight.height + gap, window.innerHeight - 240),
    left: Math.min(Math.max(16, highlight.left), window.innerWidth - width - 16),
    width,
  };
}

export function TourGuide({ open, onClose }: TourGuideProps) {
  const navigate = useNavigate();
  const [index, setIndex] = useState(0);
  const [highlight, setHighlight] = useState<Rect | null>(null);
  const [moving, setMoving] = useState(false);
  const routeRef = useRef(window.location.pathname);
  const step = tourSteps[index];
  const total = tourSteps.length;

  useEffect(() => {
    if (!open) return;
    setIndex(0);
    setMoving(false);
  }, [open]);

  useEffect(() => {
    if (!open || !step) return;
    let cancelled = false;
    setMoving(true);

    // Sidebar targets stay mounted in the shell, so move the spotlight first.
    const immediate = measureTarget(step.target);
    if (immediate) {
      const el = step.target ? visibleTourTarget(step.target) : null;
      if (el instanceof HTMLElement) el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      setHighlight(immediate);
    }

    const needsRouteChange = routeRef.current !== step.route;
    if (needsRouteChange) {
      startTransition(() => {
        navigate(step.route, { replace: true });
      });
      routeRef.current = step.route;
    }

    const settle = window.setTimeout(() => {
      if (cancelled) return;
      const next = measureTarget(step.target);
      if (next) setHighlight(next);
      setMoving(false);
    }, needsRouteChange ? 160 : 40);

    return () => {
      cancelled = true;
      window.clearTimeout(settle);
    };
  }, [open, index, step, navigate]);

  useLayoutEffect(() => {
    if (!open || !step?.target) return;
    function measure() {
      const next = measureTarget(step.target);
      if (next) setHighlight(next);
    }
    measure();
    window.addEventListener('resize', measure);
    window.addEventListener('scroll', measure, true);
    return () => {
      window.removeEventListener('resize', measure);
      window.removeEventListener('scroll', measure, true);
    };
  }, [open, step, index]);

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        markTourCompleted();
        onClose();
        return;
      }
      if (event.key === 'ArrowRight') {
        setIndex((value) => {
          if (value >= tourSteps.length - 1) {
            markTourCompleted();
            onClose();
            return value;
          }
          return value + 1;
        });
      }
      if (event.key === 'ArrowLeft') setIndex((value) => Math.max(0, value - 1));
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  function finish(_completed = true) {
    markTourCompleted();
    onClose();
  }

  function goNext() {
    if (moving) return;
    if (index >= total - 1) finish(true);
    else setIndex((value) => value + 1);
  }

  function goBack() {
    if (moving) return;
    setIndex((value) => Math.max(0, value - 1));
  }

  if (!open || !step) return null;

  const cardStyle = {
    ...popoverStyle(step, highlight),
    transition: 'top 200ms ease, left 200ms ease, transform 200ms ease',
  };

  return (
    <div className="fixed inset-0 z-[80]" role="dialog" aria-modal="true" aria-labelledby="seap-tour-title">
      {highlight ? (
        <div
          className="pointer-events-none absolute z-[81] rounded-lg border-2 border-accent shadow-[0_0_0_9999px_rgba(2,8,18,0.62)] transition-[top,left,width,height] duration-200 ease-out"
          style={{ top: highlight.top, left: highlight.left, width: highlight.width, height: highlight.height }}
        />
      ) : (
        <div className="absolute inset-0 z-[81] bg-slate-950/60" />
      )}
      <div className="absolute inset-0 z-[81]" onClick={() => finish(false)} />
      <div
        className="z-[82] rounded-lg border border-line bg-panel p-4 shadow-xl"
        style={cardStyle}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between gap-3">
          <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-accent">
            Tour · {index + 1} / {total}
          </p>
          <button type="button" className="text-xs text-mute hover:text-slate-900 dark:hover:text-slate-100" onClick={() => finish(false)}>
            Skip
          </button>
        </div>
        <h2 id="seap-tour-title" className="text-base font-semibold tracking-tight">
          {step.title}
        </h2>
        <p className="mt-2 text-sm leading-relaxed text-mute">{step.body}</p>
        <div className="mt-4 flex items-center justify-between gap-2">
          <Button variant="secondary" disabled={index === 0 || moving} onClick={goBack}>
            Back
          </Button>
          <Button disabled={moving} onClick={goNext}>{index >= total - 1 ? 'Finish' : 'Next'}</Button>
        </div>
      </div>
    </div>
  );
}

export function useAutoStartTour(start: () => void) {
  useEffect(() => {
    if (isTourCompleted()) return;
    const timer = window.setTimeout(() => start(), 600);
    return () => window.clearTimeout(timer);
  }, [start]);
}
