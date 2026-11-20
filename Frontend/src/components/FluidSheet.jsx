import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useId, useRef } from 'react';


export default function FluidSheet({ isOpen, onClose, title, children }) {
  const dialog = useRef(null);
  const close = useRef(onClose);
  const titleId = useId();
  useEffect(() => { close.current = onClose; }, [onClose]);
  useEffect(() => {
    if (!isOpen) return;
    const previous = document.activeElement;
    dialog.current?.focus();
    const keydown = event => {
      if (event.key === 'Escape') { event.preventDefault(); close.current(); }
      if (event.key !== 'Tab') return;
      const elements = [...dialog.current.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href]')];
      const first = elements[0]; const last = elements.at(-1);
      if (!first) { event.preventDefault(); return; }
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.current)) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === dialog.current)) {
        event.preventDefault(); first.focus();
      }
    };
    document.addEventListener('keydown', keydown);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', keydown);
      document.body.style.overflow = overflow;
      previous?.focus();
    };
  }, [isOpen]);
  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Dimming Scrim: Pushes the background back */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
          />

          {/* Translucent Material Sheet */}
          <motion.div
            ref={dialog}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            tabIndex={-1}
            initial={{ y: "100%" }}
            animate={{ y: 0 }}
            exit={{ y: "100%" }}
            transition={{
              type: "spring",
              bounce: 0,       /* Critically damped (Damping: 1.0) */
              duration: 0.4    /* Response time */
            }}
            drag="y"
            dragConstraints={{ top: 0 }}
            dragElastic={0.05} /* Progressive resistance (Rubber-banding) */
            onDragEnd={(event, info) => {
              // Velocity Handoff & Momentum Projection
              if (info.velocity.y > 500 || info.offset.y > 150) {
                onClose();
              }
            }}
            className="fixed bottom-0 left-0 right-0 z-50 flex flex-col h-[75vh] p-6
                       bg-white/70 dark:bg-slate-900/70 backdrop-blur-2xl
                       border-t border-white/20 dark:border-white/10 rounded-t-3xl shadow-2xl"
          >
            {/* Grab Handle */}
            <div className="w-12 h-1.5 mx-auto mb-6 rounded-full bg-slate-300 dark:bg-slate-600" />

            <h2 id={titleId} className="mb-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-white">
              {title}
            </h2>

            <div className="flex-1 overflow-y-auto">
              {children}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
