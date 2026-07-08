import { useState } from "react";
import { useLenis } from "lenis/react";
import { ArrowUp } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";

export default function ScrollToTop() {
  const [show, setShow] = useState(false);
  const lenis = useLenis(({ scroll }) => setShow(scroll > 500));

  const toTop = () => {
    if (lenis) lenis.scrollTo(0, { duration: 1.1 });
    else window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <AnimatePresence>
      {show && (
        <motion.button
          initial={{ opacity: 0, scale: 0.8, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.8, y: 10 }}
          transition={{ duration: 0.2 }}
          onClick={toTop}
          data-testid="scroll-to-top"
          aria-label="Scroll to top"
          className="fixed bottom-24 right-6 z-50 w-11 h-11 rounded-full bg-[#0A1220] text-white shadow-lg hover:bg-[#2E7DF5] flex items-center justify-center transition-colors"
        >
          <ArrowUp className="w-5 h-5" strokeWidth={2.2} />
        </motion.button>
      )}
    </AnimatePresence>
  );
}
