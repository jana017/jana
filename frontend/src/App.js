import "@/App.css";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ReactLenis from "lenis/react";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import ScrollToTop from "@/components/ScrollToTop";

const Landing = lazy(() => import("@/pages/Landing"));
const Admin = lazy(() => import("@/pages/Admin"));
const ThreatIntelligence = lazy(() => import("@/pages/ThreatIntelligence"));

function RouteFallback() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-white">
      <div className="w-8 h-8 border-2 border-slate-200 border-t-[#2E7DF5] rounded-full animate-spin" aria-label="Loading" />
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <ReactLenis root options={{ lerp: 0.09, smoothWheel: true }}>
        <div className="App min-h-screen bg-white">
          <Toaster position="bottom-right" richColors />
          <ScrollToTop />
          <BrowserRouter>
            <Suspense fallback={<RouteFallback />}>
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                <Route path="/admin" element={<Admin />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </div>
      </ReactLenis>
    </AuthProvider>
  );
}

export default App;
