import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ReactLenis from "lenis/react";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import Landing from "@/pages/Landing";
import Admin from "@/pages/Admin";
import ThreatIntelligence from "@/pages/ThreatIntelligence";
import ScrollToTop from "@/components/ScrollToTop";

function App() {
  return (
    <AuthProvider>
      <ReactLenis root options={{ lerp: 0.09, smoothWheel: true }}>
        <div className="App min-h-screen bg-white">
          <Toaster position="bottom-right" richColors />
          <ScrollToTop />
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
              <Route path="/admin" element={<Admin />} />
            </Routes>
          </BrowserRouter>
        </div>
      </ReactLenis>
    </AuthProvider>
  );
}

export default App;
