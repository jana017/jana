import { useEffect } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ReactLenis from "lenis/react";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import Landing from "@/pages/Landing";
import Admin from "@/pages/Admin";

function App() {
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <AuthProvider>
      <ReactLenis root options={{ lerp: 0.08, smoothWheel: true }}>
        <div className="App min-h-screen bg-[#050505]">
          <div className="grain-overlay" aria-hidden="true" />
          <Toaster theme="dark" position="bottom-right" richColors />
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/admin" element={<Admin />} />
            </Routes>
          </BrowserRouter>
        </div>
      </ReactLenis>
    </AuthProvider>
  );
}

export default App;
