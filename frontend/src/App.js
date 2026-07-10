import "@/App.css";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import ReactLenis from "lenis/react";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import ScrollToTop from "@/components/ScrollToTop";
import ScrollToTopOnNav from "@/components/ScrollToTopOnNav";

const Landing = lazy(() => import("@/pages/Landing"));
const Admin = lazy(() => import("@/pages/Admin"));
const ThreatIntelligence = lazy(() => import("@/pages/ThreatIntelligence"));
const KnowledgeBase = lazy(() => import("@/pages/KnowledgeBase"));
const BlogPost = lazy(() => import("@/pages/BlogPost"));
const BlogIndex = lazy(() => import("@/pages/BlogIndex"));
const CommunityCd = lazy(() => import("@/pages/CommunityCd"));
const CommunityFeed = lazy(() => import("@/pages/CommunityFeed"));
const CyberLab = lazy(() => import("@/pages/CyberLab"));
const CyberLabShare = lazy(() => import("@/pages/CyberLabShare"));

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
            <ScrollToTopOnNav />
            <Suspense fallback={<RouteFallback />}>
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                <Route path="/cybersecurity-101" element={<KnowledgeBase />} />
                <Route path="/cybersecurity-101/:slug" element={<KnowledgeBase />} />
                <Route path="/blog" element={<BlogIndex />} />
                <Route path="/blog/:slug" element={<BlogPost />} />
                <Route path="/community/cd/:topic" element={<CommunityCd />} />
                <Route path="/community/:source" element={<CommunityFeed />} />
                <Route path="/detonate" element={<Navigate to="/nivx-forge" replace />} />
                <Route path="/payload-lab" element={<Navigate to="/nivx-forge" replace />} />
                <Route path="/cyberlab" element={<CyberLab />} />
                <Route path="/nivx-forge" element={<CyberLab />} />
                <Route path="/cyberlab/share/:shareId" element={<CyberLabShare />} />
                <Route path="/nivx-forge/share/:shareId" element={<CyberLabShare />} />
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
