import "@/App.css";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import ReactLenis from "lenis/react";
import { Toaster } from "sonner";
import { AuthProvider } from "@/context/AuthContext";
import ScrollToTop from "@/components/ScrollToTop";
import ScrollToTopOnNav from "@/components/ScrollToTopOnNav";
import AnnouncementBanner from "@/components/AnnouncementBanner";
import useBrandingInjection from "@/lib/useBrandingInjection";
import useRouteBodyBg from "@/lib/useRouteBodyBg";

const Landing = lazy(() => import("@/pages/Landing"));
const Admin = lazy(() => import("@/pages/Admin"));
const ThreatIntelligence = lazy(() => import("@/pages/ThreatIntelligence"));
const KnowledgeBase = lazy(() => import("@/pages/KnowledgeBase"));
const BlogPost = lazy(() => import("@/pages/BlogPost"));
const BlogIndex = lazy(() => import("@/pages/BlogIndex"));
const CommunityCd = lazy(() => import("@/pages/CommunityCd"));
const CommunityFeed = lazy(() => import("@/pages/CommunityFeed"));
const Learn = lazy(() => import("@/pages/Learn"));
const EmployeePortal = lazy(() => import("@/pages/EmployeePortal"));
const CyberLab = lazy(() => import("@/pages/CyberLab"));
const CyberLabShare = lazy(() => import("@/pages/CyberLabShare"));
const CmsPage = lazy(() => import("@/pages/CmsPage"));
const ActorsIndex = lazy(() => import("@/pages/ActorsIndex"));
const ActorProfile = lazy(() => import("@/pages/ActorProfile"));

function RouteFallback() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-white">
      <div className="w-8 h-8 border-2 border-slate-200 border-t-[#2E7DF5] rounded-full animate-spin" aria-label="Loading" />
    </div>
  );
}

/** Small child component that lives inside <BrowserRouter> so it can read the
 * active route. Handles body-background theming and any other route-aware
 * side-effects. Returns null. */
function RouteEffects() {
  useRouteBodyBg();
  return null;
}

function App() {
  useBrandingInjection();
  return (
    <AuthProvider>
      <ReactLenis root options={{ lerp: 0.09, smoothWheel: true }}>
        <div className="App min-h-screen">
          <Toaster position="bottom-right" richColors />
          <AnnouncementBanner />
          <ScrollToTop />
          <BrowserRouter>
            <ScrollToTopOnNav />
            <RouteEffects />
            <Suspense fallback={<RouteFallback />}>
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                <Route path="/learn" element={<Learn />} />
                <Route path="/cybersecurity-101" element={<Navigate to="/learn?tab=cyber101" replace />} />
                <Route path="/cybersecurity-101/:slug" element={<KnowledgeBase />} />
                <Route path="/blog" element={<Navigate to="/learn?tab=blog" replace />} />
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
                <Route path="/employee" element={<EmployeePortal />} />
                <Route path="/pages/:slug" element={<CmsPage />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </div>
      </ReactLenis>
    </AuthProvider>
  );
}

export default App;
