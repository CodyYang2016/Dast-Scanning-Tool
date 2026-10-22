import { useEffect, useState } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { api } from "./api";
import { Layout } from "./components/ui";
import Apps from "./pages/Apps";
import Automate from "./pages/Automate";
import Finding from "./pages/Finding";
import Governance from "./pages/Governance";
import Onboard from "./pages/Onboard";
import Overview from "./pages/Overview";
import Progress from "./pages/Progress";
import Results from "./pages/Results";
import Settings from "./pages/Settings";
import type { Session } from "./types";

// The routes from the front-end contract (ui_acceptance_criteria.md §4), without a router, so
// tests can mount them inside a MemoryRouter.
export function AppRoutes() {
  const [actor, setActor] = useState<string>();
  useEffect(() => { api.get<Session>("/api/session").then((s) => setActor(s.actor)).catch(() => undefined); }, []);
  return (
    <Layout actor={actor}>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/onboard" element={<Onboard />} />
        <Route path="/apps" element={<Apps purpose="apps" />} />
        <Route path="/runs" element={<Apps purpose="runs" />} />
        <Route path="/findings" element={<Apps purpose="findings" />} />
        <Route path="/automate" element={<Apps purpose="automate" />} />
        <Route path="/apps/:app/settings" element={<Settings />} />
        <Route path="/apps/:app/runs/:scanId/progress" element={<Progress />} />
        <Route path="/apps/:app/runs/:scanId/results" element={<Results />} />
        <Route path="/apps/:app/runs/:scanId/findings/:fingerprint" element={<Finding />} />
        <Route path="/apps/:app/automate" element={<Automate />} />
        <Route path="/governance" element={<Governance />} />
        <Route path="*" element={<p className="empty">There's no page here.</p>} />
      </Routes>
    </Layout>
  );
}

export function App() {
  return <BrowserRouter><AppRoutes /></BrowserRouter>;
}
