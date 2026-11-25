import { Navigate, Route, Routes } from "react-router"
import { LogEntryPage } from "./pages/LogEntry"
import { BackfillPage } from "./pages/Backfill"
import { Shell } from "./Shell"
import { StatusPage } from "./pages/Status"
import { ReviewPage } from "./pages/Review"
import { AnalyzerPage } from "./pages/Analyzer"
import { MorePage } from "./pages/More"
import { LogPage } from "./pages/Log"
import { ListsPage } from "./pages/Lists"
import { SettingsPage } from "./pages/Settings"
import { AuditPage } from "./pages/Audit"
import { AnalyzerVendorPage } from "./pages/AnalyzerVendor"
import { AnalyzerLivePage } from "./pages/AnalyzerLive"
import { ProtonPage } from "./pages/Proton"

export function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<StatusPage />} />
        <Route path="review" element={<ReviewPage />} />
        <Route path="log" element={<LogPage />} />
        <Route path="log/entry" element={<LogEntryPage />} />
        <Route path="lists" element={<ListsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="analyzer" element={<AnalyzerPage />} />
        <Route path="analyzer/vendor" element={<AnalyzerVendorPage />} />
        <Route path="analyzer/live" element={<AnalyzerLivePage />} />
        <Route path="more" element={<MorePage />} />
        <Route path="proton" element={<ProtonPage />} />
        <Route path="backfill" element={<BackfillPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
