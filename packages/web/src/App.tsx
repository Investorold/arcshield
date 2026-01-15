import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Home from './pages/Home';
import Scan from './pages/Scan';
import Report from './pages/Report';
import ReportIDE from './pages/ReportIDE';

// Layout wrapper component
function LayoutWrapper({ children }: { children: React.ReactNode }) {
  return <Layout>{children}</Layout>;
}

function App() {
  return (
    <Routes>
      {/* IDE view - full screen, no sidebar */}
      <Route path="/report/:id/ide" element={<ReportIDE />} />

      {/* Standard views with sidebar layout */}
      <Route path="/" element={<LayoutWrapper><Home /></LayoutWrapper>} />
      <Route path="/scan" element={<LayoutWrapper><Scan /></LayoutWrapper>} />
      <Route path="/report/:id" element={<LayoutWrapper><Report /></LayoutWrapper>} />
    </Routes>
  );
}

export default App;
