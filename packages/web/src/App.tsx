import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Home from './pages/Home';
import Scan from './pages/Scan';
import Report from './pages/Report';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/report/:id" element={<Report />} />
      </Routes>
    </Layout>
  );
}

export default App;
