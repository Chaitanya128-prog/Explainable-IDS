import { HashRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import LiveTraffic from './pages/LiveTraffic';
import Alerts from './pages/Alerts';
import Explainability from './pages/Explainability';

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="traffic" element={<LiveTraffic />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="explain" element={<Explainability />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;
