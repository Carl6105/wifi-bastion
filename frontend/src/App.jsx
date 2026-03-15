import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import Navbar from './components/Navbar';

// Page Imports
import Home from './pages/Home';
import Dashbd from './pages/Dashbd';
import Scan from './pages/Scan';
import History from './pages/history';
import Blocked from './pages/blocked';
import DeviceMap from './pages/DeviceMap';
import SecurityAlerts from './pages/SecurityAlerts';
import Analytics      from './pages/Analytics';
import ChannelMap from './pages/ChannelMap';
import Settings   from './pages/Settings';

// Internal wrapper to access routing context
const AppContent = () => {
  const location = useLocation();

  // Define the intro path where navbar should be hidden
  const isIntroPage = location.pathname === "/";

  return (
    <div className="app-container">
      {/* Conditional Rendering: 
          Navbar only appears if we are NOT on the Intro page 
      */}
      {!isIntroPage && <Navbar />}

      {/* Conditional Styling: 
          We remove the "content" padding on the Home page 
          so the intro can be truly full-screen 
      */}
      <main className={isIntroPage ? "" : "content"}>
        <Routes>
          {/* Landing/Intro Page */}
          <Route path="/" element={<Home />} />
          
          {/* Operational Dashboard */}
          <Route path="/dashboard" element={<Dashbd />} />
          
          {/* Technical Pages */}
          <Route path="/scan" element={<Scan />} />
          <Route path="/devices" element={<DeviceMap />} />
          <Route path="/history" element={<History />} />
          <Route path="/blocked" element={<Blocked />} />
          <Route path="/alerts"    element={<SecurityAlerts />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/channels"  element={<ChannelMap />} />
          <Route path="/settings"  element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
};

function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;