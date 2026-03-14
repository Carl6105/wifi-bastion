import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import Navbar from './components/Navbar';

// Page Imports
import Home from './pages/Home';
import Dashbd from './pages/Dashbd';
import Scan from './pages/Scan';
import History from './pages/History';
import Blocked from './pages/Blocked';
import DeviceMap from './pages/DeviceMap';

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