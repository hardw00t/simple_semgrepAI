import { Routes, Route } from 'react-router-dom'
import MainLayout from './components/Layout/MainLayout'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'

function App() {
  return (
    <MainLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
      </Routes>
    </MainLayout>
  )
}

export default App
