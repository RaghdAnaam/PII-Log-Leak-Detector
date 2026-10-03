import { Dashboard } from "./components/Dashboard";

function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 bg-gray-900 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center gap-3">
          <div className="w-8 h-8 bg-red-600 rounded flex items-center justify-center">
            <span className="text-white text-sm font-bold">PII</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">PII Log Leak Detector</h1>
            <p className="text-xs text-gray-400">
              Find sensitive data before it reaches production logs.
            </p>
          </div>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-6 py-8">
        <Dashboard />
      </main>
    </div>
  );
}

export default App;
