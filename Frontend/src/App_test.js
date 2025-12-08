import React from 'react';
import { Shield } from 'lucide-react';

function App() {
  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center mb-8">
          <Shield className="w-8 h-8 text-blue-600 mr-3" />
          <h1 className="text-3xl font-bold text-gray-900">Cognitive Security Dashboard</h1>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">System Status</h2>
          <p className="text-gray-600">Frontend is working with Tailwind CSS!</p>
        </div>
      </div>
    </div>
  );
}

export default App;
