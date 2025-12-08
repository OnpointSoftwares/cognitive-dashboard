import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, Database, Network, Settings } from 'lucide-react';
import DashboardLayout from './components/DashboardLayout.js';
import LoginScreen from './components/LoginScreen.js';
import { AuthProvider, useAuth } from './context/AuthContext.js';
import { ApiProvider } from './context/ApiContext.js';
import './index.css';

function AppContent() {
  const { isAuthenticated, login, logout } = useAuth();

  if (!isAuthenticated) {
    return <LoginScreen onLogin={login} />;
  }

  return (
    <ApiProvider>
      <DashboardLayout onLogout={logout} />
    </ApiProvider>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
