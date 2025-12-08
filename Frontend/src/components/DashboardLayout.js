import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, Database, Network, Settings, LogOut, Menu, X } from 'lucide-react';
import { useApi } from '../context/ApiContext';
import Overview from './Overview.js';
import ThreatDetection from './ThreatDetection.js';
import NetworkMonitor from './NetworkMonitor.js';
import SystemHealth from './SystemHealth.js';

const DashboardLayout = ({ onLogout }) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const { getDashboardData, loading } = useApi();
  const [dashboardData, setDashboardData] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, [activeTab]);

  const loadDashboardData = async () => {
    try {
      const data = await getDashboardData();
      setDashboardData(data);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  const menuItems = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'threats', label: 'Threat Detection', icon: Shield },
    { id: 'network', label: 'Network Monitor', icon: Network },
    { id: 'health', label: 'System Health', icon: Settings },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return <Overview data={dashboardData} />;
      case 'threats':
        return <ThreatDetection />;
      case 'network':
        return <NetworkMonitor />;
      case 'health':
        return <SystemHealth />;
      default:
        return <Overview data={dashboardData} />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex">
      {/* Sidebar */}
      <div className={`${sidebarOpen ? 'w-64' : 'w-20'} bg-slate-900 text-white transition-all duration-300 ease-in-out`}>
        <div className="p-4">
          <div className="flex items-center justify-between mb-8">
            <div className={`flex items-center ${!sidebarOpen && 'justify-center'}`}>
              <Shield className="w-8 h-8 text-blue-400" />
              {sidebarOpen && (
                <span className="ml-3 text-xl font-bold">Cognitive Security</span>
              )}
            </div>
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-gray-400 hover:text-white"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>

          <nav className="space-y-2">
            {menuItems.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center px-3 py-2 rounded-lg transition-colors ${
                    activeTab === item.id
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-300 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {sidebarOpen && <span className="ml-3">{item.label}</span>}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Section */}
        <div className="absolute bottom-0 w-64 p-4">
          <div className="flex items-center justify-between">
            <div className={`flex items-center ${!sidebarOpen && 'justify-center'}`}>
              <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                <span className="text-sm font-medium">A</span>
              </div>
              {sidebarOpen && (
                <div className="ml-3">
                  <p className="text-sm font-medium">Admin User</p>
                  <p className="text-xs text-gray-400">admin@cognitive.local</p>
                </div>
              )}
            </div>
            {sidebarOpen && (
              <button
                onClick={onLogout}
                className="text-gray-400 hover:text-white"
                title="Logout"
              >
                <LogOut className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="bg-white shadow-sm border-b border-gray-200">
          <div className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold text-gray-900">
                  {menuItems.find(item => item.id === activeTab)?.label || 'Dashboard'}
                </h1>
                <p className="text-sm text-gray-600">
                  AI-Powered Security Monitoring System
                </p>
              </div>
              <div className="flex items-center space-x-4">
                <div className="text-sm text-gray-600">
                  Last updated: {new Date().toLocaleTimeString()}
                </div>
                {!sidebarOpen && (
                  <button
                    onClick={onLogout}
                    className="text-gray-400 hover:text-white"
                    title="Logout"
                  >
                    <LogOut className="w-5 h-5" />
                  </button>
                )}
              </div>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 p-6 overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center h-64">
              <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
            </div>
          ) : (
            renderContent()
          )}
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
