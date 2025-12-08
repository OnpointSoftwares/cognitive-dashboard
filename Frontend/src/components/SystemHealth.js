import React, { useState, useEffect } from 'react';
import { Server, CheckCircle, AlertCircle, XCircle, Activity, Database, Shield, Globe } from 'lucide-react';
import { useApi } from '../context/ApiContext';

const SystemHealth = () => {
  const { getServiceHealth, getDatabaseStats } = useApi();
  const [services, setServices] = useState([]);
  const [databaseStats, setDatabaseStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSystemHealth();
  }, []);

  const loadSystemHealth = async () => {
    try {
      const serviceList = [
        { name: 'Dashboard', id: 'dashboard', url: 'http://localhost:8001' },
        { name: 'AI WAF', id: 'waf', url: 'http://localhost:8002' },
        { name: 'Network Monitor', id: 'network', url: 'http://localhost:8004' },
        { name: 'Database', id: 'database', url: 'http://localhost:8005' },
      ];

      const healthChecks = await Promise.all(
        serviceList.map(async (service) => {
          try {
            const health = await getServiceHealth(service.id);
            return {
              ...service,
              status: health.status || 'HEALTHY',
              uptime: health.uptime || 'Unknown',
              lastCheck: new Date().toISOString()
            };
          } catch (error) {
            return {
              ...service,
              status: 'UNREACHABLE',
              uptime: 'Unknown',
              lastCheck: new Date().toISOString(),
              error: error.message
            };
          }
        })
      );

      setServices(healthChecks);

      const dbStats = await getDatabaseStats();
      setDatabaseStats(dbStats);
    } catch (error) {
      console.error('Failed to load system health:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'HEALTHY':
      case 'Operational':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'WARNING':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      case 'UNHEALTHY':
      case 'FAILED':
      case 'UNREACHABLE':
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'HEALTHY':
      case 'Operational':
        return 'bg-green-100 text-green-800';
      case 'WARNING':
        return 'bg-yellow-100 text-yellow-800';
      case 'UNHEALTHY':
      case 'FAILED':
      case 'UNREACHABLE':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getServiceIcon = (serviceId) => {
    switch (serviceId) {
      case 'dashboard':
        return <Activity className="w-6 h-6" />;
      case 'waf':
        return <Shield className="w-6 h-6" />;
      case 'network':
        return <Globe className="w-6 h-6" />;
      case 'database':
        return <Database className="w-6 h-6" />;
      default:
        return <Server className="w-6 h-6" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* System Overview */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">System Health Overview</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-green-50 rounded-lg p-4">
            <div className="flex items-center">
              <CheckCircle className="w-8 h-8 text-green-600 mr-3" />
              <div>
                <p className="text-sm text-green-600">Healthy Services</p>
                <p className="text-2xl font-bold text-green-900">
                  {services.filter(s => s.status === 'HEALTHY' || s.status === 'Operational').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-yellow-50 rounded-lg p-4">
            <div className="flex items-center">
              <AlertCircle className="w-8 h-8 text-yellow-600 mr-3" />
              <div>
                <p className="text-sm text-yellow-600">Warning Services</p>
                <p className="text-2xl font-bold text-yellow-900">
                  {services.filter(s => s.status === 'WARNING').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-red-50 rounded-lg p-4">
            <div className="flex items-center">
              <XCircle className="w-8 h-8 text-red-600 mr-3" />
              <div>
                <p className="text-sm text-red-600">Unhealthy Services</p>
                <p className="text-2xl font-bold text-red-900">
                  {services.filter(s => s.status === 'UNHEALTHY' || s.status === 'FAILED' || s.status === 'UNREACHABLE').length}
                </p>
              </div>
            </div>
          </div>
        </div>

        <button
          onClick={loadSystemHealth}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          Refresh Status
        </button>
      </div>

      {/* Services Status */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Service Status</h3>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {services.map((service, index) => (
              <div key={index} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                <div className="flex items-center">
                  <div className="p-2 bg-gray-100 rounded-lg mr-4">
                    {getServiceIcon(service.id)}
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-900">{service.name}</h4>
                    <p className="text-sm text-gray-600">{service.url}</p>
                    {service.error && (
                      <p className="text-xs text-red-600 mt-1">{service.error}</p>
                    )}
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(service.status)}`}>
                    {service.status}
                  </span>
                  {getStatusIcon(service.status)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Database Statistics */}
      {databaseStats && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Database Statistics</h3>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">{databaseStats.total_collections}</p>
                <p className="text-sm text-gray-600">Total Collections</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">{databaseStats.total_entries?.toLocaleString() || '0'}</p>
                <p className="text-sm text-gray-600">Total Entries</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">
                  {databaseStats.collection_details ? Object.keys(databaseStats.collection_details).length : 0}
                </p>
                <p className="text-sm text-gray-600">Active Collections</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">
                  {databaseStats.collection_details ? 
                    Object.values(databaseStats.collection_details).reduce((acc, col) => acc + (col.size_bytes || 0), 0) / 1024 / 1024 : 0
                  } MB
                </p>
                <p className="text-sm text-gray-600">Storage Used</p>
              </div>
            </div>

            {databaseStats.collection_details && (
              <div className="mt-6">
                <h4 className="font-medium text-gray-900 mb-3">Collection Details</h4>
                <div className="space-y-2">
                  {Object.entries(databaseStats.collection_details).map(([name, details]) => (
                    <div key={name} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                      <span className="text-sm font-medium text-gray-900">{name}</span>
                      <div className="flex items-center space-x-4 text-sm text-gray-600">
                        <span>{details.entry_count} entries</span>
                        <span>{(details.size_bytes / 1024).toFixed(1)} KB</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SystemHealth;
