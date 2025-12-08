import React, { createContext, useContext, useState, useEffect } from 'react';

const ApiContext = createContext();

export const useApi = () => {
  const context = useContext(ApiContext);
  if (!context) {
    throw new Error('useApi must be used within an ApiProvider');
  }
  return context;
};

const API_BASE_URL = 'http://localhost:8000'; // API Gateway

export const ApiProvider = ({ children }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Generic API request function
  const apiRequest = async (endpoint, options = {}) => {
    setLoading(true);
    setError(null);
    
    try {
      const token = localStorage.getItem('auth_token');
      const headers = {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` }),
        ...options.headers
      };

      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status} - ${response.statusText}`);
      }

      const data = await response.json();
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // Dashboard API calls
  const getDashboardData = async () => {
    return apiRequest('/api/v1/dashboard/dashboard');
  };

  const getMetrics = async () => {
    return apiRequest('/api/v1/dashboard/metrics');
  };

  const getRequestHistory = async (limit = 100, userId = null) => {
    const params = new URLSearchParams({ limit: limit.toString() });
    if (userId) params.append('user_id', userId);
    
    return apiRequest(`/api/v1/dashboard/history?${params}`);
  };

  // WAF API calls
  const analyzeRequest = async (requestData) => {
    return apiRequest('/api/v1/waf/analyze', {
      method: 'POST',
      body: JSON.stringify(requestData)
    });
  };

  // Network monitoring API calls
  const getNetworkStats = async () => {
    return apiRequest('/api/v1/network/stats');
  };

  const getAnomalousIPs = async (threshold = 0.7) => {
    return apiRequest(`/api/v1/network/anomalies?threshold=${threshold}`);
  };

  // Database API calls
  const getDatabaseStats = async () => {
    return apiRequest('/api/v1/database/stats');
  };

  // System health checks
  const getSystemHealth = async () => {
    return apiRequest('/health');
  };

  const getServiceHealth = async (service) => {
    const serviceUrls = {
      dashboard: 'http://localhost:8001',
      waf: 'http://localhost:8002',
      network: 'http://localhost:8004',
      database: 'http://localhost:8005'
    };

    try {
      const response = await fetch(`${serviceUrls[service]}/health`);
      return await response.json();
    } catch (err) {
      return { status: 'UNREACHABLE' };
    }
  };

  const value = {
    loading,
    error,
    apiRequest,
    // Dashboard methods
    getDashboardData,
    getMetrics,
    getRequestHistory,
    // WAF methods
    analyzeRequest,
    // Network methods
    getNetworkStats,
    getAnomalousIPs,
    // Database methods
    getDatabaseStats,
    // Health methods
    getSystemHealth,
    getServiceHealth
  };

  return (
    <ApiContext.Provider value={value}>
      {children}
    </ApiContext.Provider>
  );
};
