import React, { useState, useEffect } from 'react';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [loginError, setLoginError] = useState('');
  
  // API base URL
  const API_BASE_URL = 'http://localhost:8000';
  
  // State for real data
  const [dashboardData, setDashboardData] = useState(null);
  const [threatData, setThreatData] = useState([]);
  const [networkData, setNetworkData] = useState(null);
  const [systemHealth, setSystemHealth] = useState([]);
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState(null);
  
  // API service functions
  const apiCall = async (endpoint, options = {}) => {
    try {
      setLoading(true);
      setApiError(null);
      const token = localStorage.getItem('authToken');
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
        throw new Error(`API Error: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      setApiError(error.message);
      console.error('API call failed:', error);
      return null;
    } finally {
      setLoading(false);
    }
  };
  
  // Load dashboard data
  const loadDashboardData = async () => {
    try {
      const response = await fetch('http://localhost:8001/dashboard', {
        headers: {
          'Content-Type': 'application/json',
        }
      });
      if (response.ok) {
        const data = await response.json();
        setDashboardData(data);
      }
    } catch (error) {
      console.error('Dashboard API failed:', error);
      setApiError('Failed to load dashboard data');
    }
  };
  
  // Load threat data
  const loadThreatData = async () => {
    try {
      const response = await fetch('http://localhost:8001/history?limit=50', {
        headers: {
          'Content-Type': 'application/json',
        }
      });
      if (response.ok) {
        const data = await response.json();
        const threats = data.filter(item => 
          item.waf_result?.classification !== 'Normal'
        ) || [];
        setThreatData(threats);
      }
    } catch (error) {
      console.error('Threat API failed:', error);
      setApiError('Failed to load threat data');
    }
  };
  
  // Load network data
  const loadNetworkData = async () => {
    try {
      const [statsResponse, anomaliesResponse] = await Promise.all([
        fetch('http://localhost:8004/stats'),
        fetch('http://localhost:8004/anomalies?threshold=0.7')
      ]);
      
      if (statsResponse.ok && anomaliesResponse.ok) {
        const stats = await statsResponse.json();
        const anomalies = await anomaliesResponse.json();
        
        setNetworkData({
          ...stats,
          high_risk_ips: anomalies.anomalous_count,
          anomalous_ips: anomalies.anomalous_ips
        });
      }
    } catch (error) {
      console.error('Network API failed:', error);
      setApiError('Failed to load network data');
    }
  };
  
  // Load system health
  const loadSystemHealth = async () => {
    const services = [
      { name: 'API Gateway', url: 'http://localhost:8000' },
      { name: 'Dashboard', url: 'http://localhost:8001' },
      { name: 'AI WAF', url: 'http://localhost:8002' },
      { name: 'Network Monitor', url: 'http://localhost:8004' },
      { name: 'Database', url: 'http://localhost:8005' }
    ];
    
    const healthChecks = await Promise.all(
      services.map(async (service) => {
        try {
          const response = await fetch(`${service.url}/health`);
          const data = await response.json();
          return { ...service, status: data.status || 'HEALTHY', data };
        } catch (error) {
          return { ...service, status: 'UNREACHABLE', error: error.message };
        }
      })
    );
    
    setSystemHealth(healthChecks);
  };
  // Handle login
  const handleLogin = (e) => {
    e.preventDefault();
    setLoginError('');
    
    // Simple authentication logic
    if (loginForm.username && loginForm.password) {
      // Accept any non-empty credentials for demo
      if (loginForm.username.startsWith('admin') || loginForm.username === 'admin') {
        setIsAuthenticated(true);
        const token = 'demo_admin_token_' + Date.now();
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('authToken', token);
        localStorage.setItem('user', JSON.stringify({ name: loginForm.username, role: 'admin' }));
      } else if (loginForm.username) {
        setIsAuthenticated(true);
        const token = 'demo_user_token_' + Date.now();
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('authToken', token);
        localStorage.setItem('user', JSON.stringify({ name: loginForm.username, role: 'user' }));
      } else {
        setLoginError('Invalid credentials');
      }
    } else {
      setLoginError('Please enter username and password');
    }
  };

  // Handle logout
  const handleLogout = () => {
    setIsAuthenticated(false);
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    setLoginForm({ username: '', password: '' });
    setDashboardData(null);
    setThreatData([]);
    setNetworkData(null);
    setSystemHealth([]);
  };

  // Check for existing session on mount
  React.useEffect(() => {
    const auth = localStorage.getItem('isAuthenticated');
    if (auth === 'true') {
      setIsAuthenticated(true);
    }
  }, []);
  
  // Load data when authenticated or tab changes
  React.useEffect(() => {
    if (isAuthenticated) {
      if (activeTab === 'overview') {
        loadDashboardData();
      } else if (activeTab === 'threatdetection') {
        loadThreatData();
      } else if (activeTab === 'networkmonitor') {
        loadNetworkData();
      } else if (activeTab === 'systemhealth') {
        loadSystemHealth();
      }
    }
  }, [isAuthenticated, activeTab]);
  
  // Auto-refresh data every 30 seconds
  React.useEffect(() => {
    if (isAuthenticated) {
      const interval = setInterval(() => {
        if (activeTab === 'overview') loadDashboardData();
        else if (activeTab === 'threatdetection') loadThreatData();
        else if (activeTab === 'networkmonitor') loadNetworkData();
        else if (activeTab === 'systemhealth') loadSystemHealth();
      }, 30000);
      
      return () => clearInterval(interval);
    }
  }, [isAuthenticated, activeTab]);

  // If not authenticated, show login screen
  if (!isAuthenticated) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        backgroundColor: '#f3f4f6',
        fontFamily: 'Arial, sans-serif'
      }}>
        <div style={{
          backgroundColor: 'white',
          padding: '40px',
          borderRadius: '12px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
          width: '100%',
          maxWidth: '400px'
        }}>
          <div style={{ textAlign: 'center', marginBottom: '30px' }}>
            <div style={{
              width: '60px',
              height: '60px',
              backgroundColor: '#3b82f6',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px'
            }}>
              <span style={{ color: 'white', fontSize: '24px', fontWeight: 'bold' }}>CS</span>
            </div>
            <h2 style={{ color: '#1f2937', fontSize: '1.5rem', marginBottom: '8px' }}>
              Cognitive Security
            </h2>
            <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>
              AI-Powered Security Dashboard
            </p>
          </div>

          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {loginError && (
              <div style={{
                backgroundColor: '#fef2f2',
                color: '#991b1b',
                padding: '12px',
                borderRadius: '6px',
                fontSize: '0.875rem',
                border: '1px solid #fecaca'
              }}>
                {loginError}
              </div>
            )}

            <div>
              <label style={{ display: 'block', color: '#374151', fontSize: '0.875rem', marginBottom: '6px' }}>
                Username
              </label>
              <input
                type="text"
                value={loginForm.username}
                onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                style={{
                  width: '100%',
                  padding: '10px',
                  border: '1px solid #d1d5db',
                  borderRadius: '6px',
                  fontSize: '0.875rem'
                }}
                placeholder="Enter username"
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', color: '#374151', fontSize: '0.875rem', marginBottom: '6px' }}>
                Password
              </label>
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                style={{
                  width: '100%',
                  padding: '10px',
                  border: '1px solid #d1d5db',
                  borderRadius: '6px',
                  fontSize: '0.875rem'
                }}
                placeholder="Enter password"
                required
              />
            </div>

            <button
              type="submit"
              style={{
                backgroundColor: '#3b82f6',
                color: 'white',
                padding: '12px',
                border: 'none',
                borderRadius: '6px',
                fontSize: '0.875rem',
                fontWeight: 'bold',
                cursor: 'pointer',
                transition: 'backgroundColor 0.2s'
              }}
              onMouseOver={(e) => e.target.style.backgroundColor = '#2563eb'}
              onMouseOut={(e) => e.target.style.backgroundColor = '#3b82f6'}
            >
              Sign In
            </button>
          </form>

          <div style={{
            marginTop: '24px',
            padding: '16px',
            backgroundColor: '#f9fafb',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#6b7280'
          }}>
            <p style={{ marginBottom: '8px', fontWeight: 'bold' }}>Demo Credentials:</p>
            <p>Admin: admin / admin123</p>
            <p>User: user / user123</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ 
      display: 'flex',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      backgroundColor: '#0f172a',
      minHeight: '100vh',
      color: '#e2e8f0'
    }}>
      {/* Sidebar */}
      <div style={{
        width: '280px',
        backgroundColor: '#1e293b',
        padding: '24px',
        color: 'white',
        borderRight: '1px solid #334155'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '40px',
              height: '40px',
              background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px',
              fontWeight: 'bold'
            }}>
              CS
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: '600', margin: 0 }}>Cognitive</h2>
              <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: 0 }}>Security</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            style={{
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              color: '#ef4444',
              border: '1px solid rgba(239, 68, 68, 0.2)',
              padding: '8px 16px',
              borderRadius: '8px',
              fontSize: '0.75rem',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
            onMouseOver={(e) => e.target.style.backgroundColor = 'rgba(239, 68, 68, 0.2)'}
            onMouseOut={(e) => e.target.style.backgroundColor = 'rgba(239, 68, 68, 0.1)'}
          >
            Logout
          </button>
        </div>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {['Overview', 'Threat Detection', 'Network Monitor', 'System Health'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab.toLowerCase().replace(' ', ''))}
              style={{
                padding: '14px 18px',
                backgroundColor: activeTab === tab.toLowerCase().replace(' ', '') ? 'rgba(59, 130, 246, 0.2)' : 'transparent',
                color: activeTab === tab.toLowerCase().replace(' ', '') ? '#3b82f6' : '#94a3b8',
                border: activeTab === tab.toLowerCase().replace(' ', '') ? '1px solid rgba(59, 130, 246, 0.3)' : '1px solid transparent',
                borderRadius: '10px',
                cursor: 'pointer',
                textAlign: 'left',
                fontSize: '0.9rem',
                fontWeight: activeTab === tab.toLowerCase().replace(' ', '') ? '500' : '400',
                transition: 'all 0.2s'
              }}
              onMouseOver={(e) => {
                if (!e.target.style.backgroundColor.includes('rgba(59, 130, 246')) {
                  e.target.style.backgroundColor = 'rgba(148, 163, 184, 0.1)';
                }
              }}
              onMouseOut={(e) => {
                if (!e.target.style.backgroundColor.includes('rgba(59, 130, 246')) {
                  e.target.style.backgroundColor = 'transparent';
                }
              }}
            >
              {tab}
            </button>
          ))}
        </nav>
        
        {/* User Info */}
        <div style={{
          position: 'absolute',
          bottom: '24px',
          left: '24px',
          right: '24px',
          padding: '16px',
          backgroundColor: 'rgba(51, 65, 85, 0.5)',
          backdropFilter: 'blur(10px)',
          borderRadius: '12px',
          border: '1px solid rgba(148, 163, 184, 0.2)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
            <div style={{
              width: '32px',
              height: '32px',
              backgroundColor: '#3b82f6',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '14px',
              fontWeight: 'bold'
            }}>
              {(JSON.parse(localStorage.getItem('user') || '{}')?.name || 'User')[0].toUpperCase()}
            </div>
            <div>
              <p style={{ fontSize: '0.9rem', margin: '0', color: '#e2e8f0', fontWeight: '500' }}>
                {JSON.parse(localStorage.getItem('user') || '{}')?.name || 'User'}
              </p>
              <p style={{ fontSize: '0.75rem', margin: '0', color: '#94a3b8' }}>
                {JSON.parse(localStorage.getItem('user') || '{}')?.role || 'user'}
              </p>
            </div>
          </div>
        </div>
      </div>
      
      {/* Main Content */}
      <div style={{ flex: 1, padding: '32px', overflow: 'auto' }}>
        <div style={{ marginBottom: '32px' }}>
          <h1 style={{ 
            color: '#f1f5f9', 
            fontSize: '2.5rem',
            fontWeight: '700',
            marginBottom: '8px',
            background: 'linear-gradient(135deg, #f1f5f9, #94a3b8)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text'
          }}>
            Cognitive Security Dashboard
          </h1>
          <p style={{ color: '#64748b', fontSize: '1rem', margin: 0 }}>
            Real-time AI-powered threat detection and network monitoring
          </p>
        </div>
        
        <div style={{
          backgroundColor: 'rgba(30, 41, 59, 0.8)',
          backdropFilter: 'blur(20px)',
          padding: '24px',
          borderRadius: '16px',
          border: '1px solid rgba(148, 163, 184, 0.1)',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
        }}>
          <h2 style={{ color: '#f1f5f9', marginBottom: '20px', fontSize: '1.25rem', fontWeight: '600' }}>
            System Overview
          </h2>
        {activeTab === 'overview' && (
          <div>
            {apiError && (
              <div style={{
                backgroundColor: '#fef2f2',
                color: '#991b1b',
                padding: '12px',
                borderRadius: '6px',
                marginBottom: '20px',
                border: '1px solid #fecaca'
              }}>
                API Error: {apiError}
              </div>
            )}
            
            {loading ? (
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  border: '4px solid #e5e7eb',
                  borderTop: '4px solid #3b82f6',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite',
                  margin: '0 auto'
                }}></div>
                <p style={{ color: '#6b7280', marginTop: '16px' }}>Loading dashboard data...</p>
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                  <div style={{ backgroundColor: '#dbeafe', padding: '20px', borderRadius: '8px' }}>
                    <h3 style={{ color: '#1e40af', fontSize: '0.875rem', marginBottom: '8px' }}>Total Requests</h3>
                    <p style={{ color: '#1e40af', fontSize: '2rem', fontWeight: 'bold' }}>
                      {dashboardData?.metrics?.total_requests || '0'}
                    </p>
                    <p style={{ color: '#3b82f6', fontSize: '0.875rem' }}>
                      Total requests processed
                    </p>
                  </div>
                  <div style={{ backgroundColor: '#fee2e2', padding: '20px', borderRadius: '8px' }}>
                    <h3 style={{ color: '#991b1b', fontSize: '0.875rem', marginBottom: '8px' }}>Blocked Requests</h3>
                    <p style={{ color: '#991b1b', fontSize: '2rem', fontWeight: 'bold' }}>
                      {dashboardData?.metrics?.blocked_requests || '0'}
                    </p>
                    <p style={{ color: '#dc2626', fontSize: '0.875rem' }}>
                      Requests blocked by WAF
                    </p>
                  </div>
                  <div style={{ backgroundColor: '#fef3c7', padding: '20px', borderRadius: '8px' }}>
                    <h3 style={{ color: '#92400e', fontSize: '0.875rem', marginBottom: '8px' }}>Active Threats</h3>
                    <p style={{ color: '#92400e', fontSize: '2rem', fontWeight: 'bold' }}>
                      {dashboardData?.metrics?.active_threats || '0'}
                    </p>
                    <p style={{ color: '#f59e0b', fontSize: '0.875rem' }}>
                      Currently active threats
                    </p>
                  </div>
                  <div style={{ backgroundColor: '#d1fae5', padding: '20px', borderRadius: '8px' }}>
                    <h3 style={{ color: '#065f46', fontSize: '0.875rem', marginBottom: '8px' }}>System Health</h3>
                    <p style={{ color: '#065f46', fontSize: '2rem', fontWeight: 'bold' }}>
                      {dashboardData?.metrics?.system_health || 'HEALTHY'}
                    </p>
                    <p style={{ color: '#10b981', fontSize: '0.875rem' }}>
                      Overall system status
                    </p>
                  </div>
                </div>
                
                <div style={{ backgroundColor: '#f9fafb', padding: '20px', borderRadius: '8px' }}>
                  <h3 style={{ color: '#374151', marginBottom: '15px' }}>Recent Activity</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {dashboardData?.recent_activity?.slice(0, 5).map((activity, index) => (
                      <div key={index} style={{ backgroundColor: 'white', padding: '12px', borderRadius: '6px', borderLeft: '4px solid #3b82f6' }}>
                        <p style={{ color: '#374151', fontSize: '0.875rem' }}>
                          Request {activity.request_id?.substring(0, 8)}... - {activity.waf_result?.classification || 'Normal'}
                        </p>
                        <p style={{ color: '#6b7280', fontSize: '0.75rem' }}>
                          {new Date(activity.timestamp).toLocaleString()}
                        </p>
                      </div>
                    )) || (
                      <p style={{ color: '#6b7280', textAlign: 'center', padding: '20px' }}>
                        No recent activity data available
                      </p>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
        {activeTab === 'threatdetection' && (
          <div>
            <h3 style={{ color: '#374151', marginBottom: '20px' }}>Threat Detection Dashboard</h3>
            {loading ? (
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  border: '4px solid #e5e7eb',
                  borderTop: '4px solid #ef4444',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite',
                  margin: '0 auto'
                }}></div>
                <p style={{ color: '#6b7280', marginTop: '16px' }}>Loading threat data...</p>
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                  <div style={{ backgroundColor: '#fef2f2', padding: '20px', borderRadius: '8px', border: '1px solid #fecaca' }}>
                    <h4 style={{ color: '#991b1b', marginBottom: '10px' }}>Critical Threats</h4>
                    <p style={{ color: '#dc2626', fontSize: '1.5rem', fontWeight: 'bold' }}>
                      {threatData.filter(t => t.waf_result?.threat_level === 'CRITICAL').length}
                    </p>
                    <p style={{ color: '#7f1d1d', fontSize: '0.875rem' }}>Immediate attention required</p>
                  </div>
                  <div style={{ backgroundColor: '#fff7ed', padding: '20px', borderRadius: '8px', border: '1px solid #fed7aa' }}>
                    <h4 style={{ color: '#9a3412', marginBottom: '10px' }}>High Risk</h4>
                    <p style={{ color: '#ea580c', fontSize: '1.5rem', fontWeight: 'bold' }}>
                      {threatData.filter(t => t.waf_result?.threat_level === 'HIGH').length}
                    </p>
                    <p style={{ color: '#92400e', fontSize: '0.875rem' }}>Monitor closely</p>
                  </div>
                  <div style={{ backgroundColor: '#fef3c7', padding: '20px', borderRadius: '8px', border: '1px solid #fde68a' }}>
                    <h4 style={{ color: '#92400e', marginBottom: '10px' }}>Medium Risk</h4>
                    <p style={{ color: '#f59e0b', fontSize: '1.5rem', fontWeight: 'bold' }}>
                      {threatData.filter(t => t.waf_result?.threat_level === 'MEDIUM').length}
                    </p>
                    <p style={{ color: '#92400e', fontSize: '0.875rem' }}>Under observation</p>
                  </div>
                </div>
                
                <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
                  <h4 style={{ color: '#374151', marginBottom: '15px' }}>Recent Threats</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {threatData.slice(0, 10).map((threat, index) => (
                      <div key={index} style={{ 
                        backgroundColor: '#f9fafb', 
                        padding: '12px', 
                        borderRadius: '6px',
                        borderLeft: `4px solid ${
                          threat.waf_result?.threat_level === 'CRITICAL' ? '#dc2626' :
                          threat.waf_result?.threat_level === 'HIGH' ? '#ea580c' :
                          '#f59e0b'
                        }`
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <p style={{ color: '#374151', fontSize: '0.875rem', fontWeight: 'bold' }}>
                              {threat.waf_result?.classification || 'Unknown Threat'}
                            </p>
                            <p style={{ color: '#6b7280', fontSize: '0.75rem' }}>
                              IP: {threat.ip_address || 'Unknown'} | Time: {new Date(threat.timestamp).toLocaleString()}
                            </p>
                          </div>
                          <div style={{ textAlign: 'right' }}>
                            <span style={{
                              backgroundColor: threat.waf_result?.action_taken === 'BLOCK' ? '#fee2e2' : '#fef3c7',
                              color: threat.waf_result?.action_taken === 'BLOCK' ? '#991b1b' : '#92400e',
                              padding: '4px 8px',
                              borderRadius: '4px',
                              fontSize: '0.75rem'
                            }}>
                              {threat.waf_result?.action_taken || 'UNKNOWN'}
                            </span>
                          </div>
                        </div>
                      </div>
                    )) || (
                      <p style={{ color: '#6b7280', textAlign: 'center', padding: '20px' }}>
                        No threat data available
                      </p>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
        {activeTab === 'networkmonitor' && (
          <div>
            <h3 style={{ color: '#374151', marginBottom: '20px' }}>Network Monitoring</h3>
            {loading ? (
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  border: '4px solid #e5e7eb',
                  borderTop: '4px solid #0ea5e9',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite',
                  margin: '0 auto'
                }}></div>
                <p style={{ color: '#6b7280', marginTop: '16px' }}>Loading network data...</p>
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                  <div style={{ backgroundColor: '#f0f9ff', padding: '20px', borderRadius: '8px', border: '1px solid #bae6fd' }}>
                    <h4 style={{ color: '#075985', marginBottom: '15px' }}>Network Statistics</h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '15px' }}>
                      <div>
                        <p style={{ color: '#0c4a6e', fontSize: '0.875rem' }}>Active Connections</p>
                        <p style={{ color: '#0369a1', fontSize: '1.25rem', fontWeight: 'bold' }}>
                          {networkData?.active_connections || '0'}
                        </p>
                      </div>
                      <div>
                        <p style={{ color: '#0c4a6e', fontSize: '0.875rem' }}>Bandwidth Usage</p>
                        <p style={{ color: '#0369a1', fontSize: '1.25rem', fontWeight: 'bold' }}>
                          {networkData?.bandwidth_mbps || '0'} Mbps
                        </p>
                      </div>
                      <div>
                        <p style={{ color: '#0c4a6e', fontSize: '0.875rem' }}>Total Requests</p>
                        <p style={{ color: '#0369a1', fontSize: '1.25rem', fontWeight: 'bold' }}>
                          {networkData?.total_requests?.toLocaleString() || '0'}
                        </p>
                      </div>
                      <div>
                        <p style={{ color: '#0c4a6e', fontSize: '0.875rem' }}>Blocked Requests</p>
                        <p style={{ color: '#0369a1', fontSize: '1.25rem', fontWeight: 'bold' }}>
                          {networkData?.total_blocks?.toLocaleString() || '0'}
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  <div style={{ backgroundColor: '#fef2f2', padding: '20px', borderRadius: '8px', border: '1px solid #fecaca' }}>
                    <h4 style={{ color: '#991b1b', marginBottom: '15px' }}>Anomalous IPs</h4>
                    <p style={{ color: '#dc2626', fontSize: '1.5rem', fontWeight: 'bold' }}>
                      {networkData?.high_risk_ips || '0'}
                    </p>
                    <p style={{ color: '#7f1d1d', fontSize: '0.875rem' }}>High risk IP addresses detected</p>
                  </div>
                </div>
                
                {networkData?.anomalous_ips && networkData.anomalous_ips.length > 0 && (
                  <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
                    <h4 style={{ color: '#374151', marginBottom: '15px' }}>Top Anomalous IP Addresses</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {networkData.anomalous_ips.slice(0, 10).map((ip, index) => (
                        <div key={index} style={{ 
                          backgroundColor: '#f9fafb', 
                          padding: '12px', 
                          borderRadius: '6px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}>
                          <div>
                            <p style={{ color: '#374151', fontSize: '0.875rem', fontWeight: 'bold' }}>
                              {ip.ip}
                            </p>
                            <p style={{ color: '#6b7280', fontSize: '0.75rem' }}>
                              Requests: {ip.request_count} | Blocked: {ip.blocked_attempts}
                            </p>
                          </div>
                          <div style={{ textAlign: 'right' }}>
                            <div style={{
                              width: '60px',
                              height: '4px',
                              backgroundColor: '#e5e7eb',
                              borderRadius: '2px',
                              overflow: 'hidden'
                            }}>
                              <div style={{
                                width: `${ip.anomaly_score * 100}%`,
                                height: '100%',
                                backgroundColor: ip.anomaly_score > 0.8 ? '#dc2626' : ip.anomaly_score > 0.6 ? '#ea580c' : '#f59e0b'
                              }}></div>
                            </div>
                            <p style={{ color: '#6b7280', fontSize: '0.75rem', marginTop: '4px' }}>
                              {(ip.anomaly_score * 100).toFixed(1)}%
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
        {activeTab === 'systemhealth' && (
          <div>
            <h3 style={{ color: '#374151', marginBottom: '20px' }}>System Health Status</h3>
            {loading ? (
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  border: '4px solid #e5e7eb',
                  borderTop: '4px solid #10b981',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite',
                  margin: '0 auto'
                }}></div>
                <p style={{ color: '#6b7280', marginTop: '16px' }}>Checking system health...</p>
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                  {systemHealth.map((service, index) => (
                    <div key={index} style={{
                      backgroundColor: 'white',
                      padding: '20px',
                      borderRadius: '8px',
                      border: `1px solid ${
                        service.status === 'HEALTHY' || service.status === 'Operational' ? '#d1fae5' :
                        service.status === 'WARNING' ? '#fef3c7' :
                        '#fee2e2'
                      }`
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '15px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div style={{
                            width: '12px',
                            height: '12px',
                            backgroundColor: service.status === 'HEALTHY' || service.status === 'Operational' ? '#10b981' :
                            service.status === 'WARNING' ? '#f59e0b' :
                            '#ef4444',
                            borderRadius: '50%'
                          }}></div>
                          <span style={{ color: '#374151', fontWeight: 'bold' }}>{service.name}</span>
                        </div>
                        <span style={{
                          fontSize: '0.75rem',
                          padding: '4px 8px',
                          borderRadius: '4px',
                          backgroundColor: service.status === 'HEALTHY' || service.status === 'Operational' ? '#d1fae5' :
                          service.status === 'WARNING' ? '#fef3c7' :
                          '#fee2e2',
                          color: service.status === 'HEALTHY' || service.status === 'Operational' ? '#065f46' :
                          service.status === 'WARNING' ? '#92400e' :
                          '#991b1b'
                        }}>
                          {service.status}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                        <p>URL: {service.url}</p>
                        {service.uptime && <p>Uptime: {service.uptime}</p>}
                        {service.error && <p style={{ color: '#ef4444' }}>Error: {service.error}</p>}
                      </div>
                    </div>
                  ))}
                </div>
                
                <div style={{ backgroundColor: '#f9fafb', padding: '20px', borderRadius: '8px' }}>
                  <h4 style={{ color: '#374151', marginBottom: '15px' }}>System Summary</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
                    <div style={{ textAlign: 'center' }}>
                      <p style={{ color: '#10b981', fontSize: '1.5rem', fontWeight: 'bold' }}>
                        {systemHealth.filter(s => s.status === 'HEALTHY' || s.status === 'Operational').length}
                      </p>
                      <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>Healthy Services</p>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <p style={{ color: '#f59e0b', fontSize: '1.5rem', fontWeight: 'bold' }}>
                        {systemHealth.filter(s => s.status === 'WARNING').length}
                      </p>
                      <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>Warning Services</p>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <p style={{ color: '#ef4444', fontSize: '1.5rem', fontWeight: 'bold' }}>
                        {systemHealth.filter(s => s.status === 'UNHEALTHY' || s.status === 'UNREACHABLE').length}
                      </p>
                      <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>Unhealthy Services</p>
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>
      </div>
    </div>
  );
}

export default App;
