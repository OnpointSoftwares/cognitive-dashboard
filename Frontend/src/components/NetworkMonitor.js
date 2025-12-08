import React, { useState, useEffect } from 'react';
import { Network, Activity, AlertTriangle, Globe, Server } from 'lucide-react';
import { useApi } from '../context/ApiContext';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

const NetworkMonitor = () => {
  const { getNetworkStats, getAnomalousIPs } = useApi();
  const [networkStats, setNetworkStats] = useState(null);
  const [anomalousIPs, setAnomalousIPs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadNetworkData();
  }, []);

  const loadNetworkData = async () => {
    try {
      const [statsData, anomalousData] = await Promise.all([
        getNetworkStats(),
        getAnomalousIPs()
      ]);
      
      setNetworkStats(statsData);
      setAnomalousIPs(anomalousData.anomalous_ips || []);
    } catch (error) {
      console.error('Failed to load network data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Mock network traffic data
  const trafficData = [
    { time: '00:00', normal: 1200, anomalous: 45 },
    { time: '04:00', normal: 800, anomalous: 12 },
    { time: '08:00', normal: 2100, anomalous: 89 },
    { time: '12:00', normal: 2800, anomalous: 156 },
    { time: '16:00', normal: 2400, anomalous: 134 },
    { time: '20:00', normal: 1900, anomalous: 98 },
  ];

  const StatCard = ({ title, value, icon: Icon, color = 'blue', subtitle }) => (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
          {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
        </div>
        <div className={`p-3 bg-${color}-100 rounded-full`}>
          <Icon className={`w-6 h-6 text-${color}-600`} />
        </div>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Network Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Monitored IPs"
          value={networkStats?.monitored_ips || '0'}
          icon={Globe}
          color="blue"
          subtitle="Active connections"
        />
        <StatCard
          title="Total Requests"
          value={networkStats?.total_requests?.toLocaleString() || '0'}
          icon={Activity}
          color="green"
          subtitle="Last 24 hours"
        />
        <StatCard
          title="Blocked Requests"
          value={networkStats?.total_blocks?.toLocaleString() || '0'}
          icon={AlertTriangle}
          color="red"
          subtitle={`${((networkStats?.block_rate || 0) * 100).toFixed(1)}% rate`}
        />
        <StatCard
          title="High Risk IPs"
          value={networkStats?.high_risk_ips || '0'}
          icon={Server}
          color="orange"
          subtitle="Anomaly score > 0.7"
        />
      </div>

      {/* Network Traffic Chart */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Network Traffic Analysis</h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={trafficData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Area type="monotone" dataKey="normal" stackId="1" stroke="#10b981" fill="#10b981" />
            <Area type="monotone" dataKey="anomalous" stackId="1" stroke="#ef4444" fill="#ef4444" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Anomalous IPs Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Anomalous IP Addresses</h3>
          <p className="text-sm text-gray-600">IPs with high anomaly scores requiring attention</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Anomaly Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Request Count</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Blocked Attempts</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reputation</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {anomalousIPs.slice(0, 10).map((ip, index) => (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                    {ip.ip}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                        <div 
                          className="bg-red-500 h-2 rounded-full" 
                          style={{ width: `${ip.anomaly_score * 100}%` }}
                        ></div>
                      </div>
                      <span className="text-sm text-gray-900">
                        {(ip.anomaly_score * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {ip.request_count?.toLocaleString() || '0'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {ip.blocked_attempts || '0'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      ip.reputation_score > 0.7 ? 'bg-green-100 text-green-800' :
                      ip.reputation_score > 0.3 ? 'bg-yellow-100 text-yellow-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {ip.reputation_score > 0.7 ? 'Good' :
                       ip.reputation_score > 0.3 ? 'Medium' : 'Poor'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      ip.anomaly_score > 0.8 ? 'bg-red-100 text-red-800' :
                      ip.anomaly_score > 0.6 ? 'bg-orange-100 text-orange-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {ip.anomaly_score > 0.8 ? 'Critical' :
                       ip.anomaly_score > 0.6 ? 'High' : 'Monitor'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {anomalousIPs.length === 0 && (
          <div className="text-center py-12">
            <Network className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No anomalous IPs detected</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkMonitor;
