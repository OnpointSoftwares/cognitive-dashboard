import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Search, Filter, Eye, Block } from 'lucide-react';
import { useApi } from '../context/ApiContext';

const ThreatDetection = () => {
  const { getRequestHistory } = useApi();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadThreats();
  }, []);

  const loadThreats = async () => {
    try {
      const data = await getRequestHistory(100);
      const threatData = data.results?.filter(item => 
        item.waf_result?.classification !== 'Normal'
      ) || [];
      setThreats(threatData);
    } catch (error) {
      console.error('Failed to load threats:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredThreats = threats.filter(threat => {
    const matchesFilter = filter === 'all' || threat.waf_result?.classification === filter;
    const matchesSearch = threat.request_id?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getThreatColor = (classification) => {
    switch (classification) {
      case 'DDoS_Attack': return 'bg-red-100 text-red-800';
      case 'Intrusion_Attempt': return 'bg-orange-100 text-orange-800';
      case 'Neuro_Risk_Flag': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getActionColor = (action) => {
    return action === 'BLOCK' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800';
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
      {/* Header with Filters */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">Threat Detection</h2>
          <div className="mt-4 sm:mt-0 flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search threats..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Threats</option>
              <option value="DDoS_Attack">DDoS Attack</option>
              <option value="Intrusion_Attempt">Intrusion Attempt</option>
              <option value="Neuro_Risk_Flag">Neuro Risk</option>
            </select>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-red-50 rounded-lg p-4">
            <div className="flex items-center">
              <AlertTriangle className="w-8 h-8 text-red-600 mr-3" />
              <div>
                <p className="text-sm text-red-600">Critical Threats</p>
                <p className="text-2xl font-bold text-red-900">
                  {threats.filter(t => t.waf_result?.threat_level === 'CRITICAL').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-orange-50 rounded-lg p-4">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-orange-600 mr-3" />
              <div>
                <p className="text-sm text-orange-600">High Risk</p>
                <p className="text-2xl font-bold text-orange-900">
                  {threats.filter(t => t.waf_result?.threat_level === 'HIGH').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-yellow-50 rounded-lg p-4">
            <div className="flex items-center">
              <Eye className="w-8 h-8 text-yellow-600 mr-3" />
              <div>
                <p className="text-sm text-yellow-600">Under Monitor</p>
                <p className="text-2xl font-bold text-yellow-900">
                  {threats.filter(t => t.waf_result?.action_taken === 'MONITOR').length}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Threats Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recent Threats</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Request ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">User ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Threat Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Confidence</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Threat Level</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredThreats.map((threat, index) => (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {new Date(threat.timestamp).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                    {threat.request_id?.substring(0, 12)}...
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {threat.user_id || 'Anonymous'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getThreatColor(threat.waf_result?.classification)}`}>
                      {threat.waf_result?.classification || 'Unknown'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {threat.waf_result?.confidence 
                      ? `${(threat.waf_result.confidence * 100).toFixed(1)}%`
                      : 'N/A'
                    }
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      threat.waf_result?.threat_level === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                      threat.waf_result?.threat_level === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                      threat.waf_result?.threat_level === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {threat.waf_result?.threat_level || 'Unknown'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getActionColor(threat.waf_result?.action_taken)}`}>
                      {threat.waf_result?.action_taken || 'Unknown'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {filteredThreats.length === 0 && (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No threats found matching your criteria</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatDetection;
