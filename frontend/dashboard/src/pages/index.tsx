/**
 * Aethelred Dashboard - Main Explorer Page
 *
 * Real-time blockchain explorer and network statistics dashboard.
 */

import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  Blocks,
  Shield,
  Cpu,
  Users,
  TrendingUp,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Search,
  RefreshCw,
} from 'lucide-react';

// API configuration
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://api.mainnet.aethelred.io';

// Types
interface NetworkStats {
  totalJobs: number;
  completedJobs: number;
  activeValidators: number;
  totalSeals: number;
  averageBlockTime: number;
  currentEpoch: number;
  totalUsefulWork: string;
}

interface RecentJob {
  id: string;
  status: string;
  modelHash: string;
  creator: string;
  createdAt: string;
  proofType: string;
}

interface RecentSeal {
  id: string;
  jobId: string;
  status: string;
  createdAt: string;
  validatorCount: number;
}

interface Validator {
  address: string;
  moniker: string;
  votingPower: number;
  jobsCompleted: number;
  uptime: number;
}

// Fetch functions
async function fetchNetworkStats(): Promise<NetworkStats> {
  const response = await fetch(`${API_URL}/v1/network/stats`);
  if (!response.ok) throw new Error('Failed to fetch network stats');
  return response.json();
}

async function fetchRecentJobs(): Promise<RecentJob[]> {
  const response = await fetch(`${API_URL}/v1/jobs?limit=10&sort=created_at:desc`);
  if (!response.ok) throw new Error('Failed to fetch jobs');
  const data = await response.json();
  return data.jobs || [];
}

async function fetchRecentSeals(): Promise<RecentSeal[]> {
  const response = await fetch(`${API_URL}/v1/seals?limit=10&sort=created_at:desc`);
  if (!response.ok) throw new Error('Failed to fetch seals');
  const data = await response.json();
  return data.seals || [];
}

async function fetchValidators(): Promise<Validator[]> {
  const response = await fetch(`${API_URL}/v1/validators?limit=20`);
  if (!response.ok) throw new Error('Failed to fetch validators');
  const data = await response.json();
  return data.validators || [];
}

// Status badge component
function StatusBadge({ status }: { status: string }) {
  const statusColors: Record<string, string> = {
    completed: 'bg-green-100 text-green-800',
    pending: 'bg-yellow-100 text-yellow-800',
    computing: 'bg-blue-100 text-blue-800',
    failed: 'bg-red-100 text-red-800',
    active: 'bg-green-100 text-green-800',
    revoked: 'bg-red-100 text-red-800',
  };

  const normalizedStatus = status.toLowerCase().replace('job_status_', '').replace('seal_status_', '');
  const colorClass = statusColors[normalizedStatus] || 'bg-gray-100 text-gray-800';

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${colorClass}`}>
      {normalizedStatus.charAt(0).toUpperCase() + normalizedStatus.slice(1)}
    </span>
  );
}

// Stat card component
function StatCard({
  title,
  value,
  icon: Icon,
  change,
  changeType,
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
}) {
  const changeColors = {
    positive: 'text-green-600',
    negative: 'text-red-600',
    neutral: 'text-gray-600',
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
          {change && (
            <p className={`mt-1 text-sm ${changeColors[changeType || 'neutral']}`}>
              {change}
            </p>
          )}
        </div>
        <div className="p-3 bg-indigo-50 rounded-lg">
          <Icon className="w-6 h-6 text-indigo-600" />
        </div>
      </div>
    </div>
  );
}

// Main Dashboard component
export default function Dashboard() {
  const [searchQuery, setSearchQuery] = useState('');

  // Queries with auto-refresh
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['networkStats'],
    queryFn: fetchNetworkStats,
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  const { data: jobs, isLoading: jobsLoading } = useQuery({
    queryKey: ['recentJobs'],
    queryFn: fetchRecentJobs,
    refetchInterval: 5000,
  });

  const { data: seals, isLoading: sealsLoading } = useQuery({
    queryKey: ['recentSeals'],
    queryFn: fetchRecentSeals,
    refetchInterval: 5000,
  });

  const { data: validators, isLoading: validatorsLoading } = useQuery({
    queryKey: ['validators'],
    queryFn: fetchValidators,
    refetchInterval: 30000,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.startsWith('seal_')) {
      window.location.href = `/seals/${searchQuery}`;
    } else if (searchQuery.startsWith('job_')) {
      window.location.href = `/jobs/${searchQuery}`;
    } else if (searchQuery.startsWith('aethel1')) {
      window.location.href = `/address/${searchQuery}`;
    } else {
      window.location.href = `/search?q=${encodeURIComponent(searchQuery)}`;
    }
  };

  const truncateHash = (hash: string) => {
    if (hash.length <= 16) return hash;
    return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-indigo-600" />
              <h1 className="text-xl font-bold text-gray-900">Aethelred Explorer</h1>
            </div>

            {/* Search */}
            <form onSubmit={handleSearch} className="flex-1 max-w-lg mx-8">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by job ID, seal ID, or address..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
            </form>

            <nav className="flex items-center space-x-4">
              <a href="/jobs" className="text-gray-600 hover:text-gray-900">Jobs</a>
              <a href="/seals" className="text-gray-600 hover:text-gray-900">Seals</a>
              <a href="/validators" className="text-gray-600 hover:text-gray-900">Validators</a>
              <a href="/models" className="text-gray-600 hover:text-gray-900">Models</a>
              <a href="/devtools" className="text-indigo-600 hover:text-indigo-800 font-medium">Devtools</a>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Jobs"
            value={statsLoading ? '...' : (stats?.totalJobs || 0).toLocaleString()}
            icon={Cpu}
            change="+12% from last epoch"
            changeType="positive"
          />
          <StatCard
            title="Active Validators"
            value={statsLoading ? '...' : stats?.activeValidators || 0}
            icon={Users}
          />
          <StatCard
            title="Digital Seals"
            value={statsLoading ? '...' : (stats?.totalSeals || 0).toLocaleString()}
            icon={Shield}
            change="+8% from last epoch"
            changeType="positive"
          />
          <StatCard
            title="Avg Block Time"
            value={statsLoading ? '...' : `${stats?.averageBlockTime || 0}s`}
            icon={Clock}
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Jobs */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Recent Jobs</h2>
              <a href="/jobs" className="text-sm text-indigo-600 hover:text-indigo-700">
                View all →
              </a>
            </div>
            <div className="divide-y divide-gray-200">
              {jobsLoading ? (
                <div className="p-6 text-center text-gray-500">Loading...</div>
              ) : jobs && jobs.length > 0 ? (
                jobs.slice(0, 5).map((job) => (
                  <div key={job.id} className="px-6 py-4 hover:bg-gray-50">
                    <div className="flex items-center justify-between">
                      <div>
                        <a
                          href={`/jobs/${job.id}`}
                          className="text-sm font-medium text-indigo-600 hover:text-indigo-700"
                        >
                          {truncateHash(job.id)}
                        </a>
                        <p className="text-xs text-gray-500 mt-1">
                          {formatDate(job.createdAt)}
                        </p>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className="text-xs text-gray-500">{job.proofType}</span>
                        <StatusBadge status={job.status} />
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-6 text-center text-gray-500">No jobs found</div>
              )}
            </div>
          </div>

          {/* Recent Seals */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Recent Seals</h2>
              <a href="/seals" className="text-sm text-indigo-600 hover:text-indigo-700">
                View all →
              </a>
            </div>
            <div className="divide-y divide-gray-200">
              {sealsLoading ? (
                <div className="p-6 text-center text-gray-500">Loading...</div>
              ) : seals && seals.length > 0 ? (
                seals.slice(0, 5).map((seal) => (
                  <div key={seal.id} className="px-6 py-4 hover:bg-gray-50">
                    <div className="flex items-center justify-between">
                      <div>
                        <a
                          href={`/seals/${seal.id}`}
                          className="text-sm font-medium text-indigo-600 hover:text-indigo-700"
                        >
                          {truncateHash(seal.id)}
                        </a>
                        <p className="text-xs text-gray-500 mt-1">
                          Job: {truncateHash(seal.jobId)}
                        </p>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className="text-xs text-gray-500">
                          {seal.validatorCount} validators
                        </span>
                        <StatusBadge status={seal.status} />
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-6 text-center text-gray-500">No seals found</div>
              )}
            </div>
          </div>
        </div>

        {/* Validators Table */}
        <div className="mt-8 bg-white rounded-xl shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Active Validators</h2>
            <a href="/validators" className="text-sm text-indigo-600 hover:text-indigo-700">
              View all →
            </a>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Validator
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Address
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Voting Power
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Jobs Completed
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Uptime
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {validatorsLoading ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-4 text-center text-gray-500">
                      Loading...
                    </td>
                  </tr>
                ) : validators && validators.length > 0 ? (
                  validators.slice(0, 10).map((validator) => (
                    <tr key={validator.address} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-gray-900">
                          {validator.moniker}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <a
                          href={`/validators/${validator.address}`}
                          className="text-sm text-indigo-600 hover:text-indigo-700"
                        >
                          {truncateHash(validator.address)}
                        </a>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {validator.votingPower.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {validator.jobsCompleted.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                            <div
                              className="bg-green-500 h-2 rounded-full"
                              style={{ width: `${validator.uptime}%` }}
                            />
                          </div>
                          <span className="text-sm text-gray-500">
                            {validator.uptime.toFixed(1)}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-6 py-4 text-center text-gray-500">
                      No validators found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Network Activity Chart Placeholder */}
        <div className="mt-8 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Network Activity</h2>
          <div className="h-64 flex items-center justify-center bg-gray-50 rounded-lg">
            <div className="text-center text-gray-500">
              <Activity className="w-12 h-12 mx-auto mb-2" />
              <p>Real-time network activity chart</p>
              <p className="text-sm">(Recharts integration)</p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-500">
              © 2024 Aethelred. Sovereign AI Verification Infrastructure.
            </p>
            <div className="flex items-center space-x-4">
              <a href="https://docs.aethelred.org" className="text-sm text-gray-500 hover:text-gray-700">
                Documentation
              </a>
              <a href="https://github.com/aethelred" className="text-sm text-gray-500 hover:text-gray-700">
                GitHub
              </a>
              <a href="https://discord.gg/aethelred" className="text-sm text-gray-500 hover:text-gray-700">
                Discord
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
