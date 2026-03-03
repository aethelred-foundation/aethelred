/**
 * Aethelred Dashboard - Validators Page
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, RefreshCw, Users, Cpu, Activity, Award, Shield } from 'lucide-react';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://api.mainnet.aethelred.org';

interface Validator {
  address: string;
  moniker: string;
  votingPower: number;
  commission: number;
  jobsCompleted: number;
  jobsFailed: number;
  averageLatency: number;
  uptime: number;
  reputationScore: number;
  totalRewards: string;
  slashingEvents: number;
  teePlatforms: string[];
  zkmlSupported: boolean;
  maxModelSize: number;
  gpuMemory: number;
}

async function fetchValidators(): Promise<{ validators: Validator[]; total: number }> {
  const response = await fetch(`${API_URL}/v1/validators?limit=50`);
  if (!response.ok) throw new Error('Failed to fetch validators');
  return response.json();
}

function CapabilityBadge({ platform }: { platform: string }) {
  const platformColors: Record<string, string> = {
    'INTEL_SGX': 'bg-blue-100 text-blue-800',
    'AMD_SEV': 'bg-red-100 text-red-800',
    'AWS_NITRO': 'bg-orange-100 text-orange-800',
    'ARM_TRUSTZONE': 'bg-green-100 text-green-800',
  };

  const displayName = platform.replace('TEE_PLATFORM_', '').replace(/_/g, ' ');
  const color = platformColors[platform.replace('TEE_PLATFORM_', '')] || 'bg-gray-100 text-gray-800';

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${color}`}>
      {displayName}
    </span>
  );
}

export default function ValidatorsPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'votingPower' | 'uptime' | 'jobs'>('votingPower');

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['validators'],
    queryFn: fetchValidators,
    refetchInterval: 30000,
  });

  const truncateAddress = (addr: string) => {
    if (addr.length <= 20) return addr;
    return `${addr.slice(0, 10)}...${addr.slice(-10)}`;
  };

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num);
  };

  const filteredValidators = data?.validators?.filter(v =>
    !searchQuery ||
    v.moniker.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.address.toLowerCase().includes(searchQuery.toLowerCase())
  ).sort((a, b) => {
    switch (sortBy) {
      case 'votingPower': return b.votingPower - a.votingPower;
      case 'uptime': return b.uptime - a.uptime;
      case 'jobs': return b.jobsCompleted - a.jobsCompleted;
      default: return 0;
    }
  }) || [];

  const totalVotingPower = data?.validators?.reduce((sum, v) => sum + v.votingPower, 0) || 0;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-indigo-600 hover:text-indigo-700">
                ← Back
              </Link>
              <h1 className="text-xl font-bold text-gray-900">Validators</h1>
            </div>
            <button
              onClick={() => refetch()}
              className="inline-flex items-center px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <Users className="w-8 h-8 text-indigo-600" />
              <div>
                <p className="text-sm text-gray-500">Active Validators</p>
                <p className="text-2xl font-bold">{data?.total || 0}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <Activity className="w-8 h-8 text-green-600" />
              <div>
                <p className="text-sm text-gray-500">Total Voting Power</p>
                <p className="text-2xl font-bold">{formatNumber(totalVotingPower)}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <Cpu className="w-8 h-8 text-blue-600" />
              <div>
                <p className="text-sm text-gray-500">Total Jobs</p>
                <p className="text-2xl font-bold">
                  {formatNumber(data?.validators?.reduce((sum, v) => sum + v.jobsCompleted, 0) || 0)}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-purple-600" />
              <div>
                <p className="text-sm text-gray-500">TEE Validators</p>
                <p className="text-2xl font-bold">
                  {data?.validators?.filter(v => v.teePlatforms.length > 0).length || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4 mb-6">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex-1 min-w-64">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by moniker or address..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-500">Sort by:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              >
                <option value="votingPower">Voting Power</option>
                <option value="uptime">Uptime</option>
                <option value="jobs">Jobs Completed</option>
              </select>
            </div>
          </div>
        </div>

        {/* Validators List */}
        <div className="space-y-4">
          {isLoading ? (
            <div className="text-center py-12 text-gray-500">Loading validators...</div>
          ) : filteredValidators.length > 0 ? (
            filteredValidators.map((validator, index) => (
              <Link
                key={validator.address}
                href={`/validators/${validator.address}`}
                className="block bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-4">
                    <div className="flex items-center justify-center w-10 h-10 bg-indigo-100 rounded-full text-indigo-600 font-bold">
                      {index + 1}
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">{validator.moniker}</h3>
                      <p className="text-sm text-gray-500 font-mono">{truncateAddress(validator.address)}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {validator.teePlatforms.map(platform => (
                      <CapabilityBadge key={platform} platform={platform} />
                    ))}
                    {validator.zkmlSupported && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-100 text-purple-800">
                        zkML
                      </span>
                    )}
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div>
                    <p className="text-sm text-gray-500">Voting Power</p>
                    <p className="text-lg font-semibold">{formatNumber(validator.votingPower)}</p>
                    <p className="text-xs text-gray-400">
                      {((validator.votingPower / totalVotingPower) * 100).toFixed(2)}%
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Jobs Completed</p>
                    <p className="text-lg font-semibold">{formatNumber(validator.jobsCompleted)}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Uptime</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-green-500 h-2 rounded-full"
                          style={{ width: `${validator.uptime}%` }}
                        />
                      </div>
                      <span className="text-sm font-semibold">{validator.uptime.toFixed(1)}%</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Avg Latency</p>
                    <p className="text-lg font-semibold">{validator.averageLatency}ms</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Reputation</p>
                    <div className="flex items-center gap-1">
                      <Award className="w-4 h-4 text-yellow-500" />
                      <span className="text-lg font-semibold">{validator.reputationScore.toFixed(1)}</span>
                    </div>
                  </div>
                </div>

                {validator.slashingEvents > 0 && (
                  <div className="mt-3 p-2 bg-red-50 rounded-lg">
                    <p className="text-sm text-red-600">
                      ⚠️ {validator.slashingEvents} slashing event{validator.slashingEvents > 1 ? 's' : ''}
                    </p>
                  </div>
                )}
              </Link>
            ))
          ) : (
            <div className="text-center py-12 text-gray-500">No validators found</div>
          )}
        </div>
      </main>
    </div>
  );
}
