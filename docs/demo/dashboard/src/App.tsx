import React, { useState, useEffect, useCallback } from 'react';

// Types
interface DemoStep {
  id: string;
  title: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  duration?: number;
  details?: string[];
}

interface Demo {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  steps: DemoStep[];
  metrics?: {
    label: string;
    value: string;
  }[];
}

// Demo configurations
const DEMOS: Demo[] = [
  {
    id: 'falcon-lion',
    name: 'Falcon-Lion',
    description: 'Cross-Border Trade Finance: UAE ↔ Singapore',
    icon: '🦅',
    color: '#3b82f6',
    steps: [
      { id: 'init-falcon', title: 'Initialize Falcon Trading (UAE)', description: 'Setting up UAE trading entity', status: 'pending' },
      { id: 'init-lion', title: 'Initialize Lion Logistics (Singapore)', description: 'Setting up Singapore logistics partner', status: 'pending' },
      { id: 'create-deal', title: 'Create Trade Deal', description: 'Electronics shipment: USD 2,500,000', status: 'pending' },
      { id: 'uae-compliance', title: 'UAE Export Compliance', description: 'TEE-enclosed regulatory verification', status: 'pending' },
      { id: 'crypto-proof', title: 'Generate Cryptographic Proof', description: 'zkML proof of compliance', status: 'pending' },
      { id: 'cross-border', title: 'Cross Sovereign Boundary', description: 'UAE → Singapore data transit', status: 'pending' },
      { id: 'sg-compliance', title: 'Singapore Import Compliance', description: 'TEE-enclosed import verification', status: 'pending' },
      { id: 'mint-lc', title: 'Mint Letter of Credit', description: 'Digital Seal creation', status: 'pending' },
      { id: 'record-chain', title: 'Record on Blockchain', description: 'Immutable audit trail', status: 'pending' },
      { id: 'complete', title: 'Demo Complete', description: 'All verifications successful', status: 'pending' },
    ],
    metrics: [
      { label: 'Deal Value', value: 'USD 2,500,000' },
      { label: 'Compliance', value: 'UAE ✓ | Singapore ✓' },
      { label: 'Audit Entries', value: '12' },
    ],
  },
  {
    id: 'helix-guard',
    name: 'Helix-Guard',
    description: 'Sovereign Drug Discovery: UAE ↔ UK',
    icon: '🧬',
    color: '#8b5cf6',
    steps: [
      { id: 'init-m42', title: 'Initialize M42 Health (UAE)', description: 'Setting up secure enclave', status: 'pending' },
      { id: 'init-az', title: 'Initialize AstraZeneca (UK)', description: 'Setting up partner enclave', status: 'pending' },
      { id: 'submit-drugs', title: 'Submit Drug Candidates', description: '3 encrypted compounds', status: 'pending' },
      { id: 'submit-targets', title: 'Submit Molecular Targets', description: 'Encrypted target proteins', status: 'pending' },
      { id: 'create-session', title: 'Create Blind Session', description: 'Multi-party computation setup', status: 'pending' },
      { id: 'm42-approve', title: 'M42 Approval', description: 'Authorized computation', status: 'pending' },
      { id: 'az-approve', title: 'AstraZeneca Approval', description: 'Authorized computation', status: 'pending' },
      { id: 'blind-compute', title: 'Blind Drug-Target Matching', description: 'TEE-enclosed computation', status: 'pending' },
      { id: 'zkml-proof', title: 'Generate zkML Proof', description: 'Computation correctness proof', status: 'pending' },
      { id: 'settlement', title: 'Royalty Settlement', description: '150,000 AETHEL distributed', status: 'pending' },
      { id: 'complete', title: 'Demo Complete', description: 'Match found: 94.7% confidence', status: 'pending' },
    ],
    metrics: [
      { label: 'Partners', value: 'M42 + AstraZeneca' },
      { label: 'Data Exposure', value: 'NONE' },
      { label: 'Best Match', value: '94.7%' },
      { label: 'Settlement', value: '150,000 AETHEL' },
    ],
  },
];

// Components
const ProgressBar: React.FC<{ progress: number; color: string }> = ({ progress, color }) => (
  <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
    <div
      className="h-full transition-all duration-500 ease-out rounded-full"
      style={{
        width: `${progress}%`,
        background: `linear-gradient(90deg, ${color}, ${color}88)`
      }}
    />
  </div>
);

const StepItem: React.FC<{ step: DemoStep; index: number }> = ({ step, index }) => {
  const statusColors = {
    pending: 'bg-gray-700',
    running: 'bg-yellow-500 animate-pulse',
    completed: 'bg-green-500',
    failed: 'bg-red-500',
  };

  const statusIcons = {
    pending: '○',
    running: '◉',
    completed: '✓',
    failed: '✗',
  };

  return (
    <div
      className={`flex items-start gap-4 p-3 rounded-lg transition-all duration-300 ${
        step.status === 'running' ? 'bg-white/5' : ''
      }`}
      style={{
        opacity: step.status === 'pending' ? 0.5 : 1,
        animationDelay: `${index * 100}ms`
      }}
    >
      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${statusColors[step.status]}`}>
        {statusIcons[step.status]}
      </div>
      <div className="flex-1">
        <h4 className="font-medium text-white">{step.title}</h4>
        <p className="text-sm text-gray-400">{step.description}</p>
        {step.details && step.status === 'completed' && (
          <div className="mt-2 space-y-1">
            {step.details.map((detail, i) => (
              <p key={i} className="text-xs text-green-400 mono">✓ {detail}</p>
            ))}
          </div>
        )}
      </div>
      {step.duration && step.status === 'completed' && (
        <span className="text-xs text-gray-500 mono">{step.duration}ms</span>
      )}
    </div>
  );
};

const DemoCard: React.FC<{
  demo: Demo;
  isActive: boolean;
  onSelect: () => void;
  progress: number;
}> = ({ demo, isActive, onSelect, progress }) => (
  <button
    onClick={onSelect}
    className={`w-full p-6 rounded-xl text-left transition-all duration-300 glass ${
      isActive ? 'ring-2 ring-purple-500 scale-[1.02]' : 'hover:bg-white/5'
    }`}
  >
    <div className="flex items-center gap-4 mb-4">
      <span className="text-4xl">{demo.icon}</span>
      <div>
        <h3 className="text-xl font-bold text-white">{demo.name}</h3>
        <p className="text-sm text-gray-400">{demo.description}</p>
      </div>
    </div>
    <ProgressBar progress={progress} color={demo.color} />
    <p className="text-right text-sm text-gray-500 mt-2">{Math.round(progress)}% complete</p>
  </button>
);

const MetricCard: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="glass rounded-lg p-4">
    <p className="text-xs text-gray-400 uppercase tracking-wider">{label}</p>
    <p className="text-lg font-bold text-white mt-1">{value}</p>
  </div>
);

// Main App
const App: React.FC = () => {
  const [selectedDemo, setSelectedDemo] = useState<string>('falcon-lion');
  const [demos, setDemos] = useState<Demo[]>(DEMOS);
  const [isRunning, setIsRunning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);

  const currentDemo = demos.find(d => d.id === selectedDemo)!;
  const progress = currentDemo.steps.filter(s => s.status === 'completed').length / currentDemo.steps.length * 100;

  const runDemo = useCallback(async () => {
    if (isRunning) return;

    setIsRunning(true);

    // Reset all steps
    setDemos(prev => prev.map(d =>
      d.id === selectedDemo
        ? { ...d, steps: d.steps.map(s => ({ ...s, status: 'pending' as const, details: undefined })) }
        : d
    ));

    const stepDetails: Record<string, string[]> = {
      'uae-compliance': ['Attestation verified: SGX Quote valid', 'Measurement: 0x7a8b...3c4d'],
      'crypto-proof': ['Proof size: 1.2 KB', 'Verification: 12ms'],
      'mint-lc': ['Seal ID: seal_falcon_' + Date.now(), 'Methods: TEE + zkML'],
      'blind-compute': ['Match: Candidate #2 ↔ BRCA1', 'Confidence: 94.7%', 'Raw data: NOT EXPOSED'],
      'zkml-proof': ['Proof size: 1.2 KB', 'Verification: 12ms'],
    };

    // Run each step
    for (let i = 0; i < currentDemo.steps.length; i++) {
      setCurrentStepIndex(i);

      // Set current step to running
      setDemos(prev => prev.map(d =>
        d.id === selectedDemo
          ? {
              ...d,
              steps: d.steps.map((s, idx) =>
                idx === i ? { ...s, status: 'running' as const } : s
              )
            }
          : d
      ));

      // Wait for step duration
      await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 400));

      // Complete the step
      setDemos(prev => prev.map(d =>
        d.id === selectedDemo
          ? {
              ...d,
              steps: d.steps.map((s, idx) =>
                idx === i
                  ? {
                      ...s,
                      status: 'completed' as const,
                      duration: Math.round(300 + Math.random() * 500),
                      details: stepDetails[s.id]
                    }
                  : s
              )
            }
          : d
      ));
    }

    setIsRunning(false);
    setCurrentStepIndex(-1);
  }, [selectedDemo, isRunning, currentDemo.steps.length]);

  const resetDemo = () => {
    setDemos(prev => prev.map(d =>
      d.id === selectedDemo
        ? { ...d, steps: d.steps.map(s => ({ ...s, status: 'pending' as const, details: undefined, duration: undefined })) }
        : d
    ));
    setCurrentStepIndex(-1);
  };

  return (
    <div className="min-h-screen p-8">
      {/* Header */}
      <header className="text-center mb-12">
        <h1 className="text-5xl font-bold mb-4">
          <span className="gradient-text">AETHELRED</span>
        </h1>
        <p className="text-xl text-gray-400">Sovereign Layer 1 for Verifiable AI</p>
        <p className="text-sm text-gray-500 mt-2">Interactive Demo Dashboard</p>
      </header>

      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Demo Selection */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-300 mb-4">Select Demo</h2>
          {demos.map(demo => (
            <DemoCard
              key={demo.id}
              demo={demo}
              isActive={selectedDemo === demo.id}
              onSelect={() => setSelectedDemo(demo.id)}
              progress={demo.id === selectedDemo ? progress : 0}
            />
          ))}
        </div>

        {/* Demo Progress */}
        <div className="lg:col-span-2">
          <div className="glass rounded-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <span className="text-4xl">{currentDemo.icon}</span>
                <div>
                  <h2 className="text-2xl font-bold text-white">{currentDemo.name}</h2>
                  <p className="text-gray-400">{currentDemo.description}</p>
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={resetDemo}
                  disabled={isRunning}
                  className="px-4 py-2 rounded-lg bg-gray-700 text-white hover:bg-gray-600 disabled:opacity-50 transition-colors"
                >
                  Reset
                </button>
                <button
                  onClick={runDemo}
                  disabled={isRunning || progress === 100}
                  className="px-6 py-2 rounded-lg bg-purple-600 text-white hover:bg-purple-500 disabled:opacity-50 transition-colors animate-pulse-glow"
                >
                  {isRunning ? 'Running...' : progress === 100 ? 'Completed' : 'Run Demo'}
                </button>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="mb-6">
              <ProgressBar progress={progress} color={currentDemo.color} />
              <p className="text-right text-sm text-gray-400 mt-2">
                {currentDemo.steps.filter(s => s.status === 'completed').length} / {currentDemo.steps.length} steps
              </p>
            </div>

            {/* Steps */}
            <div className="space-y-2 max-h-[400px] overflow-y-auto pr-2">
              {currentDemo.steps.map((step, index) => (
                <StepItem key={step.id} step={step} index={index} />
              ))}
            </div>

            {/* Metrics */}
            {currentDemo.metrics && progress === 100 && (
              <div className="mt-6 pt-6 border-t border-gray-700">
                <h3 className="text-lg font-semibold text-white mb-4">Results</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {currentDemo.metrics.map((metric, i) => (
                    <MetricCard key={i} label={metric.label} value={metric.value} />
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Key Points */}
          <div className="glass rounded-xl p-6 mt-6">
            <h3 className="text-lg font-semibold text-white mb-4">Key Takeaways</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg bg-purple-500/10 border border-purple-500/20">
                <h4 className="font-semibold text-purple-400 mb-2">🔒 Data Sovereignty</h4>
                <p className="text-sm text-gray-400">Data never leaves jurisdictional boundaries. TEE ensures isolation.</p>
              </div>
              <div className="p-4 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                <h4 className="font-semibold text-cyan-400 mb-2">✓ Cryptographic Proof</h4>
                <p className="text-sm text-gray-400">Every computation generates verifiable zkML proofs.</p>
              </div>
              <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/20">
                <h4 className="font-semibold text-green-400 mb-2">📜 Audit Trail</h4>
                <p className="text-sm text-gray-400">Immutable blockchain record of all compliance checks.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="text-center mt-12 text-gray-500 text-sm">
        <p>Aethelred MVP Demo • No Testnet Required</p>
        <p className="mt-1">docs.aethelred.ai • github.com/aethelred</p>
      </footer>
    </div>
  );
};

export default App;
