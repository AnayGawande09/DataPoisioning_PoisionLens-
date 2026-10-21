import React, { useEffect, useState } from 'react';
import {
  Search,
  Filter,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowUpDown,
  ExternalLink,
  Lock,
} from 'lucide-react';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';
import { api } from '../services/api';
import { SampleItem, SampleDetail, SamplesResponse } from '../types';
import { SampleDrawer } from '../components/SampleDrawer';

interface SampleExplorerPageProps {
  initialRunId?: string;
}

export const SampleExplorerPage: React.FC<SampleExplorerPageProps> = ({ initialRunId = 'attack_badnets_5' }) => {
  const [samplesData, setSamplesData] = useState<SamplesResponse | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [groundTruthOnly, setGroundTruthOnly] = useState<boolean>(false);
  const [selectedSample, setSelectedSample] = useState<SampleDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchSamples = async () => {
    setLoading(true);
    try {
      const data = await api.getSamples(initialRunId, {
        limit: 50,
        decision: decisionFilter,
        search: searchQuery,
        ground_truth_only: groundTruthOnly,
      });
      setSamplesData(data);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSamples();
  }, [decisionFilter, groundTruthOnly, initialRunId]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchSamples();
  };

  const handleOpenSample = async (sampleId: number) => {
    const detail = await api.getSampleDetail(initialRunId, sampleId);
    if (detail) setSelectedSample(detail);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Search size={26} style={{ color: 'var(--cyan-400)' }} />
            <span>Suspicious Sample Explorer</span>
          </h1>
          <p className="page-description">
            Search, filter, and inspect training dynamics for all 9,800 training samples. Distinguish suspicious model trajectory predictions from known controlled-evaluation attack labels.
          </p>
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="Sample Explorer: How to Inspect Individual Images"
        summary="Think of this tab as a magnifying glass. You can search through all 9,800 training images, see why PoisonLens labeled specific images as suspicious, and click on any sample to see its 10-epoch training curve."
        steps={[
          {
            step: '1',
            title: 'Filter by Decision',
            description: 'Use the buttons below to filter: Quarantine (red, banned), Downweight (yellow, softened), or Keep (green, trusted).',
          },
          {
            step: '2',
            title: 'Controlled Ground Truth',
            description: 'Check the "Ground-Truth Poisons Only" box to see images that the test script deliberately tampered with.',
          },
          {
            step: '3',
            title: 'Click for Patient Chart',
            description: 'Click any image card to open its detailed drawer showing how the model learned this image across 10 epochs.',
          },
          {
            step: '4',
            title: 'Loss Trajectory Secret',
            description: 'Clean images learn steadily with falling loss. Poisoned backdoor images fluctuate wildly and resist normal learning.',
          },
        ]}
        takeaway="Try clicking sample #2984 (Frog labeled as Truck) to see a real poisoned backdoor sample's erratic learning curve."
        accentColor="violet"
      />

      {/* Section Explainer for Filters */}
      <PlainEnglishBox
        question="How do I find interesting images?"
        explanation="Click 'Quarantine' to see the top 5% most suspicious images caught by PoisonLens. You can also type a specific sample ID (like 2984) into the search box to jump directly to it."
      />

      {/* Filter and Search Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '14px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 14,
        }}
      >
        {/* Decision Filter Tabs */}
        <div style={{ display: 'flex', gap: 6 }}>
          {[
            { id: 'all', label: 'All Samples' },
            { id: 'quarantine', label: 'Quarantine (w=0.0)' },
            { id: 'downweight', label: 'Downweight (w=0.20)' },
            { id: 'keep', label: 'Keep (w=1.0)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setDecisionFilter(tab.id)}
              className="btn-ghost"
              style={{
                fontSize: '0.75rem',
                padding: '6px 12px',
                background: decisionFilter === tab.id ? 'rgba(6, 182, 212, 0.15)' : undefined,
                color: decisionFilter === tab.id ? 'var(--cyan-400)' : undefined,
                borderColor: decisionFilter === tab.id ? 'var(--cyan-400)' : undefined,
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search Input & Ground-Truth Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', cursor: 'pointer', color: 'var(--text-secondary)' }}>
            <input
              type="checkbox"
              checked={groundTruthOnly}
              onChange={(e) => setGroundTruthOnly(e.target.checked)}
              style={{ accentColor: 'var(--rose-400)' }}
            />
            <span>Ground-Truth Poisons Only</span>
          </label>

          <form onSubmit={handleSearchSubmit} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input
              type="text"
              placeholder="Search sample ID, reason, or hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                padding: '6px 12px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                color: '#FFF',
                fontSize: '0.75rem',
                width: 240,
                fontFamily: 'var(--font-mono)',
              }}
            />
            <button type="submit" className="btn-cyan" style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
              Search
            </button>
          </form>
        </div>
      </div>

      {/* Samples Table */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Sample ID</th>
                <th>Suspicion Score</th>
                <th>Detection Explanations</th>
                <th>Decision</th>
                <th>Weight</th>
                <th>Evaluation Label</th>
                <th>Audit Block Hash</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {samplesData?.items && samplesData.items.length > 0 ? (
                samplesData.items.map((sample) => {
                  const isQuar = sample.decision === 'quarantine';
                  const isDown = sample.decision === 'downweight';

                  return (
                    <tr
                      key={sample.sample_id}
                      onClick={() => handleOpenSample(sample.sample_id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#FFFFFF' }}>
                        #{sample.sample_id}
                      </td>

                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: isQuar ? 'var(--rose-400)' : isDown ? 'var(--amber-400)' : 'var(--emerald-400)' }}>
                        {sample.score.toFixed(3)}
                      </td>

                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {sample.reasons.slice(0, 2).map((r, i) => (
                            <span
                              key={i}
                              className="mono-tag"
                              style={{
                                background: 'rgba(255, 255, 255, 0.05)',
                                color: 'var(--text-secondary)',
                                fontSize: '0.675rem',
                              }}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </td>

                      <td>
                        <span className={`pill-decision ${sample.decision}`}>
                          {sample.decision}
                        </span>
                      </td>

                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        w={sample.sample_weight.toFixed(2)}
                      </td>

                      <td>
                        {sample.is_ground_truth_poison !== undefined && sample.is_ground_truth_poison !== null ? (
                          <span
                            className="mono-tag"
                            style={{
                              background: sample.is_ground_truth_poison ? 'var(--rose-900)' : 'rgba(255,255,255,0.05)',
                              color: sample.is_ground_truth_poison ? 'var(--rose-400)' : 'var(--text-muted)',
                              fontSize: '0.675rem',
                            }}
                          >
                            {sample.is_ground_truth_poison ? 'POISON (GT)' : 'CLEAN (GT)'}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>Unlabeled</span>
                        )}
                      </td>

                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--cyan-400)' }}>
                        {sample.entry_hash}
                      </td>

                      <td>
                        <button
                          className="btn-ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenSample(sample.sample_id);
                          }}
                          style={{ fontSize: '0.7rem', padding: '3px 8px' }}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                    No samples matched the active filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detailed Slide-over Drawer */}
      <SampleDrawer sample={selectedSample} onClose={() => setSelectedSample(null)} />
    </div>
  );
};
