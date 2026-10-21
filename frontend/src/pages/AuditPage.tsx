import React, { useEffect, useState } from 'react';
import { Lock, ShieldCheck, ShieldAlert, Layers, RefreshCw } from 'lucide-react';
import { AuditChainVisualizer } from '../components/AuditChainVisualizer';
import { SimpleGuideCard, PlainEnglishBox } from '../components/SimpleGuideCard';
import { api } from '../services/api';
import { AuditEntry, AuditVerificationResult } from '../types';

interface AuditPageProps {
  initialRunId?: string;
}

export const AuditPage: React.FC<AuditPageProps> = ({ initialRunId = 'attack_badnets_5' }) => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verification, setVerification] = useState<AuditVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  const fetchAuditData = async () => {
    try {
      const data = await api.getAuditEntries(initialRunId, 25, 0);
      setEntries(data.entries);
    } catch {
      // Demo fallback
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, [initialRunId]);

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const result = await api.verifyAudit(initialRunId, false);
      setVerification(result);
    } catch (e: any) {
      setVerification({
        is_valid: false,
        message: 'Audit verification service error: ' + (e.message || 'unknown error'),
        total_entries: 0,
        broken_index: null,
        verified_at: new Date().toISOString(),
        filename: 'audit_log.jsonl',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSimulateTamper = async () => {
    setIsVerifying(true);
    try {
      const result = await api.verifyAudit(initialRunId, true);
      setVerification(result);
    } catch (e: any) {
      // Fallback
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Lock size={26} style={{ color: 'var(--cyan-400)' }} />
            <span>Cryptographic Audit Log & Chain Integrity</span>
          </h1>
          <p className="page-description">
            Immutable SHA-256 hash-chained JSON Lines ledger. Every per-sample anomaly score, weight decision, and explanation is mathematically linked (H_i = SHA-256(H_{'i-1'} || payload_i)).
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="mono-tag" style={{ background: 'rgba(6, 182, 212, 0.15)', color: 'var(--cyan-400)', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
            TARGET RUN: {initialRunId}
          </span>
        </div>
      </div>

      {/* Tab-Level Plain-English Guide */}
      <SimpleGuideCard
        title="Cryptographic Audit: What is a Tamper-Proof Audit Log?"
        summary="Think of this as an unbreakable digital wax seal (like a mini-blockchain) on every single decision PoisonLens makes. Each line of the log contains a cryptographic fingerprint (SHA-256 hash) of the previous line. If an insider or hacker tries to secretly edit past records, the seal breaks instantly."
        steps={[
          {
            step: '1',
            title: 'Chained Digital Blocks',
            description: 'Every image evaluated receives a digital receipt holding the hash of the image before it.',
          },
          {
            step: '2',
            title: 'Mathematical Guarantee',
            description: 'You cannot change a single comma in the past without invalidating all subsequent block hashes.',
          },
          {
            step: '3',
            title: 'Live Verification Button',
            description: 'Clicking "Verify Audit Log" runs the real Python cryptographic verification function across all entries.',
          },
          {
            step: '4',
            title: 'Tamper Simulation',
            description: 'Clicking "Simulate Tampering" modifies block #10 to prove that the system immediately detects forged logs.',
          },
        ]}
        takeaway="Click 'Verify Audit Log' to see a green verified chain. Then click 'Simulate Tampering' to see block #10 turn red and flag the exact broken link."
        accentColor="amber"
      />

      {/* Section Explainer */}
      <PlainEnglishBox
        question="Why does AI security need cryptographic audit logs?"
        explanation="Without cryptographic proof, a malicious actor or negligent engineer could delete evidence of an attack after the fact. Hash chaining provides mathematically undeniable proof of what happened, when, and why."
      />

      {/* Main Audit Chain Visualizer Component */}
      <AuditChainVisualizer
        entries={entries}
        verification={verification}
        onVerify={handleVerify}
        onSimulateTamper={handleSimulateTamper}
        isVerifying={isVerifying}
      />
    </div>
  );
};
