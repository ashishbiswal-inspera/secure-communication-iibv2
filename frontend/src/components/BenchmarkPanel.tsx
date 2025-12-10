import React, { useState, useCallback } from "react";
import {
  runAllBenchmarks,
  printBenchmarkResults,
  type BenchmarkSuite,
  type BenchmarkResult,
  type BenchmarkProgress,
} from "@/lib/benchmark";

// =============================================================================
// COMPONENT STYLES (using Tailwind-like inline styles for portability)
// =============================================================================

const styles = {
  container: "p-6 max-w-6xl mx-auto",
  header: "text-2xl font-bold mb-4 flex items-center gap-2",
  button:
    "px-4 py-2 rounded font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
  buttonPrimary: "bg-blue-600 hover:bg-blue-700 text-white",
  buttonSecondary: "bg-gray-200 hover:bg-gray-300 text-gray-800",
  progressBar: "w-full bg-gray-200 rounded-full h-2 mb-4",
  progressFill: "bg-blue-600 h-2 rounded-full transition-all duration-300",
  table: "w-full border-collapse text-sm",
  th: "text-left p-2 border-b-2 border-gray-300 bg-gray-100 font-semibold",
  td: "p-2 border-b border-gray-200",
  categoryHeader: "bg-gray-50 font-bold text-gray-700",
  badge: "text-xs px-2 py-1 rounded",
  badgeFast: "bg-green-100 text-green-800",
  badgeMedium: "bg-yellow-100 text-yellow-800",
  badgeSlow: "bg-red-100 text-red-800",
  card: "bg-white rounded-lg shadow-md p-4 mb-4",
  infoText: "text-gray-600 text-sm mb-4",
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function getSpeedBadge(avgTimeMs: number): {
  label: string;
  className: string;
} {
  if (avgTimeMs < 1) {
    return { label: "Fast", className: styles.badgeFast };
  } else if (avgTimeMs < 10) {
    return { label: "Medium", className: styles.badgeMedium };
  } else {
    return { label: "Slow", className: styles.badgeSlow };
  }
}

function formatTime(ms: number): string {
  if (ms < 0.001) {
    return `${(ms * 1000000).toFixed(2)} ns`;
  } else if (ms < 1) {
    return `${(ms * 1000).toFixed(2)} μs`;
  } else if (ms < 1000) {
    return `${ms.toFixed(3)} ms`;
  } else {
    return `${(ms / 1000).toFixed(2)} s`;
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// =============================================================================
// COMPONENTS
// =============================================================================

interface ResultRowProps {
  result: BenchmarkResult;
}

const ResultRow: React.FC<ResultRowProps> = ({ result }) => {
  const badge = getSpeedBadge(result.avgTimeMs);

  return (
    <tr className="hover:bg-gray-50">
      <td className={styles.td}>{result.name}</td>
      <td className={styles.td}>
        <span className={`${styles.badge} ${badge.className}`}>
          {badge.label}
        </span>
      </td>
      <td className={`${styles.td} font-mono text-right`}>
        {formatTime(result.avgTimeMs)}
      </td>
      <td className={`${styles.td} font-mono text-right text-gray-500`}>
        {formatTime(result.minTimeMs)}
      </td>
      <td className={`${styles.td} font-mono text-right text-gray-500`}>
        {formatTime(result.maxTimeMs)}
      </td>
      <td className={`${styles.td} font-mono text-right`}>
        {result.sizeBefore !== undefined && result.sizeAfter !== undefined ? (
          <span>
            {formatBytes(result.sizeBefore)} → {formatBytes(result.sizeAfter)}
            {result.overheadPercent !== undefined && (
              <span className="text-gray-500 text-xs ml-1">
                (+{result.overheadPercent.toFixed(1)}%)
              </span>
            )}
          </span>
        ) : (
          <span className="text-gray-400">—</span>
        )}
      </td>
      <td className={`${styles.td} text-center text-gray-500`}>
        {result.iterations}
      </td>
    </tr>
  );
};

interface CategorySectionProps {
  category: string;
  results: BenchmarkResult[];
  icon: string;
}

const CategorySection: React.FC<CategorySectionProps> = ({
  category,
  results,
  icon,
}) => {
  if (results.length === 0) return null;

  return (
    <>
      <tr>
        <td colSpan={7} className={`${styles.td} ${styles.categoryHeader}`}>
          {icon} {category.toUpperCase()}
        </td>
      </tr>
      {results.map((result, idx) => (
        <ResultRow key={`${category}-${idx}`} result={result} />
      ))}
    </>
  );
};

// =============================================================================
// MAIN COMPONENT
// =============================================================================

const BenchmarkPanel: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState<BenchmarkProgress | null>(null);
  const [results, setResults] = useState<BenchmarkSuite | null>(null);

  const handleRunBenchmarks = useCallback(async () => {
    setIsRunning(true);
    setProgress(null);
    setResults(null);

    try {
      const suite = await runAllBenchmarks((p) => setProgress(p));
      setResults(suite);
      printBenchmarkResults(suite); // Also log to console
    } catch (error) {
      console.error("Benchmark failed:", error);
    } finally {
      setIsRunning(false);
      setProgress(null);
    }
  }, []);

  const handleExportJSON = useCallback(() => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `benchmark-results-${
      new Date().toISOString().split("T")[0]
    }.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [results]);

  const categories = [
    { name: "Key Generation", icon: "🔑" },
    { name: "Encryption", icon: "🔒" },
    { name: "Serialization", icon: "📄" },
    { name: "End-to-End", icon: "🔄" },
  ];

  return (
    <div className={styles.container}>
      <div className={styles.card}>
        <h1 className={styles.header}>🔐 Security Benchmarks</h1>

        <p className={styles.infoText}>
          Benchmark ECDH key exchange, AES-256-GCM encryption, and JSON
          serialization with complex nested objects (20 properties, depth 5).
        </p>

        <div className="flex gap-2 mb-4">
          <button
            onClick={handleRunBenchmarks}
            disabled={isRunning}
            className={`${styles.button} ${styles.buttonPrimary}`}
          >
            {isRunning ? "Running..." : "Run Benchmarks"}
          </button>

          {results && (
            <button
              onClick={handleExportJSON}
              className={`${styles.button} ${styles.buttonSecondary}`}
            >
              Export JSON
            </button>
          )}
        </div>

        {isRunning && progress && (
          <div className="mb-4">
            <div className={styles.progressBar}>
              <div
                className={styles.progressFill}
                style={{
                  width: `${(progress.current / progress.total) * 100}%`,
                }}
              />
            </div>
            <p className="text-sm text-gray-600">
              {progress.currentBenchmark} ({progress.current}/{progress.total})
            </p>
          </div>
        )}
      </div>

      {results && (
        <div className={styles.card}>
          <div className="mb-4 text-sm text-gray-600">
            <strong>Timestamp:</strong>{" "}
            {new Date(results.timestamp).toLocaleString()}
            <br />
            <strong>Browser:</strong> {results.browser.substring(0, 100)}...
          </div>

          <div className="overflow-x-auto">
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.th}>Benchmark</th>
                  <th className={styles.th}>Speed</th>
                  <th className={`${styles.th} text-right`}>Avg Time</th>
                  <th className={`${styles.th} text-right`}>Min</th>
                  <th className={`${styles.th} text-right`}>Max</th>
                  <th className={`${styles.th} text-right`}>Size/Overhead</th>
                  <th className={`${styles.th} text-center`}>Iters</th>
                </tr>
              </thead>
              <tbody>
                {categories.map(({ name, icon }) => (
                  <CategorySection
                    key={name}
                    category={name}
                    icon={icon}
                    results={results.results.filter((r) => r.category === name)}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* Summary Stats */}
          <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-blue-50 p-3 rounded">
              <div className="text-2xl font-bold text-blue-600">
                {results.results.length}
              </div>
              <div className="text-sm text-gray-600">Total Benchmarks</div>
            </div>
            <div className="bg-green-50 p-3 rounded">
              <div className="text-2xl font-bold text-green-600">
                {results.results.filter((r) => r.avgTimeMs < 1).length}
              </div>
              <div className="text-sm text-gray-600">Fast (&lt;1ms)</div>
            </div>
            <div className="bg-yellow-50 p-3 rounded">
              <div className="text-2xl font-bold text-yellow-600">
                {
                  results.results.filter(
                    (r) => r.avgTimeMs >= 1 && r.avgTimeMs < 10
                  ).length
                }
              </div>
              <div className="text-sm text-gray-600">Medium (1-10ms)</div>
            </div>
            <div className="bg-red-50 p-3 rounded">
              <div className="text-2xl font-bold text-red-600">
                {results.results.filter((r) => r.avgTimeMs >= 10).length}
              </div>
              <div className="text-sm text-gray-600">Slow (&gt;10ms)</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BenchmarkPanel;
