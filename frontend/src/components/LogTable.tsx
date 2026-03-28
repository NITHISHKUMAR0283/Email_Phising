import React from 'react';

interface LogTableProps {
  logs: any[];
}

const exportJSON = (logs: any[]) => {
  const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'phishing_logs.json';
  a.click();
  URL.revokeObjectURL(url);
};

const exportCSV = (logs: any[]) => {
  if (!logs.length) return;
  const keys = Object.keys(logs[0]);
  const csv = [keys.join(',')].concat(
    logs.map(row => keys.map(k => JSON.stringify(row[k] || '')).join(','))
  ).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'phishing_logs.csv';
  a.click();
  URL.revokeObjectURL(url);
};

const LogTable: React.FC<LogTableProps> = ({ logs }) => (
  <div className="w-full mt-4">
    <div className="flex gap-2 mb-2">
      <button className="bg-blue-500 text-white px-2 py-1 rounded" onClick={() => exportJSON(logs)}>Export JSON</button>
      <button className="bg-green-500 text-white px-2 py-1 rounded" onClick={() => exportCSV(logs)}>Export CSV</button>
    </div>
    <table className="w-full text-xs border">
      <thead>
        <tr>
          <th className="border px-2">Timestamp</th>
          <th className="border px-2">Subject</th>
          <th className="border px-2">Sender</th>
          <th className="border px-2">Risk</th>
          <th className="border px-2">Heuristics</th>
        </tr>
      </thead>
      <tbody>
        {logs.map((log, i) => (
          <tr key={i}>
            <td className="border px-2">{log.timestamp}</td>
            <td className="border px-2">{log.subject}</td>
            <td className="border px-2">{log.sender}</td>
            <td className="border px-2">{log.risk_score}</td>
            <td className="border px-2">{log.heuristics?.join('; ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default LogTable;
