import React from 'react';

export default function Dashboard({ analyses, quizHistory }: { analyses: any[]; quizHistory: any[] }) {
  // Calculate user risk score (simple: % of quiz mistakes)
  const total = quizHistory.length;
  const mistakes = quizHistory.filter(q => q.mistake).length;
  const riskScore = total ? Math.round((mistakes / total) * 100) : 0;

  return (
    <div className="w-full max-w-xl bg-white shadow rounded p-6 mb-8">
      <h2 className="text-xl font-semibold mb-4">User Dashboard</h2>
      <div className="mb-4">
        <span className="font-bold">Cumulative User Risk Score:</span> <span className={riskScore > 50 ? 'text-red-600' : riskScore > 20 ? 'text-yellow-600' : 'text-green-600'}>{riskScore}%</span>
      </div>
      <div className="mb-2 font-bold">Recent Analyses:</div>
      <ul className="list-disc ml-6 mb-4">
        {analyses.slice(-5).map((a, i) => (
          <li key={i}>
            <span className="font-semibold">{a.risk_score}</span>: {a.reason}
          </li>
        ))}
      </ul>
      <div className="mb-2 font-bold">Quiz History:</div>
      <ul className="list-disc ml-6">
        {quizHistory.slice(-5).map((q, i) => (
          <li key={i}>
            Q{q.question_id}: {q.mistake ? <span className="text-red-600">Mistake</span> : <span className="text-green-600">Correct</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}
