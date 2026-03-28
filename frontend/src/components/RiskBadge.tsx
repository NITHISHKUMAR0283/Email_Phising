import React from 'react';

const colorMap: Record<string, string> = {
  High: 'bg-red-500',
  Medium: 'bg-yellow-500',
  Low: 'bg-green-500',
};

const RiskBadge: React.FC<{ risk: string }> = ({ risk }) => (
  <span className={`px-2 py-1 rounded text-white text-xs font-bold ${colorMap[risk] || 'bg-gray-400'}`}>
    {risk}
  </span>
);

export default RiskBadge;
