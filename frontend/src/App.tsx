
import DetectionForm from './components/DetectionForm';
import EmailList from './components/EmailList';
import EmailDetail from './components/EmailDetail';
import HighRiskInbox from './components/HighRiskInbox';
import React, { useState } from 'react';



function App() {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [tab, setTab] = useState<'gmail' | 'manual'>('gmail');

  const handleDetection = (result: any) => {
    setAnalyses(prev => [...prev, result]);
    setSelectedIdx(analyses.length);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center py-8">
      <h1 className="text-3xl font-bold text-blue-700 mb-4">PhishGuard AI</h1>
      <p className="text-lg text-gray-700 mb-8">Gmail-integrated & manual phishing detection dashboard</p>
      <div className="flex gap-4 mb-6">
        <button
          className={`px-4 py-2 rounded font-semibold ${tab === 'gmail' ? 'bg-blue-600 text-white' : 'bg-white text-blue-700 border border-blue-600'}`}
          onClick={() => setTab('gmail')}
        >
          Gmail Inbox
        </button>
        <button
          className={`px-4 py-2 rounded font-semibold ${tab === 'manual' ? 'bg-blue-600 text-white' : 'bg-white text-blue-700 border border-blue-600'}`}
          onClick={() => setTab('manual')}
        >
          Manual Detection
        </button>
      </div>
      {tab === 'gmail' ? (
        <HighRiskInbox />
      ) : (
        <div className="flex flex-col md:flex-row gap-8 w-full max-w-6xl">
          <div className="w-full md:w-1/3">
            <EmailList emails={analyses} selected={selectedIdx} onSelect={setSelectedIdx} />
          </div>
          <div className="w-full md:w-2/3">
            <DetectionForm onDetect={handleDetection} />
            {analyses.length > 0 && analyses[selectedIdx] && (
              <EmailDetail email={analyses[selectedIdx]} />
            )}
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
