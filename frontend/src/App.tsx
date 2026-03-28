import React from 'react';
import DetectionForm from './components/DetectionForm';
import Quiz from './components/Quiz';
import Dashboard from './components/Dashboard';
import React, { useState } from 'react';


function App() {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [quizHistory, setQuizHistory] = useState<any[]>([]);

  // Wrap DetectionForm to collect analyses
  const handleDetection = (result: any) => {
    setAnalyses(prev => [...prev, result]);
  };

  // Wrap Quiz to collect quiz history
  const handleQuiz = (entry: any) => {
    setQuizHistory(prev => [...prev, entry]);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center py-8">
      <h1 className="text-3xl font-bold text-blue-700 mb-4">PhishGuard AI</h1>
      <p className="text-lg text-gray-700 mb-8">Offline, privacy-preserving phishing detection & awareness dashboard</p>
      <Dashboard analyses={analyses} quizHistory={quizHistory} />
      <DetectionForm onDetect={handleDetection} />
      <Quiz onQuiz={handleQuiz} />
    </div>
  );
}

export default App;
