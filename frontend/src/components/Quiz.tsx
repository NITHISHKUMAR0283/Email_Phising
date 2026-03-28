
import React from 'react';

interface QuizProps {
  quiz: Array<{
    question: string;
    options: string[];
    correct: string[];
  }>;
}

const Quiz: React.FC<QuizProps> = ({ quiz }) => (
  <div className="w-full bg-gray-50 rounded shadow p-4">
    <h3 className="font-bold mb-2">Phishing Awareness Quiz</h3>
    {quiz.map((q, i) => (
      <div key={i} className="mb-4">
        <div className="mb-1">{q.question}</div>
        <ul>
          {q.options.map((opt, j) => (
            <li key={j} className="ml-4 list-disc">
              {opt}
              {q.correct.includes(opt) && (
                <span className="ml-2 text-green-600 font-semibold">(Correct)</span>
              )}
            </li>
          ))}
        </ul>
      </div>
    ))}
  </div>
);

export default Quiz;
