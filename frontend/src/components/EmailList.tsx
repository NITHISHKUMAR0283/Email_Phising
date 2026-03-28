import React from 'react';

interface EmailListProps {
  emails: any[];
  selected: number;
  onSelect: (idx: number) => void;
}

const EmailList: React.FC<EmailListProps> = ({ emails, selected, onSelect }) => (
  <div className="w-full">
    <h2 className="font-bold text-lg mb-2">Inbox</h2>
    <ul>
      {emails.map((email, idx) => (
        <li
          key={idx}
          className={`p-2 cursor-pointer rounded ${selected === idx ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
          onClick={() => onSelect(idx)}
        >
          <div className="font-semibold">{email.subject}</div>
          <div className="text-xs text-gray-500">{email.sender}</div>
        </li>
      ))}
    </ul>
  </div>
);

export default EmailList;
