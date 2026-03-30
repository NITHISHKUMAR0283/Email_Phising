import React from 'react';

interface InputFieldProps {
  type: 'email' | 'password' | 'text';
  placeholder: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  required?: boolean;
}

const InputField: React.FC<InputFieldProps> = ({
  type,
  placeholder,
  value,
  onChange,
  required = false
}) => {
  return (
    <div className="relative group">
      <input
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        required={required}
        className="w-full px-4 py-3 bg-white/5 border border-zinc-700/50
                   text-white placeholder-zinc-500
                   rounded-lg transition-all duration-300
                   focus:outline-none focus:border-red-500 focus:bg-white/10
                   focus:shadow-[0_0_15px_rgba(220,38,38,0.3)]
                   hover:border-zinc-600/50
                   backdrop-blur-sm"
      />
      <div className="absolute inset-0 rounded-lg opacity-0 group-focus-within:opacity-100 
                      transition-opacity duration-300
                      pointer-events-none
                      shadow-[inset_0_0_20px_rgba(220,38,38,0.1)]" />
    </div>
  );
};

export default InputField;
