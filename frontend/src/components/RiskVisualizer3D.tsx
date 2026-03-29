import React from 'react';

interface RiskVisualizerProps {
  risk: 'HIGH' | 'MEDIUM' | 'LOW';
  percentage: number;
}

const RiskVisualizer: React.FC<RiskVisualizerProps> = ({ risk, percentage }) => {
  const colorMap = {
    HIGH: 'from-red-500 to-red-600',
    MEDIUM: 'from-yellow-500 to-yellow-600',
    LOW: 'from-green-500 to-green-600',
  };

  const glowColor = {
    HIGH: '#ff1744',
    MEDIUM: '#ffb300',
    LOW: '#00c853',
  };

  return (
    <div className="w-full h-full bg-gradient-to-br from-slate-800/50 to-slate-700/50 flex items-center justify-center overflow-hidden relative perspective pointer-events-none">
      {/* High Risk - Spam Icon */}
      {risk === 'HIGH' && (
        <div className="relative w-20 h-20 flex items-center justify-center">
          <img 
            src="/spam.png" 
            alt="High Risk" 
            style={{
              width: '100%',
              height: '100%',
              filter: 'drop-shadow(0 0 15px rgba(255, 23, 68, 0.8))',
              animation: 'pulse 2s ease-in-out infinite'
            }}
          />
        </div>
      )}

      {/* Medium/Low Risk - 3D Orb */}
      {(risk === 'MEDIUM' || risk === 'LOW') && (
        <div className="relative w-20 h-20">
          {/* Outer glow ring 1 */}
          <div 
            className={`absolute inset-0 rounded-full border-2 ${risk === 'MEDIUM' ? 'border-yellow-500' : 'border-green-500'} opacity-50`}
            style={{
              animation: 'spinOuter 4s linear infinite, float 3s ease-in-out infinite',
              boxShadow: `0 0 20px ${glowColor[risk]}`
            }}
          ></div>

          {/* Outer glow ring 2 */}
          <div 
            className={`absolute inset-2 rounded-full border border-dashed ${risk === 'MEDIUM' ? 'border-yellow-400' : 'border-green-400'} opacity-40`}
            style={{
              animation: 'spinInner 6s linear infinite reverse, float 3s ease-in-out infinite'
            }}
          ></div>

          {/* Main 3D sphere with gradient and shadow */}
          <div 
            className={`absolute inset-0 bg-gradient-to-br ${colorMap[risk]} rounded-full shadow-2xl border-2 border-white/30`}
            style={{
              animation: 'float 3s ease-in-out infinite, pulse 2s ease-in-out infinite',
              boxShadow: `0 0 30px ${glowColor[risk]},
                         0 0 60px ${glowColor[risk]}80,
                         inset -2px -2px 10px rgba(0,0,0,0.3),
                         inset 2px 2px 10px rgba(255,255,255,0.1)`,
              transform: 'perspective(600px) rotateX(10deg) rotateY(20deg)',
            }}
          >
            {/* Inner shine effect */}
            <div className="absolute top-2 left-2 w-6 h-6 bg-white/40 rounded-full blur-sm"></div>
            
            {/* Center percentage text */}
            <div className="w-full h-full flex items-center justify-center">
              <span className="text-white font-bold text-xs drop-shadow-lg">{Math.round(percentage)}%</span>
            </div>
          </div>

          {/* Particle effects around orb */}
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className={`absolute w-1 h-1 ${risk === 'MEDIUM' ? 'bg-yellow-400' : 'bg-green-400'} rounded-full`}
              style={{
                animation: `orbit 3s linear infinite`,
                animationDelay: `${i * 0.75}s`,
                opacity: 0.6,
              }}
            ></div>
          ))}
        </div>
      )}

      <style>{`
        @keyframes float {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-8px); }
        }
        
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.8; }
        }
        
        @keyframes spinOuter {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        @keyframes spinInner {
          0% { transform: rotate(360deg); }
          100% { transform: rotate(0deg); }
        }
        
        @keyframes orbit {
          0% {
            transform: rotate(0deg) translateX(25px) rotate(0deg);
          }
          100% {
            transform: rotate(360deg) translateX(25px) rotate(-360deg);
          }
        }
      `}</style>
    </div>
  );
};

export default RiskVisualizer;
