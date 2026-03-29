import React from 'react';

// Enhanced CSS-based 3D visualization
const Scene3D: React.FC = () => {
  return (
    <div className="w-full h-full bg-gradient-to-br from-slate-800/50 to-slate-700/50 flex items-center justify-center overflow-hidden relative pointer-events-none">
      {/* Gmail Logo - Static */}
      <div style={{ 
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <img 
          src="/google-gmail-svgrepo-com.svg" 
          alt="Gmail Logo"
          style={{
            width: '120px',
            height: '120px',
            filter: 'drop-shadow(0 0 25px rgba(79, 70, 229, 0.7))',
            borderRadius: '8px'
          }}
        />
      </div>

      {/* Orbiting particles */}
      {[0, 1, 2, 3].map((i) => (
        <div
          key={i}
          className="absolute w-2 h-2 rounded-full bg-blue-400"
          style={{
            animation: `orbit-3d 5s linear infinite`,
            animationDelay: `${i * 1.25}s`,
            opacity: 0.6,
            boxShadow: `0 0 8px rgba(59,130,246,0.8)`
          }}
        ></div>
      ))}

      <style>{`
        @keyframes spin3D {
          0% {
            transform: rotateX(0deg) rotateY(0deg) rotateZ(0deg);
          }
          100% {
            transform: rotateX(360deg) rotateY(360deg) rotateZ(360deg);
          }
        }

        @keyframes orbit-3d {
          0% {
            transform: rotate(0deg) translateX(100px) rotate(0deg);
          }
          100% {
            transform: rotate(360deg) translateX(100px) rotate(-360deg);
          }
        }
      `}</style>
    </div>
  );
};

export default Scene3D;
