import React from 'react';

const ParticleBackground: React.FC = () => {
  // Generate random particles
  const particles = Array.from({ length: 40 }, (_, i) => ({
    id: i,
    left: Math.random() * 100,
    top: Math.random() * 100,
    delay: Math.random() * 5,
    duration: 6 + Math.random() * 4,
    size: 2 + Math.random() * 8,
    opacity: 0.3 + Math.random() * 0.4,
  }));

  return (
    <div className="fixed inset-0 w-full h-full -z-10 overflow-hidden pointer-events-none bg-[#020617]">
      {/* Main gradient background */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950/30 to-slate-950"></div>
      
      {/* Animated glowing orbs */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-red-500/15 rounded-full blur-3xl animate-pulse"></div>
      <div className="absolute top-1/3 right-1/4 w-80 h-80 bg-blue-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
      <div className="absolute bottom-0 left-1/2 w-72 h-72 bg-purple-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s'}}></div>
      <div className="absolute bottom-1/4 right-0 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1.5s'}}></div>

      {/* Particle layer */}
      <div className="absolute inset-0 overflow-hidden">
        {particles.map((particle) => (
          <div
            key={particle.id}
            className="absolute rounded-full bg-cyan-400/50"
            style={{
              left: `${particle.left}%`,
              top: `${particle.top}%`,
              width: `${particle.size}px`,
              height: `${particle.size}px`,
              opacity: particle.opacity,
              animation: `float-particle ${particle.duration}s ease-in-out infinite`,
              animationDelay: `${particle.delay}s`,
              boxShadow: `0 0 10px cyan`,
              filter: 'blur(1px)',
            }}
          />
        ))}
      </div>

      {/* Grid overlay for depth */}
      <div className="absolute inset-0 opacity-[0.02]" style={{
        backgroundImage: 'linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(0deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
        backgroundSize: '50px 50px'
      }}></div>

      <style>{`
        @keyframes float-particle {
          0% {
            transform: translateY(0) translateX(0) scale(1);
            opacity: 0;
          }
          10% {
            opacity: 0.4;
          }
          50% {
            transform: translateY(-100vh) translateX(100px) scale(0.8);
            opacity: 0.3;
          }
          90% {
            opacity: 0.1;
          }
          100% {
            transform: translateY(-200vh) translateX(200px) scale(0.5);
            opacity: 0;
          }
        }
      `}</style>
    </div>
  );
};

export default ParticleBackground;
