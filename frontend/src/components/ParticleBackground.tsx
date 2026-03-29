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
    <div className="w-full h-full relative overflow-hidden">
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
