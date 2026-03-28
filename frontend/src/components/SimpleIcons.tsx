// Simple SVG icons as React components for use instead of Heroicons
import React from 'react';


export function ExclamationTriangleSVG({ title, ...props }: React.SVGProps<SVGSVGElement> & { title?: string }) {
  return (
    <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" {...props}>
      {title ? <title>{title}</title> : null}
      <path fillRule="evenodd" clipRule="evenodd" d="M8.257 3.099c.764-1.36 2.722-1.36 3.486 0l6.518 11.614c.75 1.336-.213 3.037-1.742 3.037H3.48c-1.53 0-2.492-1.7-1.742-3.037L8.257 3.1zm2.486.874a1 1 0 00-1.486 0L2.74 15.587A1 1 0 003.48 17h13.04a1 1 0 00.74-1.413L10.743 3.973zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-2a1 1 0 01-1-1V8a1 1 0 112 0v2a1 1 0 01-1 1z" fill="currentColor"/>
    </svg>
  );
}

export function TrashSVG({ title, ...props }: React.SVGProps<SVGSVGElement> & { title?: string }) {
  return (
    <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" {...props}>
      {title ? <title>{title}</title> : null}
      <path d="M6 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm3 0a1 1 0 012 0v6a1 1 0 11-2 0V8zm3-3a1 1 0 00-1-1h-1V4a2 2 0 10-4 0v1H6a1 1 0 000 2h8a1 1 0 100-2zm-5-1a1 1 0 112 0v1H8V4zm-3 3v10a2 2 0 002 2h6a2 2 0 002-2V7H5z" fill="currentColor"/>
    </svg>
  );
}
