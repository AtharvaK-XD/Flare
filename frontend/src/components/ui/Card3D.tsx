import React from 'react';

interface Card3DProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  intensity?: number;
  glare?: boolean;
}

export function Card3D({
  children,
  className = '',
  style,
  ...props
}: Card3DProps) {
  return (
    <div
      style={style}
      className={`relative ${className}`}
      {...props}
    >
      <div className="w-full h-full relative rounded-md">
        {children}
      </div>
    </div>
  );
}
