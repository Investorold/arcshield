import { Link, useLocation } from 'react-router-dom';
import { ReactNode } from 'react';

interface LayoutProps {
  children: ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();

  const navItems = [
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/scan', label: 'New Scan', icon: '🔍' },
  ];

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-800 border-r border-gray-700">
        <div className="p-4">
          <h1 className="text-2xl font-bold text-arc-purple flex items-center gap-2">
            <span className="text-3xl">🛡️</span>
            ArcShield
          </h1>
          <p className="text-gray-400 text-sm mt-1">Security Scanner</p>
        </div>

        <nav className="mt-6">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 text-sm transition-colors ${
                location.pathname === item.path
                  ? 'bg-arc-purple/20 text-arc-purple border-r-2 border-arc-purple'
                  : 'text-gray-300 hover:bg-gray-700'
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="absolute bottom-0 w-64 p-4 border-t border-gray-700">
          <p className="text-xs text-gray-500">
            ArcShield v0.1.0
          </p>
          <p className="text-xs text-gray-500">
            Multi-Agent AI Security Scanner
          </p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-8 overflow-auto">
        {children}
      </main>
    </div>
  );
}
