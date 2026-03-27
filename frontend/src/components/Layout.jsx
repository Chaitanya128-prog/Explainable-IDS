import { Outlet, Link, useLocation } from 'react-router-dom';
import { Activity, ShieldAlert, PieChart, BrainCircuit } from 'lucide-react';

export default function Layout() {
  const location = useLocation();
  
  const navItems = [
    { name: 'Dashboard', path: '/', icon: <PieChart size={20} /> },
    { name: 'Live Traffic', path: '/traffic', icon: <Activity size={20} /> },
    { name: 'Alerts', path: '/alerts', icon: <ShieldAlert size={20} /> },
    { name: 'Risk & XAI', path: '/explain', icon: <BrainCircuit size={20} /> }
  ];

  return (
    <div className="flex h-screen bg-neutral-950 text-gray-100 font-sans selection:bg-cyan-500/30">
      {/* Sidebar */}
      <div className="w-64 bg-neutral-900/50 backdrop-blur-xl border-r border-white/5 flex flex-col relative z-10">
        <div className="p-6 border-b border-white/5 flex items-center gap-3">
          <div className="relative">
             <div className="absolute inset-0 bg-cyan-400 blur-md opacity-40 rounded-full animate-pulse"></div>
             <ShieldAlert className="text-cyan-400 relative z-10" size={28} />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Sentinel.AI</h1>
        </div>
        
        <nav className="flex-1 p-4 flex flex-col gap-2 mt-4">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <Link 
                key={item.path} 
                to={item.path}
                className={`group flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 ${isActive ? 'bg-gradient-to-r from-cyan-500/10 to-transparent text-cyan-400 border-l-2 border-cyan-400' : 'text-gray-400 hover:text-gray-100 hover:bg-white/5 border-l-2 border-transparent hover:border-white/10'}`}
              >
                <div className={`transition-transform duration-300 ${isActive ? 'scale-110' : 'group-hover:scale-110'}`}>
                    {item.icon}
                </div>
                <span className="font-medium tracking-wide text-sm">{item.name}</span>
              </Link>
            )
          })}
        </nav>
        
        <div className="p-5 border-t border-white/5 text-xs text-gray-500 font-mono text-center flex flex-col gap-1 tracking-wider">
          <span>SYSTEM ONLINE</span>
          <span className="text-emerald-500 flex items-center justify-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> ALL SYSTEMS NOMINAL</span>
        </div>
      </div>
      
      {/* Main Content Area */}
      <div className="flex-1 overflow-auto relative bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-neutral-900 via-neutral-950 to-black">
        <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-[0.03]"></div>
        <main className="p-8 h-full max-w-7xl mx-auto relative z-10">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
