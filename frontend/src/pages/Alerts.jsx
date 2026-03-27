import { useWebSocket } from '../context/WebSocketContext';
import { ShieldAlert, AlertTriangle, Info } from 'lucide-react';

export default function Alerts() {
  const { alerts } = useWebSocket();

  const getAlertIcon = (severity) => {
    if (severity === 'High') return <ShieldAlert className="text-red-500" size={24} />;
    if (severity === 'Medium') return <AlertTriangle className="text-yellow-500" size={24} />;
    return <Info className="text-blue-500" size={24} />;
  };

  const getAlertBg = (severity) => {
    if (severity === 'High') return 'bg-red-500/10 border-red-500/20';
    if (severity === 'Medium') return 'bg-yellow-500/10 border-yellow-500/20';
    return 'bg-blue-500/10 border-blue-500/20';
  };

  return (
    <div className="space-y-6">
      <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-500">Security Alerts</h2>
      
      <div className="grid gap-4">
        {alerts.length > 0 ? alerts.map((alert, i) => (
          <div key={alert.id || i} className={`p-5 rounded-2xl border flex gap-4 items-start ${getAlertBg(alert.severity)} transition-all hover:bg-white/5`}>
            <div className="mt-1">
              {getAlertIcon(alert.severity)}
            </div>
            <div className="flex-1">
              <div className="flex justify-between items-center mb-1">
                <h4 className="font-semibold text-gray-100 text-lg">
                  {alert.severity} Severity Alert
                </h4>
                <span className="text-sm font-mono text-gray-500 tracking-tight">
                  {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'Just now'}
                </span>
              </div>
              <p className="text-gray-400 font-mono text-sm leading-relaxed">{alert.message}</p>
            </div>
            <button className="px-4 py-2 text-xs font-semibold rounded-lg bg-neutral-900 border border-white/10 hover:bg-white/10 hover:text-cyan-400 transition-colors">
               Investigate
            </button>
          </div>
        )) : (
          <div className="p-16 text-center text-gray-500 bg-neutral-900/40 rounded-2xl border border-white/5 flex flex-col items-center justify-center">
             <div className="p-4 bg-emerald-500/10 rounded-full mb-4">
                 <ShieldAlert className="text-emerald-500" size={48} />
             </div>
             <p className="text-lg">No active alerts detected. Systems are secure.</p>
          </div>
        )}
      </div>
    </div>
  );
}
