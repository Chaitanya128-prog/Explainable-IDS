import { useWebSocket } from '../context/WebSocketContext';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Activity, ShieldAlert, Cpu, Wifi, Globe, MapPin } from 'lucide-react';

export default function Dashboard() {
  const { packets, alerts, isConnected, calibrationStatus } = useWebSocket();
  
  const totalPackets = packets.length;
  const recentAlerts = alerts.length;
  const threatCount = packets.filter(p => ['Malicious', 'Suspicious'].includes(p.threat_status)).length;
  
  // Dynamic Pie Data
  const protocols = packets.reduce((acc, p) => {
    acc[p.protocol] = (acc[p.protocol] || 0) + 1;
    return acc;
  }, {});
  
  const pieData = Object.entries(protocols).map(([name, value]) => ({ name, value }));
  const COLORS = ['#0891b2', '#0ea5e9', '#3b82f6', '#6366f1', '#a855f7'];

  // Very simplified time series for line chart (Group by exact timestamp length for simplicity in UI)
  const timeSeries = packets.slice(0, 50).reverse().map((p, index) => ({
      time: index,
      size: p.length,
      isThreat: p.threat_status !== 'Normal' ? 10 : 0
  }));

  // Dynamically compute global metrics
  const domainCounts = {};
  const countryCounts = {};
  
  packets.forEach(p => {
     if (p.domain_sni && p.domain_sni !== 'Cleartext HTTP') {
       domainCounts[p.domain_sni] = (domainCounts[p.domain_sni] || 0) + 1;
     }
     if (p.country_code && p.country_code !== 'UNKNOWN' && p.country_code !== 'LOCAL') {
       countryCounts[p.country_code] = (countryCounts[p.country_code] || 0) + 1;
     }
  });

  const topDomains = Object.entries(domainCounts)
    .sort((a,b) => b[1] - a[1]).slice(0, 5)
    .map(([domain, count]) => ({domain, count}));
    
  const topCountries = Object.entries(countryCounts)
    .sort((a,b) => b[1] - a[1]).slice(0, 5)
    .map(([code, count]) => ({code, count}));

  const getFlagEmoji = (countryCode) => {
    if (!countryCode || countryCode === 'UNKNOWN' || countryCode === 'LOCAL') return '🌐';
    const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
  };

  const handleToggleEngine = async () => {
    try {
      let apiUrl = '/api/engine/toggle';
      if (window.location.protocol === 'file:') {
        apiUrl = 'http://127.0.0.1:8006/api/engine/toggle';
      }
      await fetch(apiUrl, { method: 'POST' });
    } catch (e) {
      console.error("Failed to toggle engine", e);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
         <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-500">Security Overview</h2>
         <div className="flex items-center gap-4">
           {isConnected && (
             <button 
               onClick={handleToggleEngine}
               className={`flex items-center gap-2 px-4 py-2 rounded-full font-semibold text-sm transition-all shadow-lg ${calibrationStatus === 'Paused' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 hover:scale-105 active:scale-95'}`}
             >
               {calibrationStatus === 'Paused' ? '▶ Resume Engine' : '■ Pause Engine'}
             </button>
           )}
           <div className="flex items-center gap-3 bg-neutral-900/80 px-4 py-2 rounded-full border border-white/5 shadow-inner">
             <div className="relative flex h-3 w-3">
               {isConnected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
               <span className={`relative inline-flex rounded-full h-3 w-3 ${isConnected ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
             </div>
             <span className="text-sm font-medium text-gray-300 font-mono">
                {isConnected ? `Engine: ${calibrationStatus}` : 'Disconnected'}
             </span>
           </div>
         </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
          <div className="flex justify-between items-start relative z-10">
            <div>
              <p className="text-gray-400 font-medium text-sm tracking-wide">TOTAL PACKETS (MEM)</p>
              <h3 className="text-4xl font-bold text-gray-100 mt-2">{totalPackets}</h3>
            </div>
            <div className="p-3 bg-cyan-500/10 rounded-xl text-cyan-400"><Activity size={24} /></div>
          </div>
        </div>

        <div className="bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-red-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
          <div className="flex justify-between items-start relative z-10">
            <div>
              <p className="text-gray-400 font-medium text-sm tracking-wide">THREATS DETECTED</p>
              <h3 className="text-4xl font-bold text-red-400 mt-2">{threatCount}</h3>
            </div>
            <div className="p-3 bg-red-500/10 rounded-xl text-red-400"><ShieldAlert size={24} /></div>
          </div>
        </div>

        <div className="bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-purple-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
          <div className="flex justify-between items-start relative z-10">
            <div>
              <p className="text-gray-400 font-medium text-sm tracking-wide">ACTIVE ALERTS</p>
              <h3 className="text-4xl font-bold text-purple-400 mt-2">{recentAlerts}</h3>
            </div>
            <div className="p-3 bg-purple-500/10 rounded-xl text-purple-400"><Cpu size={24} /></div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
         <div className="lg:col-span-2 bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 min-h-[400px]">
             <h3 className="text-lg font-medium text-gray-200 mb-6 flex items-center gap-2"><Wifi size={18} className="text-cyan-500"/> Traffic Pulse (Packet Size)</h3>
             <div className="h-[300px]">
                {timeSeries.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={timeSeries}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                      <XAxis dataKey="time" stroke="#666" tick={false} />
                      <YAxis stroke="#666" />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#171717', borderColor: '#333', borderRadius: '8px' }}
                        itemStyle={{ color: '#e5e5e5' }}
                      />
                      <Line type="monotone" dataKey="size" stroke="#06b6d4" strokeWidth={3} dot={false} activeDot={{ r: 8 }} />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-gray-500">Awaiting traffic data...</div>
                )}
             </div>
         </div>

         <div className="bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 min-h-[400px]">
            <h3 className="text-lg font-medium text-gray-200 mb-6">Protocol Distribution</h3>
            <div className="h-[300px]">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip 
                       contentStyle={{ backgroundColor: '#171717', borderColor: '#333', borderRadius: '8px' }}
                       itemStyle={{ color: '#e5e5e5' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">No protocol data</div>
              )}
            </div>
         </div>
      </div>

      {/* Top Intelligence Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
         {/* Top Domains Card */}
         <div className="bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 min-h-[300px]">
             <h3 className="text-lg font-medium text-gray-200 mb-6 flex items-center gap-2"><Globe size={18} className="text-purple-500"/> Top Target Domains</h3>
             <div className="space-y-4">
               {topDomains.length > 0 ? topDomains.map((d, i) => (
                 <div key={i} className="flex justify-between items-center bg-neutral-950/50 p-3 rounded-lg border border-white/5 hover:border-purple-500/30 transition-colors">
                   <div className="flex items-center gap-3">
                      <div className="w-6 h-6 rounded bg-purple-500/10 text-purple-400 flex flex-col items-center justify-center text-xs font-bold">{i+1}</div>
                      <span className="text-gray-300 font-mono text-sm max-w-[200px] truncate">{d.domain}</span>
                   </div>
                   <span className="text-gray-500 text-sm font-semibold">{d.count} hits</span>
                 </div>
               )) : (
                 <div className="text-gray-500 flex justify-center items-center h-40">Awaiting domain intelligence...</div>
               )}
             </div>
         </div>
         {/* Top Countries Card */}
         <div className="bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 min-h-[300px]">
             <h3 className="text-lg font-medium text-gray-200 mb-6 flex items-center gap-2"><MapPin size={18} className="text-emerald-500"/> Global Threat Origins</h3>
             <div className="space-y-4">
               {topCountries.length > 0 ? topCountries.map((c, i) => (
                 <div key={i} className="flex justify-between items-center bg-neutral-950/50 p-3 rounded-lg border border-white/5 hover:border-emerald-500/30 transition-colors">
                   <div className="flex items-center gap-3">
                      <span className="text-2xl drop-shadow-lg">{getFlagEmoji(c.code)}</span>
                      <span className="text-gray-300 font-mono text-sm">{c.code}</span>
                   </div>
                   <span className="text-gray-500 text-sm font-semibold">{c.count} packets</span>
                 </div>
               )) : (
                 <div className="text-gray-500 flex justify-center items-center h-40">Awaiting geolocation data...</div>
               )}
             </div>
         </div>
      </div>
    </div>
  );
}
