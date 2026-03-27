import { useState } from 'react';
import { useWebSocket } from '../context/WebSocketContext';
import { Search, Filter, Info, X, Shield, Globe, Monitor, AlertTriangle, CheckCircle } from 'lucide-react';

export default function LiveTraffic() {
  const { packets } = useWebSocket();
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [selectedPacket, setSelectedPacket] = useState(null);

  const filteredPackets = packets.filter(p => {
    if (filter !== 'All' && p.threat_status !== filter) return false;
    if (search && !p.src_ip.includes(search) && !p.dst_ip.includes(search)) return false;
    return true;
  });

  const getStatusColor = (status) => {
    if (status === 'Malicious') return 'bg-red-500/10 text-red-500 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.5)]';
    if (status === 'Suspicious') return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20 shadow-[0_0_15px_rgba(234,179,8,0.3)]';
    if (status === 'Calibrating') return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 drop-shadow-[0_0_8px_rgba(16,185,129,0.3)]';
  };

  const getRowGlow = (status) => {
    if (status === 'Malicious') return 'hover:bg-red-500/10 border-l-2 border-transparent hover:border-red-500';
    if (status === 'Suspicious') return 'hover:bg-yellow-500/10 border-l-2 border-transparent hover:border-yellow-500';
    return 'hover:bg-emerald-500/5 border-l-2 border-transparent hover:border-emerald-500';
  };
  
  const getDomainColor = (trust) => {
    if (trust === 'SAFE') return 'text-blue-400';
    if (trust === 'SUSPICIOUS') return 'text-yellow-400';
    return 'text-gray-300';
  };

  const getDomainIcon = (packet) => {
    if (packet.domain_sni === 'Local Network Device' || packet.country_code === 'LOCAL') return <Monitor size={14} className="text-emerald-500" />;
    if (packet.domain_trust === 'SUSPICIOUS') return <AlertTriangle size={14} className="text-yellow-500" />;
    return <Globe size={14} className={packet.domain_sni ? "text-blue-400" : "text-gray-600"} />;
  };

  const getFlagEmoji = (countryCode) => {
    if (!countryCode || countryCode === 'UNKNOWN' || countryCode === 'LOCAL') return '🌐';
    const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
  };

  return (
    <div className="space-y-6 flex flex-col h-full">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-500">Live Traffic Stream</h2>
        
        <div className="flex gap-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
            <input 
              type="text" 
              placeholder="Search IP..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-neutral-900 border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all"
            />
          </div>
          <select 
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-neutral-900 border border-white/10 rounded-lg px-4 py-2 text-sm text-gray-200 focus:outline-none focus:border-cyan-500/50 transition-all font-medium"
          >
            <option value="All">All Traffic</option>
            <option value="Normal">Normal Only</option>
            <option value="Malicious">Malicious Only</option>
            <option value="Suspicious">Suspicious Only</option>
          </select>
        </div>
      </div>

      <div className="flex-1 flex gap-6 h-[600px]">
        {/* Main Table */}
        <div className={`transition-all duration-300 bg-neutral-900/40 backdrop-blur-sm rounded-2xl border border-white/5 overflow-hidden flex flex-col ${selectedPacket ? 'w-2/3' : 'w-full'}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-neutral-900/90 backdrop-blur-md z-10 border-b border-white/5 shadow-[0_5px_15px_rgba(0,0,0,0.5)]">
                <tr className="text-gray-400 text-xs uppercase tracking-wider">
                  <th className="p-4 font-medium">Time</th>
                  <th className="p-4 font-medium">Source</th>
                  <th className="p-4 font-medium">Destination</th>
                  <th className="p-4 font-medium">Domain / App</th>
                  <th className="p-4 font-medium">Protocol</th>
                  <th className="p-4 font-medium">Geo/Location</th>
                  <th className="p-4 font-medium">Threat Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-sm">
                {filteredPackets.length > 0 ? filteredPackets.map((packet, i) => (
                  <tr 
                    key={packet.id || i} 
                    onClick={() => setSelectedPacket(packet)}
                    className={`cursor-pointer transition-all ${getRowGlow(packet.threat_status)} ${selectedPacket?.id === packet.id ? 'bg-white/10 border-l-cyan-500' : ''}`}
                  >
                    <td className="p-4 text-gray-500 font-mono text-xs whitespace-nowrap">{packet.timestamp ? new Date(packet.timestamp).toLocaleTimeString() : 'Live'}</td>
                    <td className="p-4 text-gray-300 font-mono tracking-tight">{packet.src_ip}</td>
                    <td className="p-4 text-gray-300 font-mono tracking-tight">{packet.dst_ip}</td>
                    <td className="p-4" title={`Resolved from: ${packet.dst_ip}\nGeo: ${packet.city || packet.country}`}>
                      <div className="flex items-center gap-2">
                         {getDomainIcon(packet)}
                         <span className={`font-medium truncate max-w-[150px] inline-block ${getDomainColor(packet.domain_trust)}`}>{packet.domain_sni || packet.dst_ip}</span>
                      </div>
                    </td>
                    <td className="p-4">
                       <span className="px-2 py-0.5 rounded text-xs bg-gray-800 text-cyan-400 font-mono shadow-[0_0_10px_rgba(6,182,212,0.2)]">{packet.protocol}</span>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{getFlagEmoji(packet.country_code)}</span>
                        <span className="text-gray-400 text-xs">{packet.city && packet.city !== 'Unknown' ? packet.city : packet.country}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 rounded-full border text-xs font-semibold tracking-wide ${getStatusColor(packet.threat_status)}`}>
                        {packet.threat_status}
                      </span>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan="7" className="p-12 text-center text-gray-500 flex flex-col items-center justify-center h-full">
                       <p>No traffic matching criteria</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Slide-out Deep Inspection Panel */}
        {selectedPacket && (
          <aside className="w-1/3 bg-neutral-900/60 backdrop-blur-md rounded-2xl border border-white/5 flex flex-col shadow-[0_0_30px_rgba(0,0,0,0.5)] transform transition-transform duration-300">
            <div className="p-6 border-b border-white/5 flex justify-between items-center bg-gradient-to-r from-transparent to-white/[0.02]">
              <h3 className="text-lg font-bold text-gray-200 flex items-center gap-2"><Info className="text-cyan-500"/> Deep Packet Inspection</h3>
              <button onClick={() => setSelectedPacket(null)} className="text-gray-500 hover:text-white transition-colors"><X size={20}/></button>
            </div>
            
            <div className="p-6 overflow-y-auto flex-1 space-y-6">
               <div>
                 <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Intelligence Summary</h4>
                 <div className="bg-neutral-950/80 rounded-xl p-4 border border-white/5 space-y-3 shadow-inner">
                    <div className="flex justify-between"><span className="text-gray-500">Classification</span> <span className={`font-medium ${selectedPacket.threat_status==='Malicious'?'text-red-500':(selectedPacket.threat_status==='Suspicious'?'text-yellow-500':'text-emerald-500')}`}>{selectedPacket.threat_status}</span></div>
                    {selectedPacket.attack_type && <div className="flex justify-between"><span className="text-gray-500">Attack Signature</span> <span className="text-gray-300">{selectedPacket.attack_type}</span></div>}
                    <div className="flex justify-between items-center">
                       <span className="text-gray-500">Domain Identity</span> 
                       <div className="flex items-center gap-2">
                         {selectedPacket.domain_trust === 'SAFE' && <CheckCircle size={14} className="text-blue-500"/>}
                         {selectedPacket.domain_trust === 'SUSPICIOUS' && <AlertTriangle size={14} className="text-yellow-500"/>}
                         <span className={`font-mono text-sm max-w-[150px] truncate ${getDomainColor(selectedPacket.domain_trust)}`}>{selectedPacket.domain_sni || selectedPacket.dst_ip}</span>
                       </div>
                    </div>
                    <div className="flex justify-between items-center"><span className="text-gray-500">Domain Trust Level</span> <span className={`text-xs font-bold border px-2 py-0.5 rounded tracking-wide ${selectedPacket.domain_trust==='SAFE'?'border-blue-500/50 text-blue-400 bg-blue-500/10':(selectedPacket.domain_trust==='SUSPICIOUS'?'border-yellow-500/50 text-yellow-400 bg-yellow-500/10':'border-gray-500/50 text-gray-400 bg-gray-500/10')}`}>{selectedPacket.domain_trust || 'UNKNOWN'}</span></div>
                    <div className="flex justify-between items-center"><span className="text-gray-500">Origin Geo</span> <span className="text-gray-300 flex items-center gap-1">{getFlagEmoji(selectedPacket.country_code)} {selectedPacket.city && selectedPacket.city !== 'Unknown' ? `${selectedPacket.city}, ` : ''}{selectedPacket.country}</span></div>
                 </div>
               </div>

               <div>
                 <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Network Layer (L3/L4)</h4>
                 <div className="bg-neutral-950/80 rounded-xl p-4 border border-white/5 font-mono text-xs text-gray-400 space-y-2 shadow-inner">
                    <div className="flex justify-between"><span>Source</span> <span className="text-gray-200">{selectedPacket.src_ip}:{selectedPacket.src_port}</span></div>
                    <div className="flex justify-between"><span>Destination</span> <span className="text-gray-200">{selectedPacket.dst_ip}:{selectedPacket.dst_port}</span></div>
                    <div className="flex justify-between"><span>Protocol</span> <span className="text-gray-200">{selectedPacket.protocol}</span></div>
                    <div className="flex justify-between"><span>Packet Size</span> <span className="text-gray-200">{selectedPacket.length} bytes</span></div>
                 </div>
               </div>
               
               {selectedPacket.explanation && Object.keys(selectedPacket.explanation).length > 0 && (
                 <div>
                   <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-2"><Shield size={14} className="text-purple-500"/> SHAP Explanations</h4>
                   <div className="bg-neutral-950/80 rounded-xl p-4 border border-purple-500/20 space-y-3 relative overflow-hidden shadow-inner">
                      <div className="absolute inset-0 bg-purple-500/5 pointer-events-none"></div>
                      {Object.entries(selectedPacket.explanation).slice(0, 5).map(([feature, impact], idx) => (
                        <div key={idx} className="relative z-10">
                           <div className="flex justify-between text-xs mb-1">
                             <span className="text-gray-400">{feature}</span>
                             <span className={impact > 0 ? 'text-red-400' : 'text-emerald-400'}>{impact > 0 ? '+' : ''}{impact.toFixed(4)}</span>
                           </div>
                           <div className="w-full bg-neutral-900 rounded-full h-1.5 overflow-hidden border border-white/5">
                             <div className={`h-full ${impact > 0 ? 'bg-red-500 shadow-[0_0_5px_rgba(239,68,68,0.8)]' : 'bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.8)]'}`} style={{ width: `${Math.min(Math.abs(impact)*100, 100)}%` }}></div>
                           </div>
                        </div>
                      ))}
                   </div>
                 </div>
               )}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
