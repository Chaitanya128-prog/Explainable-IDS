import { useWebSocket } from '../context/WebSocketContext';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { BrainCircuit } from 'lucide-react';

export default function Explainability() {
  const { packets } = useWebSocket();
  
  // Find the latest malicious packet that has an explanation
  const maliciousPackets = packets.filter(p => (p.threat_status === 'Malicious' || p.threat_status === 'Suspicious') && p.explanation);
  const latestThreat = maliciousPackets.length > 0 ? maliciousPackets[0] : null;

  const shapData = latestThreat && latestThreat.explanation ? 
    Object.entries(latestThreat.explanation)
      .slice(0, 5) // Top 5 features
      .map(([name, value]) => ({ 
         name: name.replace('_', ' '), 
         value: Math.abs(value), // Absolute for bar height
         actualValue: value
      })) 
  : [];

  return (
    <div className="space-y-6 flex flex-col h-full">
      <div className="flex justify-between items-center">
         <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-100 to-gray-500">AI Explainability (SHAP)</h2>
      </div>

      {!latestThreat ? (
        <div className="flex-1 bg-neutral-900/40 backdrop-blur-sm rounded-2xl border border-white/5 flex flex-col justify-center items-center text-gray-500 p-12">
            <BrainCircuit className="opacity-20 mb-4" size={64} />
            <p className="text-lg">Awaiting threats for XAI decision breakdown...</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 shadow-2xl">
                <h3 className="text-lg font-medium text-gray-200 mb-4 border-b border-white/5 pb-3 flex items-center gap-2">
                   <BrainCircuit size={20} className="text-cyan-400"/> Threat Context
                </h3>
                
                <div className="space-y-5 font-mono text-sm mt-4">
                    <div>
                        <span className="text-gray-500 block mb-1 uppercase text-xs">Classification</span>
                        <span className={`font-bold px-3 py-1 rounded-md ${latestThreat.threat_status === 'Malicious' ? 'bg-red-500/10 text-red-500 border border-red-500/20' : 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20'}`}>
                           {latestThreat.threat_status}
                        </span>
                    </div>
                    <div>
                        <span className="text-gray-500 block mb-1 uppercase text-xs">Attack Signature</span>
                        <span className="text-gray-200">{latestThreat.attack_type || 'Unknown Anomaly Silhouette'}</span>
                    </div>
                    <div>
                        <span className="text-gray-500 block mb-1 uppercase text-xs">Source Vector</span>
                        <span className="text-cyan-400">{latestThreat.src_ip} <span className="text-gray-600">:{latestThreat.src_port}</span></span>
                    </div>
                    <div>
                        <span className="text-gray-500 block mb-1 uppercase text-xs">Target Vector</span>
                        <span className="text-blue-400">{latestThreat.dst_ip} <span className="text-gray-600">:{latestThreat.dst_port}</span></span>
                    </div>
                    <div>
                        <span className="text-gray-500 block mb-1 uppercase text-xs">Protocol Payload</span>
                        <span className="text-gray-200">{latestThreat.protocol} / <span className="text-emerald-400">{latestThreat.length} bytes</span></span>
                    </div>
                </div>
            </div>

            <div className="lg:col-span-2 bg-neutral-900/40 backdrop-blur-sm p-6 rounded-2xl border border-white/5 min-h-[400px]">
                <h3 className="text-xl font-medium text-gray-200 mb-2">Feature Importance Analysis</h3>
                <p className="text-gray-500 text-sm mb-8 max-w-2xl leading-relaxed">Top network features that influenced the AI isolation model. Longer bars indicate that the specific feature severely digressed from the learned baseline calibration.</p>
                
                <div className="h-[350px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart layout="vertical" data={shapData} margin={{ top: 5, right: 30, left: 60, bottom: 5 }}>
                            <XAxis type="number" stroke="#666" tick={{fill: '#888'}} axisLine={false} tickLine={false} />
                            <YAxis dataKey="name" type="category" stroke="#999" width={110} tick={{fill: '#e5e5e5', fontSize: 13}} axisLine={false} tickLine={false} />
                            <Tooltip 
                                cursor={{fill: 'rgba(255,255,255,0.05)'}}
                                contentStyle={{ backgroundColor: '#171717', borderColor: '#333', borderRadius: '12px', padding: '12px' }}
                                itemStyle={{ color: '#ef4444', fontWeight: 600 }}
                                formatter={(value, name, props) => {
                                    return [props.payload.actualValue.toFixed(4), "SHAP Weight"]
                                }}
                            />
                            <Bar dataKey="value" fill="url(#colorShap)" radius={[0, 4, 4, 0]} barSize={24} />
                            <defs>
                              <linearGradient id="colorShap" x1="0" y1="0" x2="1" y2="0">
                                <stop offset="0%" stopColor="#b91c1c" stopOpacity={0.8}/>
                                <stop offset="100%" stopColor="#ef4444" stopOpacity={1}/>
                              </linearGradient>
                            </defs>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>
        </div>
      )}
    </div>
  );
}
