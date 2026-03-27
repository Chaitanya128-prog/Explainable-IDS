import { createContext, useContext, useEffect, useState } from 'react';

const WebSocketContext = createContext(null);

export const useWebSocket = () => {
    const context = useContext(WebSocketContext);
    if (!context) throw new Error("useWebSocket must be used within Provider");
    return context;
};

export const WebSocketProvider = ({ children }) => {
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [calibrationStatus, setCalibrationStatus] = useState("Calibrating...");

  useEffect(() => {
    let reconnectTimer;
    let ws;

    const connect = () => {
      // Relative path to seamlessly use Vite proxy, bypassing all CORS and mixed content blocks
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      let wsUrl = `${protocol}//${window.location.host}/ws/traffic`;
      
      // If deployed in Electron, window.location.protocol is 'file:' 
      // Bridge directly to the packaged Python background engine's port!
      if (window.location.protocol === 'file:') {
        wsUrl = `ws://127.0.0.1:8006/ws/traffic`;
      }
      
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        setIsConnected(true);
        if (reconnectTimer) clearTimeout(reconnectTimer);
      };
      
      ws.onclose = () => {
        setIsConnected(false);
        setCalibrationStatus("Reconnecting...");
        // Auto-reconnect after 3 seconds
        reconnectTimer = setTimeout(connect, 3000);
      };
      
      ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === "NEW_PACKET") {
              setPackets(prev => {
                 const newPackets = [msg.data, ...prev];
                 return newPackets.slice(0, 500); // Store up to 500 packets in memory
              });
            } else if (msg.type === "ALERT") {
              setAlerts(prev => [msg.data, ...prev]);
            } else if (msg.type === "CALIBRATION_COMPLETE") {
              setCalibrationStatus("Active & Live");
            } else if (msg.type === "ENGINE_STATE") {
              setCalibrationStatus(msg.data);
            }
        } catch (e) {
            console.error("Error parsing WS message", e);
        }
      };
    };

    connect();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ packets, alerts, isConnected, calibrationStatus }}>
      {children}
    </WebSocketContext.Provider>
  );
};
