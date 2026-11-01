import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { useAuth } from './auth';
import { TrafficContext } from './traffic';
import { apiFetch, socketURL } from '../services/api';

const empty = key => ({ key, packets: [], columns: [], chartData: [], status: 'Connecting…', anomalies: [],
  stats: { totalScanned: 0, totalDeviations: 0, riskScore: 0 }, error: null });
const sourceLabels = { running: 'Replay active', telemetry_only: 'Live telemetry only — classification unavailable',
  completed: 'Replay complete', disabled: 'Source disabled', starting: 'Starting source…',
  unavailable: 'Source unavailable', degraded: 'Detection degraded', stopped: 'Source stopped',
  stale: 'Zeek sensor data is stale', clock_skew: 'Zeek sensor clock is ahead' };

export const TrafficProvider = ({ children }) => {
  const { token, verified } = useAuth();
  const [selectedDataset, setSelectedDataset] = useState('cicids2017');
  const [state, setState] = useState(() => empty(''));
  const key = token && verified ? `${token}:${selectedDataset}` : '';
  const current = state.key === key && key ? state : empty(key);

  useEffect(() => {
    if (!key) return;
    let cancelled = false;
    let socket;
    let reconnectTimer;
    let retryMs = 1000;
    let polling = false;
    let lastSample;
    const controller = new AbortController();
    const update = change => {
      if (!cancelled) setState(previous => change(previous.key === key ? previous : empty(key)));
    };
    const sync = async () => {
      if (polling) return;
      polling = true;
      try {
        const [statsResponse, alertsResponse] = await Promise.all([
          apiFetch('/api/network/stats', { signal: controller.signal }),
          apiFetch('/api/alerts', { signal: controller.signal }),
        ]);
        const [stats, alerts] = await Promise.all([statsResponse.json(), alertsResponse.json()]);
        const now = Date.now();
        const count = stats.sources?.[selectedDataset]?.processed ?? 0;
        const rate = lastSample ? Math.max(0, (count - lastSample.count) / ((now - lastSample.time) / 1000)) : 0;
        lastSample = { count, time: now };
        update(previous => ({ ...previous, stats, anomalies: alerts.alerts, error: null,
          chartData: [...previous.chartData, Number(rate.toFixed(2))].slice(-30) }));
      } catch (error) {
        if (error.name !== 'AbortError') update(previous => ({ ...previous, error: error.message }));
      } finally {
        polling = false;
      }
    };
    const connect = () => {
      if (cancelled) return;
      socket = new WebSocket(socketURL(selectedDataset));
      socket.onopen = () => {
        retryMs = 1000;
        socket.send(JSON.stringify({ type: 'authenticate', token }));
      };
      socket.onmessage = event => {
        let message;
        try { message = JSON.parse(event.data); } catch { return; }
        if (message.type === 'resync_required') { sync(); return; }
        if (message.type === 'source_status') {
          update(previous => ({ ...previous, status: message.status === 'waiting_for_log' ? 'Waiting for Zeek log' : sourceLabels[message.status] || 'Unknown source state',
            error: message.error || (message.malformed_lines ? `${message.malformed_lines} malformed Zeek lines skipped; inspect sensor health` : null) }));
          return;
        }
        if (message.type !== 'packet') return;
        update(previous => ({
          ...previous, packets: [message, ...previous.packets].slice(0, 50),
          status: message.analysis_status === 'analyzed' ? 'Replay active' : 'Detection unavailable',
          columns: Object.keys(message).slice(0, 4),
          error: message.error || null,
          anomalies: message.incident && !message.simulated
            ? [message.incident, ...previous.anomalies.filter(item => item.id !== message.incident.id)].slice(0, 100)
            : previous.anomalies,
        }));
        if (message.incident && !message.simulated) {
          toast.error(`${message.incident.severity}: ${message.incident.type}`, { id: message.incident.id });
        }
      };
      socket.onerror = () => update(previous => ({ ...previous, status: 'Connection error' }));
      socket.onclose = event => {
        if (cancelled) return;
        update(previous => ({ ...previous, status: event.code === 1008 ? 'Stream access denied' : 'Disconnected — reconnecting…' }));
        if (event.code !== 1008) {
          reconnectTimer = setTimeout(connect, retryMs);
          retryMs = Math.min(retryMs * 2, 15000);
        }
      };
    };
    sync();
    connect();
    const interval = setInterval(sync, 5000);
    return () => {
      cancelled = true;
      controller.abort();
      clearInterval(interval);
      clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [key, selectedDataset, token]);

  const setAnomalies = value => setState(previous => ({ ...previous,
    anomalies: typeof value === 'function' ? value(previous.anomalies) : value }));
  return <TrafficContext.Provider value={{ ...current, selectedDataset, setSelectedDataset,
    anomalyCount: current.anomalies.length, setAnomalies }}>
    {children}
  </TrafficContext.Provider>;
};
export default TrafficProvider;
