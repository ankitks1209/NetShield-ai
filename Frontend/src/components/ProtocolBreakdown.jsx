import { useContext } from 'react';
import { useOutletContext } from 'react-router-dom';
import { TrafficContext } from '../context/traffic';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

const ProtocolBreakdown = () => {
  // Royal Upgrade: Connects to the global master switch
  const { theme } = useOutletContext() || { theme: 'dark' };
  const { packets } = useContext(TrafficContext);

  // Dynamically invert chart text based on the theme
  const textColor = theme === 'dark' ? '#9A9A97' : '#86868B';

  // Dynamically compute protocol counts from live packets
  const protocolCounts = packets.reduce((acc, pkt) => {
    const proto = String(pkt['Protocol'] || pkt['proto'] || 'UNKNOWN').toUpperCase();
    const cleanProto = ['17', 'UDP'].includes(proto) ? 'UDP'
                     : ['6', 'TCP'].includes(proto) ? 'TCP'
                     : ['1', 'ICMP'].includes(proto) ? 'ICMP' : 'Other / unknown';
    acc[cleanProto] = (acc[cleanProto] || 0) + 1;
    return acc;
  }, { TCP: 0, UDP: 0, ICMP: 0, 'Other / unknown': 0 });

  const doughnutData = {
    labels: Object.keys(protocolCounts),
    datasets: [{
      data: Object.values(protocolCounts),
      backgroundColor: ['#6366F1', '#34D399', '#FBBF24', '#F87171'],
      borderWidth: 0,
      hoverOffset: 4
    }]
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'bottom', labels: { color: textColor, font: { size: 11 } } }
    },
    cutout: '70%'
  };

  return (
    <div className="apple-card p-6 w-full h-[280px] flex flex-col">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold text-[15px] apple-text-primary">Protocol Breakdown</h3>
      </div>
      <div className="flex-grow relative flex items-center justify-center pb-2">
        {/* key={theme} forces the canvas to redraw instantly when the switch is flipped */}
        <Doughnut key={theme} data={doughnutData} options={doughnutOptions} />
      </div>
    </div>
  );
};

export default ProtocolBreakdown;
