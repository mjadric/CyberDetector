import * as d3 from 'd3';

export interface NetworkNode {
  id: string;
  name: string;
  type: string;
  x: number;
  y: number;
  status?: string;
}

export interface NetworkLink {
  source: string;
  target: string;
  status?: string;
}

export interface NetworkData {
  nodes: NetworkNode[];
  links: NetworkLink[];
}

export function renderNetworkTopology(
  containerId: string,
  data: NetworkData,
  width: number,
  height: number
) {
  // Clear previous SVG if exists
  d3.select(`#${containerId} svg`).remove();

  // Create SVG element
  const svg = d3.select(`#${containerId}`)
    .append('svg')
    .attr('width', width)
    .attr('height', height);

  // Create links (lines)
  const linkElements = svg.selectAll('line')
    .data(data.links)
    .enter()
    .append('line')
    .attr('x1', (d) => {
      const sourceNode = data.nodes.find(n => n.id === d.source);
      return sourceNode ? sourceNode.x : 0;
    })
    .attr('y1', (d) => {
      const sourceNode = data.nodes.find(n => n.id === d.source);
      return sourceNode ? sourceNode.y : 0;
    })
    .attr('x2', (d) => {
      const targetNode = data.nodes.find(n => n.id === d.target);
      return targetNode ? targetNode.x : 0;
    })
    .attr('y2', (d) => {
      const targetNode = data.nodes.find(n => n.id === d.target);
      return targetNode ? targetNode.y : 0;
    })
    .attr('stroke', (d) => d.status === 'attack' ? '#EF4444' : '#3B82F6')
    .attr('stroke-width', (d) => d.status === 'attack' ? 3 : 1.5)
    .attr('stroke-dasharray', (d) => d.status === 'attack' ? '5,3' : null);

  // Create node groups
  const nodeGroups = svg.selectAll('g')
    .data(data.nodes)
    .enter()
    .append('g')
    .attr('transform', (d) => `translate(${d.x}, ${d.y})`);

  // Create node circles
  nodeGroups.append('circle')
    .attr('r', (d) => {
      switch (d.type) {
        case 'router': return 15;
        case 'switch': return 12;
        default: return 10;
      }
    })
    .attr('fill', (d) => {
      if (d.status === 'attack') return '#EF4444';
      switch (d.type) {
        case 'router': return '#3B82F6';
        case 'switch': return '#10B981';
        case 'server': return '#8B5CF6';
        case 'client': return '#F59E0B';
        case 'attacker': return '#EF4444';
        default: return '#94A3B8';
      }
    })
    .attr('stroke', '#1E293B')
    .attr('stroke-width', 2);

  // Create node labels
  nodeGroups.append('text')
    .attr('dy', (d) => d.type === 'attacker' ? -12 : 25)
    .attr('text-anchor', 'middle')
    .attr('fill', '#CBD5E1')
    .style('font-size', '10px')
    .text((d) => d.name);

  // Simulate attack animation
  setInterval(() => {
    svg.selectAll('line')
      .filter((d: any) => d.status === 'attack')
      .attr('stroke-dashoffset', function() {
        const currentOffset = parseFloat(d3.select(this).attr('stroke-dashoffset') || '0');
        return currentOffset - 1;
      });
  }, 100);
}
