// Distinct shape and color per node type; color is never the only cue.
export interface NodeStyle {
  shape: string;
  color: string;
  shapeName: string;
}

export const NODE_STYLES: Record<string, NodeStyle> = {
  Vulnerability: { shape: 'ellipse', color: '#b3261e', shapeName: 'circle' },
  Exploit: { shape: 'diamond', color: '#7a4b00', shapeName: 'diamond' },
  Weakness: { shape: 'hexagon', color: '#00604a', shapeName: 'hexagon' },
  Product: { shape: 'round-rectangle', color: '#1a4fa0', shapeName: 'rounded box' },
  Vendor: { shape: 'rectangle', color: '#5b2c83', shapeName: 'box' },
  Domain: { shape: 'octagon', color: '#444444', shapeName: 'octagon' },
  Author: { shape: 'triangle', color: '#8a1f5c', shapeName: 'triangle' },
};

const FALLBACK: NodeStyle = { shape: 'ellipse', color: '#333333', shapeName: 'circle' };

export const styleFor = (type: string): NodeStyle => NODE_STYLES[type] ?? FALLBACK;
