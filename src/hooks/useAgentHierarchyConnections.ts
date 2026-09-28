import { useState, useEffect, useCallback, useMemo, RefObject, MutableRefObject } from 'react';
import { SpecialistAgent } from '../types';

export type EdgeType = 'top' | 'bottom' | 'left' | 'right';

export interface SnapPoint {
  x: number;
  y: number;
  edge: EdgeType;
}

export interface CardEdges {
  top: SnapPoint;
  bottom: SnapPoint;
  left: SnapPoint;
  right: SnapPoint;
}

export interface CardGeometry {
  index: number;
  agentId: string;
  left: number;
  top: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
  centerX: number;
  centerY: number;
  row: number;
  col: number;
  edges: CardEdges;
}

export interface PipelineLinkDefinition {
  from: number;
  to: number;
  label?: string;
}

export interface DynamicPipelineConnection {
  id: string;
  fromIndex: number;
  toIndex: number;
  fromAgent?: SpecialistAgent;
  toAgent?: SpecialistAgent;
  label?: string;
  fromPoint: SnapPoint;
  toPoint: SnapPoint;
  path: string;
  midPoint: { x: number; y: number };
  arrowPoints: string;
  isSameRow: boolean;
  isAdjacent: boolean;
  isActive: boolean;
}

export interface DynamicCommandConnection {
  agentId: string;
  agentIndex: number;
  agent?: SpecialistAgent;
  busPoint: { x: number; y: number };
  cardSnapPoint: SnapPoint;
  busSegmentPath: string;
  dropPath: string;
  arrowPoints: string;
  tierColor: string;
  isActive: boolean;
  isSelected: boolean;
  row: number;
  busY: number;
}

export interface RowBusGeometry {
  row: number;
  busY: number;
  firstX: number;
  lastX: number;
  minY: number;
  maxY: number;
  cardCount: number;
  anchors: CardGeometry[];
}

export interface UseAgentHierarchyConnectionsOptions {
  gridViewMode: 'panoramic' | 'matrix';
  flowMode: 'all' | 'command' | 'pipeline';
  selectedAgentId?: string | null;
  pipelineLinks?: PipelineLinkDefinition[];
}

export interface UseAgentHierarchyConnectionsReturn {
  containerDimensions: { width: number; height: number };
  cardGeometries: CardGeometry[];
  rowBuses: RowBusGeometry[];
  stemX: number;
  masterBusY: number;
  commandConnections: DynamicCommandConnection[];
  pipelineConnections: DynamicPipelineConnection[];
  recalculate: () => void;
  findNearestEdge: (cardIndex: number, target: { x: number; y: number } | CardGeometry) => SnapPoint;
}

/**
 * Calculates Euclidean distance between two 2D points.
 */
function getDistance(p1: { x: number; y: number }, p2: { x: number; y: number }): number {
  return Math.hypot(p1.x - p2.x, p1.y - p2.y);
}

/**
 * Given two 2D points on card edges, generates a smooth SVG path snapping to the edges.
 */
function createEdgeSnappedPath(
  from: SnapPoint,
  to: SnapPoint,
  isSameRow: boolean,
  hasIntervening: boolean
): { path: string; midPoint: { x: number; y: number }; arrowPoints: string } {
  // Scenario A: Same row with intervening cards -> Arched bridge over top edges
  if (isSameRow && hasIntervening) {
    const cardTop = Math.min(from.y, to.y);
    const apexY = Math.max(6, cardTop - 18);
    const midX = (from.x + to.x) / 2;
    const path = `M ${from.x} ${from.y} Q ${midX} ${apexY} ${to.x} ${to.y}`;
    const arrowPoints = `${midX - 3},${apexY - 3} ${midX + 3},${apexY - 3} ${midX},${apexY + 1}`;
    return { path, midPoint: { x: midX, y: apexY }, arrowPoints };
  }

  // Scenario B: Adjacent cards horizontally (Right edge to Left edge)
  if (from.edge === 'right' && to.edge === 'left') {
    const midX = (from.x + to.x) / 2;
    const midY = (from.y + to.y) / 2;
    const path = `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`;
    const arrowPoints = `${to.x - 5},${to.y - 3} ${to.x - 5},${to.y + 3} ${to.x},${to.y}`;
    return { path, midPoint: { x: midX, y: midY }, arrowPoints };
  }

  // Scenario C: Left edge to Right edge (reverse horizontal)
  if (from.edge === 'left' && to.edge === 'right') {
    const midX = (from.x + to.x) / 2;
    const midY = (from.y + to.y) / 2;
    const path = `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`;
    const arrowPoints = `${to.x + 5},${to.y - 3} ${to.x + 5},${to.y + 3} ${to.x},${to.y}`;
    return { path, midPoint: { x: midX, y: midY }, arrowPoints };
  }

  // Scenario D: Vertical cascade (Bottom edge to Top edge across rows)
  if (from.edge === 'bottom' && to.edge === 'top') {
    const midY = (from.y + to.y) / 2;
    const path = `M ${from.x} ${from.y} C ${from.x} ${midY}, ${to.x} ${midY}, ${to.x} ${to.y}`;
    const arrowPoints = `${to.x - 3.5},${to.y - 5} ${to.x + 3.5},${to.y - 5} ${to.x},${to.y}`;
    return { path, midPoint: { x: (from.x + to.x) / 2, y: midY }, arrowPoints };
  }

  // Scenario E: Top edge to Bottom edge
  if (from.edge === 'top' && to.edge === 'bottom') {
    const midY = (from.y + to.y) / 2;
    const path = `M ${from.x} ${from.y} C ${from.x} ${midY}, ${to.x} ${midY}, ${to.x} ${to.y}`;
    const arrowPoints = `${to.x - 3.5},${to.y + 5} ${to.x + 3.5},${to.y + 5} ${to.x},${to.y}`;
    return { path, midPoint: { x: (from.x + to.x) / 2, y: midY }, arrowPoints };
  }

  // Generic case with outward normal offsets
  const normalOffset = Math.min(36, Math.max(16, getDistance(from, to) * 0.25));
  const getNormal = (edge: EdgeType) => {
    switch (edge) {
      case 'top': return { dx: 0, dy: -1 };
      case 'bottom': return { dx: 0, dy: 1 };
      case 'left': return { dx: -1, dy: 0 };
      case 'right': return { dx: 1, dy: 0 };
    }
  };

  const n1 = getNormal(from.edge);
  const n2 = getNormal(to.edge);
  const cp1 = { x: from.x + n1.dx * normalOffset, y: from.y + n1.dy * normalOffset };
  const cp2 = { x: to.x + n2.dx * normalOffset, y: to.y + n2.dy * normalOffset };
  const path = `M ${from.x} ${from.y} C ${cp1.x} ${cp1.y}, ${cp2.x} ${cp2.y}, ${to.x} ${to.y}`;
  const midPoint = { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 };

  // Calculate arrow orientation at target
  const arrowPoints = `${to.x + n2.dx * 5 - n2.dy * 3},${to.y + n2.dy * 5 + n2.dx * 3} ${to.x + n2.dx * 5 + n2.dy * 3},${to.y + n2.dy * 5 - n2.dx * 3} ${to.x},${to.y}`;

  return { path, midPoint, arrowPoints };
}

/**
 * Finds the closest edge of a card to a given reference point.
 */
function findNearestEdgeToPoint(card: CardGeometry, targetPoint: { x: number; y: number }): SnapPoint {
  const edges: EdgeType[] = ['top', 'bottom', 'left', 'right'];
  let bestEdge: SnapPoint = card.edges.top;
  let bestDist = Infinity;

  for (const edge of edges) {
    const pt = card.edges[edge];
    const dist = getDistance(pt, targetPoint);
    if (dist < bestDist) {
      bestDist = dist;
      bestEdge = pt;
    }
  }

  return bestEdge;
}

/**
 * Finds the optimal pair of snapped edges between source and target cards.
 */
function findNearestEdgesBetweenCards(
  source: CardGeometry,
  target: CardGeometry,
  isSameRow: boolean,
  hasIntervening: boolean
): { fromPoint: SnapPoint; toPoint: SnapPoint } {
  // If in same row and there are intervening cards, jumping over top edge prevents obstruction
  if (isSameRow && hasIntervening) {
    return {
      fromPoint: source.edges.top,
      toPoint: target.edges.top,
    };
  }

  // If in the same row and adjacent:
  if (isSameRow) {
    if (source.centerX < target.centerX) {
      return { fromPoint: source.edges.right, toPoint: target.edges.left };
    } else {
      return { fromPoint: source.edges.left, toPoint: target.edges.right };
    }
  }

  // Cross-row connections: evaluate cardinal edge distances to find the absolute closest boundary points
  const edgeKeys: EdgeType[] = ['top', 'bottom', 'left', 'right'];
  let bestFrom: SnapPoint = source.edges.bottom;
  let bestTo: SnapPoint = target.edges.top;
  let minDistance = Infinity;

  for (const eFrom of edgeKeys) {
    for (const eTo of edgeKeys) {
      const p1 = source.edges[eFrom];
      const p2 = target.edges[eTo];
      const d = getDistance(p1, p2);
      if (d < minDistance) {
        minDistance = d;
        bestFrom = p1;
        bestTo = p2;
      }
    }
  }

  return { fromPoint: bestFrom, toPoint: bestTo };
}

/**
 * Custom Hook: useAgentHierarchyConnections
 * 
 * Dynamically recalculates SVG path coordinates for connection lines based on getBoundingClientRect
 * of agent cards, ensuring connections snap to the edge nearest the parent/child node.
 */
export function useAgentHierarchyConnections(
  containerRef: RefObject<HTMLDivElement | null>,
  cardRefs: MutableRefObject<(HTMLDivElement | null)[]>,
  agents: SpecialistAgent[],
  options: UseAgentHierarchyConnectionsOptions
): UseAgentHierarchyConnectionsReturn {
  const { gridViewMode, selectedAgentId, pipelineLinks = [] } = options;

  const [containerDimensions, setContainerDimensions] = useState<{ width: number; height: number }>({
    width: 1040,
    height: 380,
  });

  const [measuredGeometries, setMeasuredGeometries] = useState<CardGeometry[]>([]);

  // Pixel-accurate recalculation based on getBoundingClientRect()
  const recalculate = useCallback(() => {
    if (!containerRef.current) return;

    const container = containerRef.current;
    const containerRect = container.getBoundingClientRect();
    const measuredWidth = Math.max(container.scrollWidth, container.offsetWidth, 320);
    const measuredHeight = Math.max(container.scrollHeight, container.offsetHeight, 320);

    setContainerDimensions((prev) => 
      prev.width !== measuredWidth || prev.height !== measuredHeight
        ? { width: measuredWidth, height: measuredHeight }
        : prev
    );

    const count = agents.length || 8;
    const newGeometries: CardGeometry[] = [];

    for (let index = 0; index < count; index++) {
      const el = cardRefs.current[index];
      if (el) {
        const elRect = el.getBoundingClientRect();

        // Exact relative coordinates within the container's coordinate system
        const left = elRect.left - containerRect.left;
        const top = elRect.top - containerRect.top;
        const right = elRect.right - containerRect.left;
        const bottom = elRect.bottom - containerRect.top;
        const width = elRect.width;
        const height = elRect.height;
        const centerX = left + width / 2;
        const centerY = top + height / 2;

        const edges: CardEdges = {
          top: { x: centerX, y: top, edge: 'top' },
          bottom: { x: centerX, y: bottom, edge: 'bottom' },
          left: { x: left, y: centerY, edge: 'left' },
          right: { x: right, y: centerY, edge: 'right' },
        };

        newGeometries.push({
          index,
          agentId: agents[index]?.id || `agent-${index}`,
          left,
          top,
          right,
          bottom,
          width,
          height,
          centerX,
          centerY,
          row: 0,
          col: 0,
          edges,
        });
      }
    }

    if (newGeometries.length === count) {
      // Cluster rows dynamically by top coordinate threshold
      const sortedTops = Array.from(new Set(newGeometries.map((g) => Math.round(g.top / 24) * 24))).sort((a, b) => a - b);
      
      newGeometries.forEach((g) => {
        const rounded = Math.round(g.top / 24) * 24;
        const rowIdx = sortedTops.indexOf(rounded);
        g.row = rowIdx >= 0 ? rowIdx : 0;
      });

      // Assign column indices within each row sorted by horizontal position
      const rowBuckets = new Map<number, CardGeometry[]>();
      newGeometries.forEach((g) => {
        if (!rowBuckets.has(g.row)) rowBuckets.set(g.row, []);
        rowBuckets.get(g.row)!.push(g);
      });

      rowBuckets.forEach((list) => {
        list.sort((a, b) => a.left - b.left);
        list.forEach((item, colIdx) => {
          item.col = colIdx;
        });
      });

      setMeasuredGeometries(newGeometries);
    }
  }, [agents, containerRef, cardRefs]);

  // Synchronize on mount, window resize, scroll, and container resize
  useEffect(() => {
    recalculate();

    const handleResize = () => {
      requestAnimationFrame(recalculate);
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('scroll', handleResize, true);

    let containerObserver: ResizeObserver | null = null;
    let cardObservers: ResizeObserver[] = [];

    if (typeof ResizeObserver !== 'undefined') {
      if (containerRef.current) {
        containerObserver = new ResizeObserver(() => {
          requestAnimationFrame(recalculate);
        });
        containerObserver.observe(containerRef.current);
      }

      cardRefs.current.forEach((el) => {
        if (el) {
          const obs = new ResizeObserver(() => {
            requestAnimationFrame(recalculate);
          });
          obs.observe(el);
          cardObservers.push(obs);
        }
      });
    }

    // Short delayed check to catch post-layout font and icon sizing
    const timer = setTimeout(recalculate, 60);

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('scroll', handleResize, true);
      if (containerObserver) containerObserver.disconnect();
      cardObservers.forEach((obs) => obs.disconnect());
      clearTimeout(timer);
    };
  }, [recalculate, gridViewMode, containerRef, cardRefs]);

  // Re-measure after DOM layout changes
  useEffect(() => {
    const frame = requestAnimationFrame(recalculate);
    return () => cancelAnimationFrame(frame);
  }, [gridViewMode, agents.length, recalculate]);

  // Deterministic fallback geometries for instant first render prior to DOM measurement
  const cardGeometries: CardGeometry[] = useMemo(() => {
    if (measuredGeometries.length === agents.length && measuredGeometries.length > 0) {
      return measuredGeometries;
    }

    const estWidth = containerDimensions.width || 1040;
    const count = agents.length || 8;
    const isMatrix = gridViewMode === 'matrix';
    const cols = isMatrix ? 4 : count;
    const colW = (estWidth - (cols - 1) * 8) / cols;

    return agents.map((agent, idx) => {
      const colIdx = isMatrix ? idx % cols : idx;
      const rowIdx = isMatrix ? Math.floor(idx / cols) : 0;
      const left = colIdx * (colW + 8);
      const top = rowIdx === 0 ? 36 : 260;
      const width = colW;
      const height = 230;
      const right = left + width;
      const bottom = top + height;
      const centerX = left + width / 2;
      const centerY = top + height / 2;

      return {
        index: idx,
        agentId: agent.id,
        left,
        top,
        right,
        bottom,
        width,
        height,
        centerX,
        centerY,
        row: rowIdx,
        col: colIdx,
        edges: {
          top: { x: centerX, y: top, edge: 'top' },
          bottom: { x: centerX, y: bottom, edge: 'bottom' },
          left: { x: left, y: centerY, edge: 'left' },
          right: { x: right, y: centerY, edge: 'right' },
        },
      };
    });
  }, [measuredGeometries, agents, containerDimensions.width, gridViewMode]);

  // Group geometries by operational row to configure horizontal bus lines
  const rowBuses: RowBusGeometry[] = useMemo(() => {
    const rowMap = new Map<number, CardGeometry[]>();
    cardGeometries.forEach((g) => {
      if (!rowMap.has(g.row)) rowMap.set(g.row, []);
      rowMap.get(g.row)!.push(g);
    });

    const sortedRows = Array.from(rowMap.keys()).sort((a, b) => a - b);
    return sortedRows.map((rIdx) => {
      const items = rowMap.get(rIdx) || [];
      items.sort((a, b) => a.left - b.left);
      const firstX = items[0]?.centerX ?? 65;
      const lastX = items[items.length - 1]?.centerX ?? (containerDimensions.width - 65);
      const minY = Math.min(...items.map((i) => i.top));
      const maxY = Math.max(...items.map((i) => i.bottom));
      const busY = rIdx === 0 ? Math.max(16, minY - 18) : Math.max(minY - 18, 120);

      return {
        row: rIdx,
        busY,
        firstX,
        lastX,
        minY,
        maxY,
        cardCount: items.length,
        anchors: items,
      };
    });
  }, [cardGeometries, containerDimensions.width]);

  const stemX = containerDimensions.width / 2;
  const masterBusY = rowBuses[0]?.busY ?? 38;

  // Dynamically compute command bus connections snapping to nearest edge of each card
  const commandConnections: DynamicCommandConnection[] = useMemo(() => {
    return cardGeometries.map((card) => {
      const agent = agents[card.index];
      const rowBus = rowBuses.find((rb) => rb.row === card.row) || rowBuses[0];
      const busY = rowBus ? rowBus.busY : masterBusY;
      const busPoint = { x: card.centerX, y: busY };

      // Snap to edge nearest the parent bus point (usually top edge)
      const cardSnapPoint = findNearestEdgeToPoint(card, busPoint);

      const isActive = agent?.status === 'ACTIVE';
      const isSelected = selectedAgentId === agent?.id;
      const tierColor = card.index < 2 ? '#10b981' : card.index < 5 ? '#38bdf8' : '#a855f7';

      // Drop line path from bus bar to card edge
      const dropPath = `M ${busPoint.x} ${busPoint.y} L ${cardSnapPoint.x} ${cardSnapPoint.y}`;

      // Arrowhead polygon points
      let arrowPoints = `${cardSnapPoint.x - 3.5},${cardSnapPoint.y - 6} ${cardSnapPoint.x + 3.5},${cardSnapPoint.y - 6} ${cardSnapPoint.x},${cardSnapPoint.y}`;
      if (cardSnapPoint.edge === 'bottom') {
        arrowPoints = `${cardSnapPoint.x - 3.5},${cardSnapPoint.y + 6} ${cardSnapPoint.x + 3.5},${cardSnapPoint.y + 6} ${cardSnapPoint.x},${cardSnapPoint.y}`;
      } else if (cardSnapPoint.edge === 'left') {
        arrowPoints = `${cardSnapPoint.x - 6},${cardSnapPoint.y - 3.5} ${cardSnapPoint.x - 6},${cardSnapPoint.y + 3.5} ${cardSnapPoint.x},${cardSnapPoint.y}`;
      } else if (cardSnapPoint.edge === 'right') {
        arrowPoints = `${cardSnapPoint.x + 6},${cardSnapPoint.y - 3.5} ${cardSnapPoint.x + 6},${cardSnapPoint.y + 3.5} ${cardSnapPoint.x},${cardSnapPoint.y}`;
      }

      // Bus segment from stem/trunk to drop point
      const busSegmentPath = `M ${stemX} ${busY} L ${busPoint.x} ${busY}`;

      return {
        agentId: card.agentId,
        agentIndex: card.index,
        agent,
        busPoint,
        cardSnapPoint,
        busSegmentPath,
        dropPath,
        arrowPoints,
        tierColor,
        isActive: !!isActive,
        isSelected: !!isSelected,
        row: card.row,
        busY,
      };
    });
  }, [cardGeometries, agents, rowBuses, masterBusY, stemX, selectedAgentId]);

  // Dynamically compute pipeline cascade connections snapping to nearest edges between parent & child
  const pipelineConnections: DynamicPipelineConnection[] = useMemo(() => {
    return pipelineLinks
      .map((link): DynamicPipelineConnection | null => {
        const fromCard = cardGeometries[link.from];
        const toCard = cardGeometries[link.to];
        if (!fromCard || !toCard) return null;

        const fromAgent = agents[link.from];
        const toAgent = agents[link.to];
        const isSameRow = fromCard.row === toCard.row;
        const isAdjacent = isSameRow && Math.abs(fromCard.col - toCard.col) === 1;
        const hasIntervening = isSameRow && Math.abs(fromCard.col - toCard.col) > 1;

        // Calculate nearest edge snap points
        const { fromPoint, toPoint } = findNearestEdgesBetweenCards(
          fromCard,
          toCard,
          isSameRow,
          hasIntervening
        );

        const { path, midPoint, arrowPoints } = createEdgeSnappedPath(
          fromPoint,
          toPoint,
          isSameRow,
          hasIntervening
        );

        const isActive = (fromAgent?.status === 'ACTIVE') && (toAgent?.status === 'ACTIVE');

        return {
          id: `pipe-${link.from}-${link.to}`,
          fromIndex: link.from,
          toIndex: link.to,
          fromAgent,
          toAgent,
          label: link.label,
          fromPoint,
          toPoint,
          path,
          midPoint,
          arrowPoints,
          isSameRow,
          isAdjacent,
          isActive: !!isActive,
        };
      })
      .filter((item): item is DynamicPipelineConnection => item !== null);
  }, [pipelineLinks, cardGeometries, agents]);

  // Helper function exposed to callers
  const findNearestEdge = useCallback((cardIndex: number, target: { x: number; y: number } | CardGeometry): SnapPoint => {
    const card = cardGeometries[cardIndex];
    if (!card) return { x: 0, y: 0, edge: 'top' };
    const targetPoint = 'centerX' in target ? { x: target.centerX, y: target.centerY } : target;
    return findNearestEdgeToPoint(card, targetPoint);
  }, [cardGeometries]);

  return {
    containerDimensions,
    cardGeometries,
    rowBuses,
    stemX,
    masterBusY,
    commandConnections,
    pipelineConnections,
    recalculate,
    findNearestEdge,
  };
}
