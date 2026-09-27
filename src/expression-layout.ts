import type { SourceRange } from './execution-types';

export type ExpressionStyle = 'float' | 'rail' | 'inline';
export type ScreenPoint = { x: number; y: number };
export type ScreenRect = { left: number; top: number; right: number; bottom: number };
export type ExpressionProjection = {
  visible: boolean;
  exact: boolean;
  revision: number;
  width: number;
  height: number;
  bounds: ScreenRect;
  lineBounds: ScreenRect;
  lineHeight: number;
  tangent: [number, number, number, number];
  glyphs: ScreenRect[];
};
export type ExpressionProjector = (range: SourceRange | undefined, line: number) => ExpressionProjection | null;
export type ExpressionPlacement = {
  center: ScreenPoint;
  box: ScreenRect;
  matrix: [number, number, number, number];
  start: ScreenPoint;
  end: ScreenPoint;
  collision: boolean;
};

export function overlaps(a: ScreenRect, b: ScreenRect, margin = 0) {
  return a.left < b.right + margin && a.right > b.left - margin && a.top < b.bottom + margin && a.bottom > b.top - margin;
}

/** Positions are derived from projected source geometry, never from C++ parsing. */
export function placeExpression(projection: ExpressionProjection, width: number, height: number, style: ExpressionStyle, occupied: ScreenRect[] = [], previous?: ScreenPoint): ExpressionPlacement {
  const { bounds, lineBounds } = projection;
  const matrix: ExpressionPlacement['matrix'] = style === 'inline' ? projection.tangent : [1, 0, 0, 1];
  const halfWidth = (Math.abs(matrix[0]) * width + Math.abs(matrix[2]) * height) / 2;
  const halfHeight = (Math.abs(matrix[1]) * width + Math.abs(matrix[3]) * height) / 2;
  const middle = { x: (bounds.left + bounds.right) / 2, y: (bounds.top + bounds.bottom) / 2 };
  const preferred = style === 'rail'
    ? { x: lineBounds.right + halfWidth + 16, y: middle.y }
    : { x: middle.x, y: style === 'float' ? bounds.top - halfHeight - 5 : bounds.bottom + halfHeight + 4 };
  const clamp = (point: ScreenPoint) => ({
    x: Math.max(halfWidth + 10, Math.min(projection.width - halfWidth - 10, point.x)),
    y: Math.max(halfHeight + 10, Math.min(projection.height - halfHeight - 10, point.y)),
  });
  const candidates = previous ? [previous, preferred] : [preferred];
  const step = Math.max(height + 8, projection.lineHeight);
  const rows = [preferred.y, middle.y, bounds.top - halfHeight - 5, bounds.bottom + halfHeight + 4];
  for (let distance = 1; distance <= 4; distance++) rows.push(middle.y - step * distance, middle.y + step * distance);
  for (const y of rows) {
    candidates.push(
      { x: middle.x, y },
      { x: lineBounds.right + halfWidth + 16, y },
      { x: lineBounds.left - halfWidth - 16, y },
      { x: projection.width - halfWidth - 14, y },
      { x: halfWidth + 14, y },
    );
    for (const glyph of projection.glyphs) {
      if (glyph.bottom < y - halfHeight - 4 || glyph.top > y + halfHeight + 4) continue;
      candidates.push({ x: glyph.right + halfWidth + 10, y }, { x: glyph.left - halfWidth - 10, y });
    }
  }
  const obstacles = [...projection.glyphs, ...occupied, { left: projection.width - 198, right: projection.width, top: 0, bottom: 48 }];
  let winner: ExpressionPlacement | undefined;
  let bestScore = Infinity;
  for (const [index, candidate] of candidates.entries()) {
    const center = clamp(candidate);
    const box = { left: center.x - halfWidth, right: center.x + halfWidth, top: center.y - halfHeight, bottom: center.y + halfHeight };
    const hits = obstacles.filter((obstacle) => overlaps(box, obstacle, 3)).length;
    const score = hits * 100000 + Math.hypot(center.x - preferred.x, (center.y - preferred.y) * (style === 'float' ? 1.8 : 1)) + Math.hypot(center.x - middle.x, center.y - middle.y) * .12 - (previous && index === 0 ? 44 : 0);
    if (score >= bestScore) continue;
    const start = style === 'rail' ? { x: bounds.right + 2, y: middle.y }
      : { x: middle.x, y: center.y < middle.y ? bounds.top - 2 : bounds.bottom + 2 };
    const end = {
      x: Math.max(box.left, Math.min(box.right, start.x)),
      y: Math.max(box.top, Math.min(box.bottom, start.y)),
    };
    winner = { center, box, matrix, start, end, collision: hits > 0 };
    bestScore = score;
  }
  return winner!;
}
