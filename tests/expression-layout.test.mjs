import { strict as assert } from 'node:assert';
import { overlaps, placeExpression } from '../src/expression-layout.ts';

const projection = {
  visible: true, exact: true, revision: 1, width: 1000, height: 700,
  bounds: { left: 390, right: 480, top: 330, bottom: 352 },
  lineBounds: { left: 130, right: 550, top: 330, bottom: 352 },
  lineHeight: 50, tangent: [.999, -.04, .10, .995],
  glyphs: [
    { left: 130, right: 550, top: 330, bottom: 352 },
    { left: 130, right: 550, top: 280, bottom: 302 },
    { left: 130, right: 340, top: 380, bottom: 402 },
  ],
};
const styles = ['float', 'rail', 'inline'];
const positions = styles.map((style) => {
  const placement = placeExpression(projection, 84, style === 'rail' ? 48 : 22, style);
  assert.ok(!placement.collision, `${style} has a safe placement`);
  assert.ok(projection.glyphs.every((glyph) => !overlaps(placement.box, glyph)), `${style} never covers source glyphs`);
  assert.ok(placement.box.left >= 0 && placement.box.right <= projection.width);
  assert.ok(placement.box.top >= 0 && placement.box.bottom <= projection.height);
  assert.ok(Math.hypot(placement.center.x - 435, placement.center.y - 341) < 200, `${style} stays near the source`);
  if (style === 'inline') assert.deepEqual(placement.matrix, projection.tangent, 'Inline follows both projected plane axes');
  else assert.deepEqual(placement.matrix, [1, 0, 0, 1]);
  return placement.center;
});
assert.notDeepEqual(positions[0], positions[1]);
assert.notDeepEqual(positions[0], positions[2]);
const first = placeExpression(projection, 80, 22, 'float');
const second = placeExpression(projection, 80, 22, 'float', [first.box]);
assert.ok(!overlaps(first.box, second.box, 2), 'Parallel calls receive separate positions');
const shifted = { ...projection, bounds: { ...projection.bounds, left: 394, right: 484 } };
const stable = placeExpression(shifted, 80, 22, 'float', [], { x: first.center.x + 4, y: first.center.y });
assert.ok(Math.abs(stable.center.x - first.center.x - 4) < 1e-6, 'A valid placement follows the source without choosing a new side');
const packed = { ...projection, width: 150, height: 100, bounds: { left: 0, top: 0, right: 150, bottom: 100 }, glyphs: [{ left: 0, top: 0, right: 150, bottom: 100 }] };
assert.equal(placeExpression(packed, 100, 30, 'float').collision, true, 'A fully occupied viewport reports no safe location so the overlay can be culled');
console.log('Expression geometry passed: distinct layouts, source/peer collision avoidance, plane tangent, stable placement, viewport constraints.');
