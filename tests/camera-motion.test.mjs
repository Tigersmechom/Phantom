import { strict as assert } from 'node:assert';
import { fitPerspectiveDistance, flightDuration, flightPose, smoothPanStep } from '../src/camera-motion.ts';

const main = { position: [-7, -7, 30], target: [-1, -10, .12] };
const functionCall = { position: [-4, 24, 24], target: [-1, 20, .12] };
const duration = flightDuration(main, functionCall);
assert.deepEqual(flightPose(main, functionCall, 0, duration), main);
assert.deepEqual(flightPose(main, functionCall, duration, duration), functionCall);
assert.deepEqual(flightPose(main, functionCall, -100, duration), main);
assert.deepEqual(flightPose(main, functionCall, duration + 100, duration), functionCall);
let previous = main;
for (let ms = 16; ms <= duration; ms += 16) {
  const next = flightPose(main, functionCall, ms, duration);
  assert.ok(next.target[1] >= previous.target[1], 'Focus must move monotonically toward the called function');
  assert.ok(next.target[1] <= functionCall.target[1], 'The target must not overshoot');
  assert.ok(Math.hypot(...next.position.map((value, index) => value - previous.position[index])) < 1.5, 'Every frame follows a continuous path');
  assert.ok(next.position[2] > next.target[2] + 10, 'The camera remains in front of the glyphs');
  previous = next;
}
const midpoint = flightPose(main, functionCall, duration / 2, duration);
assert.ok(midpoint.position[2] > (main.position[2] + functionCall.position[2]) / 2, 'A function jump follows a gentle pullback arc');
for (const aspect of [.55, 1, 1.8, 3]) {
  const distance = fitPerspectiveDistance(28, 11, aspect, 37);
  const visibleHeight = distance * Math.tan(37 * Math.PI / 360) * 2;
  assert.ok(visibleHeight >= 11 - 1e-8);
  assert.ok(visibleHeight * aspect >= 28 - 1e-8);
}
const firstPanFrame = smoothPanStep([0, 0, 0], [10, 0, 0], .016);
assert.ok(firstPanFrame.velocity[0] > 0 && firstPanFrame.velocity[0] < 1.1, 'Acceleration starts below cruising speed');
assert.ok(firstPanFrame.displacement[0] > 0 && firstPanFrame.displacement[0] < .01, 'Keydown must not add a position impulse');
const oneLongStep = smoothPanStep([0, 0, 0], [10, -4, 0], .64);
let shortSteps = { velocity: [0, 0, 0], displacement: [0, 0, 0] };
for (let index = 0; index < 40; index++) {
  const next = smoothPanStep(shortSteps.velocity, [10, -4, 0], .016);
  shortSteps = { velocity: next.velocity, displacement: next.displacement.map((value, axis) => value + shortSteps.displacement[axis]) };
}
for (let axis = 0; axis < 3; axis++) {
  assert.ok(Math.abs(shortSteps.displacement[axis] - oneLongStep.displacement[axis]) < 1e-10, 'Travel distance must not depend on frame rate');
  assert.ok(Math.abs(shortSteps.velocity[axis] - oneLongStep.velocity[axis]) < 1e-10, 'Acceleration must not depend on frame rate');
}
const released = smoothPanStep([10, 0, 0], [0, 0, 0], .016);
assert.ok(released.velocity[0] > 9 && released.velocity[0] < 10, 'Release eases the speed down rather than stopping abruptly');
assert.ok(released.displacement[0] > .1, 'Release preserves a short, continuous coast');
const settled = smoothPanStep([10, 0, 0], [0, 0, 0], 2);
assert.ok(settled.velocity[0] < .0001, 'Manual inertia ends before the two-second follow handoff');
const reverse = smoothPanStep([10, 0, 0], [-10, 0, 0], .016);
assert.ok(reverse.velocity[0] > 0 && reverse.velocity[0] < 10, 'Changing direction first slows down without an instantaneous flip');
console.log('Camera math passed: continuous flights, perspective fit, smooth start/release/reversal, frame-rate-independent pan.');
