export type CameraVector = [number, number, number];
export type CameraPose = { position: CameraVector; target: CameraVector };

/** Time-based flight: zero velocity at both ends, a gentle pullback on long jumps. */
export function flightPose(from: CameraPose, to: CameraPose, elapsedMs: number, durationMs: number): CameraPose {
  const t = Math.max(0, Math.min(1, elapsedMs / Math.max(1, durationMs)));
  const ease = t * t * t * (t * (t * 6 - 15) + 10);
  const interpolate = (a: CameraVector, b: CameraVector): CameraVector => a.map((value, index) => value + (b[index] - value) * ease) as CameraVector;
  const position = interpolate(from.position, to.position);
  const target = interpolate(from.target, to.target);
  const distance = Math.hypot(to.target[0] - from.target[0], to.target[1] - from.target[1]);
  const arc = Math.min(10, Math.max(0, distance - 3) * .2);
  // sin² has zero slope at both ends, unlike a plain sine arch.
  position[2] += Math.sin(Math.PI * t) ** 2 * arc;
  return { position, target };
}

export function flightDuration(from: CameraPose, to: CameraPose) {
  const distance = Math.hypot(...to.target.map((value, index) => value - from.target[index]));
  return Math.min(1450, 680 + distance * 24);
}

export function fitPerspectiveDistance(width: number, height: number, aspect: number, fovDegrees: number) {
  const tangent = Math.tan(fovDegrees * Math.PI / 360);
  return Math.max(height / (2 * tangent), width / (2 * tangent * Math.max(.1, aspect)));
}

/** Integrate a velocity that approaches its target exponentially, independent of frame rate. */
export function smoothPanStep(
  velocity: CameraVector,
  desiredVelocity: CameraVector,
  seconds: number,
  responseSeconds = .16,
): { velocity: CameraVector; displacement: CameraVector } {
  const dt = Math.max(0, seconds);
  const response = Math.max(.001, responseSeconds);
  const decay = Math.exp(-dt / response);
  return {
    velocity: velocity.map((value, index) => desiredVelocity[index] + (value - desiredVelocity[index]) * decay) as CameraVector,
    displacement: velocity.map((value, index) => desiredVelocity[index] * dt + (value - desiredVelocity[index]) * response * (1 - decay)) as CameraVector,
  };
}
